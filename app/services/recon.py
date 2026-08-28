from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import httpx


class DomainSafetyError(ValueError):
    """Raised when a target is not a public internet hostname."""


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    domain = (parsed.hostname or "").rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainSafetyError("The domain could not be normalised.") from exc
    if not DOMAIN_RE.fullmatch(domain):
        raise DomainSafetyError("Enter a valid public domain, such as example.com.")
    return domain


def assert_public_target(domain: str) -> None:
    """Avoid turning passive scanning endpoints into an internal-network proxy."""
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise DomainSafetyError("The domain could not be resolved through public DNS.") from exc
    if not addresses:
        raise DomainSafetyError("The domain did not resolve to a public address.")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise DomainSafetyError("Domains resolving to non-public addresses cannot be assessed.")


def _dns_txt(domain: str, prefix: str | None = None) -> list[str]:
    records = dns.resolver.resolve(domain, "TXT", lifetime=6)
    values = ["".join(part.decode("utf-8", errors="replace") for part in answer.strings) for answer in records]
    if prefix:
        return [value for value in values if value.lower().startswith(prefix.lower())]
    return values


async def _check_mail(domain: str) -> dict[str, Any]:
    try:
        spf, dmarc = await asyncio.gather(
            asyncio.to_thread(_dns_txt, domain, "v=spf1"),
            asyncio.to_thread(_dns_txt, f"_dmarc.{domain}", "v=dmarc1"),
        )
        return {
            "status": "ok",
            "spf_present": bool(spf),
            "dmarc_present": bool(dmarc),
            "dmarc_policy": next((record for record in dmarc if "p=" in record.lower()), None),
        }
    except Exception as exc:
        return {"status": "unavailable", "reason": str(exc)[:180]}


async def _check_security_txt(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    try:
        response = await client.get(f"https://{domain}/.well-known/security.txt")
        content = response.text[:8_000]
        valid_contact = bool(re.search(r"^Contact:\s*\S+", content, flags=re.IGNORECASE | re.MULTILINE))
        return {
            "status": "ok",
            "http_status": response.status_code,
            "present": response.status_code == 200 and valid_contact,
            "contact_present": valid_contact,
        }
    except httpx.HTTPError as exc:
        return {"status": "unavailable", "reason": str(exc)[:180]}


async def _check_http_fingerprint(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    try:
        response = await client.get(f"https://{domain}/")
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = response.text[:50_000].lower()
        missing_headers = [
            label
            for label, header in {
                "HSTS": "strict-transport-security",
                "Content-Security-Policy": "content-security-policy",
                "X-Content-Type-Options": "x-content-type-options",
            }.items()
            if header not in headers
        ]
        technology: list[str] = []
        if "wp-content/" in body or "wordpress" in body:
            technology.append("WordPress")
        if "shopify" in body or "x-shopify" in headers:
            technology.append("Shopify")
        if "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers:
            technology.append("Cloudflare")
        powered_by = headers.get("x-powered-by")
        return {
            "status": "ok",
            "http_status": response.status_code,
            "missing_headers": missing_headers,
            "server": headers.get("server"),
            "powered_by": powered_by,
            "technologies": technology,
        }
    except httpx.HTTPError as exc:
        return {"status": "unavailable", "reason": str(exc)[:180]}


def _tls_handshake(domain: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=domain) as secure_socket:
                certificate = secure_socket.getpeercert()
                expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                days_remaining = (expires - datetime.now(UTC)).days
                return {
                    "status": "ok",
                    "expires_at": expires.isoformat(),
                    "days_remaining": days_remaining,
                    "protocol": secure_socket.version(),
                }
    except ssl.SSLCertVerificationError as exc:
        return {"status": "invalid", "reason": str(exc)[:180]}
    except (OSError, ssl.SSLError) as exc:
        return {"status": "unavailable", "reason": str(exc)[:180]}


async def _check_tls(domain: str) -> dict[str, Any]:
    return await asyncio.to_thread(_tls_handshake, domain)


async def _check_cert_transparency(client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
    try:
        response = await client.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=12
        )
        response.raise_for_status()
        names: set[str] = set()
        for certificate in response.json():
            for name in str(certificate.get("name_value", "")).lower().splitlines():
                clean = name.lstrip("*.")
                if clean == domain or clean.endswith(f".{domain}"):
                    names.add(clean)
        return {"status": "ok", "subdomain_count": len(names), "sample": sorted(names)[:8]}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "unavailable", "reason": str(exc)[:180]}


async def collect_signals(domain_input: str) -> dict[str, Any]:
    """Collect only public, low-impact metadata. No probing or exploitation occurs."""
    domain = normalise_domain(domain_input)
    await asyncio.to_thread(assert_public_target, domain)
    async with httpx.AsyncClient(
        headers={"User-Agent": "RiskPulse/1.0 passive-security-assessment"},
        follow_redirects=False,
        timeout=httpx.Timeout(10.0),
        trust_env=False,
    ) as client:
        mail, security_txt, http, tls, certificate_transparency = await asyncio.gather(
            _check_mail(domain),
            _check_security_txt(client, domain),
            _check_http_fingerprint(client, domain),
            _check_tls(domain),
            _check_cert_transparency(client, domain),
        )
    return {
        "domain": domain,
        "collection_method": "Passive public DNS, TLS, certificate-transparency and HTTPS metadata only.",
        "mail": mail,
        "security_txt": security_txt,
        "http": http,
        "tls": tls,
        "certificate_transparency": certificate_transparency,
    }
