from __future__ import annotations

from typing import Any


def _finding(
    finding_id: str,
    severity: str,
    signal: str,
    narrative: str,
    recommendation: str,
    points: int,
    clause: str = "Reasonable security safeguards and breach preparedness",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "signal": signal,
        "narrative": narrative,
        "recommendation": recommendation,
        "points": points,
        "dpdp_clause": clause,
    }


def score(signals: dict[str, Any]) -> dict[str, Any]:
    """Auditable deterministic score. Unavailable passive checks do not create findings."""
    findings: list[dict[str, Any]] = []
    mail = signals["mail"]
    if mail["status"] == "ok":
        if not mail["dmarc_present"]:
            findings.append(_finding("dmarc", "high", "DMARC", "No DMARC policy was found. A spoofed sender could impersonate this domain in customer or vendor email.", "Publish and monitor a DMARC policy, beginning with p=none and progressing to enforcement.", 18))
        if not mail["spf_present"]:
            findings.append(_finding("spf", "high", "SPF", "No SPF record was found. Receiving systems have less evidence that mail claiming this domain is authorised.", "Publish a least-privilege SPF record and align it with DMARC.", 13))

    security_txt = signals["security_txt"]
    if security_txt["status"] == "ok" and not security_txt["present"]:
        findings.append(_finding("security_txt", "medium", "security.txt", "A discoverable security-contact policy was not found. External researchers may struggle to report a vulnerability safely.", "Add RFC 9116 security.txt at /.well-known/security.txt with a monitored contact channel.", 7))

    tls = signals["tls"]
    if tls["status"] == "invalid":
        findings.append(_finding("tls", "critical", "TLS certificate", "The TLS handshake did not pass certificate validation. Visitors may receive a browser warning or be exposed to interception risk.", "Renew or correct the certificate chain and verify the domain name and expiry date.", 20))
    elif tls["status"] == "ok":
        days = tls["days_remaining"]
        if days < 15:
            findings.append(_finding("tls", "high", "TLS certificate", f"The public TLS certificate expires in {days} days, creating an avoidable service and trust risk.", "Renew the certificate and add expiry monitoring.", 12))
        elif days < 30:
            findings.append(_finding("tls", "medium", "TLS certificate", f"The public TLS certificate expires in {days} days.", "Schedule renewal and add expiry monitoring before the next change window.", 6))

    http = signals["http"]
    if http["status"] == "ok" and http["missing_headers"]:
        points = min(10, 3 * len(http["missing_headers"]))
        missing = ", ".join(http["missing_headers"])
        findings.append(_finding("headers", "medium", "Web response headers", f"The public site did not return: {missing}. These headers provide defence-in-depth against common browser-side attacks.", "Review and deploy the missing response headers after testing application compatibility.", points))
    if http["status"] == "ok" and http.get("powered_by"):
        findings.append(_finding("tech", "low", "Technology disclosure", "The site publicly discloses an application runtime through X-Powered-By. This is a low-severity fingerprinting signal.", "Remove unnecessary technology disclosure and keep the underlying stack patched.", 2))

    ct = signals["certificate_transparency"]
    if ct["status"] == "ok":
        count = ct["subdomain_count"]
        if count >= 50:
            findings.append(_finding("subdomains", "medium", "Certificate Transparency", f"{count} publicly visible hostnames were observed in certificate-transparency logs. A larger external footprint needs ownership and lifecycle discipline.", "Maintain an asset inventory and retire or protect unused hostnames.", 9))
        elif count >= 10:
            findings.append(_finding("subdomains", "low", "Certificate Transparency", f"{count} public hostnames were observed in certificate-transparency logs.", "Review the hostname inventory and assign each host an owner.", 4))

    deduction = sum(item["points"] for item in findings)
    observed = sum(
        signals[key].get("status") in {"ok", "invalid"}
        for key in ("mail", "security_txt", "http", "tls", "certificate_transparency")
    )
    return {
        "score": max(0, min(100, 100 - deduction)),
        "findings": sorted(findings, key=lambda item: (-item["points"], item["id"])),
        "coverage": {"checks_observed": observed, "checks_attempted": 5, "confidence_percent": observed * 20},
        "methodology": "A deterministic, published weighted rubric over observable public posture signals. Missing telemetry is shown as lower coverage, not treated as a vulnerability.",
    }
