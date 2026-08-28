const state = { scan: null, budget: 50000 };
const rupees = new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR", maximumFractionDigits: 0 });
const byId = (id) => document.getElementById(id);

function text(id, value) { byId(id).textContent = value; }
function money(value) { return rupees.format(value || 0); }
function setError(message = "") { const node = byId("error-message"); node.hidden = !message; node.textContent = message; }
function element(name, className, content) { const node = document.createElement(name); if (className) node.className = className; if (content) node.textContent = content; return node; }

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Something went wrong. Please try again.");
  return data;
}

function renderFindings(findings) {
  const target = byId("findings-list"); target.replaceChildren();
  text("finding-count", `${findings.length} signal${findings.length === 1 ? "" : "s"}`);
  if (!findings.length) { target.append(element("p", "panel-note", "No scored gaps were observed in the available passive signals. Review coverage before treating this as assurance.")); return; }
  findings.forEach((finding) => {
    const item = element("article", "finding"); const head = element("div", "finding-heading");
    const title = element("h4", "", finding.signal); const badge = element("span", `severity ${finding.severity}`, finding.severity);
    head.append(title, badge); item.append(head, element("p", "", finding.narrative), element("p", "recommendation", `Next: ${finding.recommendation}`)); target.append(item);
  });
}

function renderControls(result) {
  const target = byId("controls-list"); target.replaceChildren();
  text("budget-caption", `${money(result.spend)} of ${money(result.budget_inr)}`);
  text("optimisation-summary", result.selected.length ? `${money(result.spend)} across ${result.selected.length} controls could reduce modelled annual exposure by ${money(result.ale_reduction_inr)} (${result.reduction_percent}%).` : "This budget does not yet fund a catalogued control. Increase it to see a portfolio.");
  result.selected.forEach((control) => {
    const item = element("article", "control"); const head = element("div", "control-heading"); head.append(element("h4", "", control.name), element("span", "control-cost", money(control.cost_inr)));
    const meta = element("div", "control-meta", `${control.relevance} · potential reduction ${money(control.ale_reduction_inr)}`); item.append(head, meta); target.append(item);
  });
}

function renderTrend(items) {
  const target = byId("trend-chart"); target.replaceChildren();
  text("trend-status", items.length > 1 ? `${items.length} snapshots` : "First snapshot");
  const width = 400, height = 160, padding = { top: 18, right: 12, bottom: 28, left: 25 };
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); svg.setAttribute("viewBox", `0 0 ${width} ${height}`); svg.setAttribute("role", "img");
  [0, 50, 100].forEach((score) => { const y = padding.top + (100 - score) / 100 * (height - padding.top - padding.bottom); const line = document.createElementNS(svg.namespaceURI, "line"); line.setAttribute("x1", padding.left); line.setAttribute("x2", width - padding.right); line.setAttribute("y1", y); line.setAttribute("y2", y); line.setAttribute("class", "chart-grid"); svg.append(line); const label = document.createElementNS(svg.namespaceURI, "text"); label.setAttribute("x", 0); label.setAttribute("y", y + 3); label.setAttribute("class", "chart-label"); label.textContent = score; svg.append(label); });
  const visible = items.slice(-12); const points = visible.map((item, index) => { const x = visible.length === 1 ? width / 2 : padding.left + index / (visible.length - 1) * (width - padding.left - padding.right); const y = padding.top + (100 - item.score) / 100 * (height - padding.top - padding.bottom); return { x, y, item }; });
  if (points.length) { const path = document.createElementNS(svg.namespaceURI, "path"); path.setAttribute("d", points.map((point, i) => `${i ? "L" : "M"}${point.x} ${point.y}`).join(" ")); path.setAttribute("class", "chart-path"); svg.append(path); points.forEach((point, index) => { const circle = document.createElementNS(svg.namespaceURI, "circle"); circle.setAttribute("cx", point.x); circle.setAttribute("cy", point.y); circle.setAttribute("r", index === points.length - 1 ? 5 : 3); circle.setAttribute("class", "chart-point"); const title = document.createElementNS(svg.namespaceURI, "title"); title.textContent = `${point.item.score}/100 · ${new Date(point.item.ts).toLocaleString()}`; circle.append(title); svg.append(circle); }); }
  target.append(svg);
}

function renderLedger(ledger, scan) {
  const badge = byId("ledger-badge"); badge.className = `ledger-badge ${ledger.intact ? "good" : "bad"}`; badge.textContent = ledger.intact ? `Verified · ${ledger.records_checked} record${ledger.records_checked === 1 ? "" : "s"}` : "Integrity check failed";
  text("report-hash", scan.report_hash); text("ledger-copy", ledger.intact ? "Each stored report contains the prior report hash. This local chain is intact and can expose later alterations." : "The integrity chain contains a mismatch. Inspect the report history before relying on it.");
}

function renderScan(scan, optimisation, trend, ledger) {
  state.scan = scan; byId("empty-state").hidden = true; byId("results").hidden = false;
  text("result-domain", scan.domain); text("result-time", `Assessed ${new Date(scan.created_at).toLocaleString()}`);
  const coverage = scan.scoring.coverage; text("coverage-chip", `${coverage.confidence_percent}% signal coverage`);
  text("score-value", scan.scoring.score); byId("score-bar").style.width = `${scan.scoring.score}%`;
  text("ale-value", money(scan.quantified.ale_inr)); text("likelihood-value", `${scan.quantified.likelihood_band} modelled likelihood · ${Math.round(scan.quantified.p_breach * 100)}% annual proxy`);
  text("reduction-value", money(optimisation.ale_reduction_inr)); text("roi-value", optimisation.spend ? `${optimisation.roi_multiple}× estimated return on ${money(optimisation.spend)}` : "Increase budget to unlock a plan");
  text("board-report", scan.board_report.content); text("report-notice", scan.board_report.notice); text("report-source", scan.board_report.source === "ai" ? "AI narrative" : "Auditable fallback");
  text("methodology", scan.scoring.methodology); renderFindings(scan.scoring.findings); renderControls(optimisation); renderTrend(trend.items); renderLedger(ledger, scan);
  window.location.hash = "results";
}

byId("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault(); setError(); const button = byId("scan-button"); button.disabled = true; button.querySelector("span").textContent = "Assessing…";
  try {
    const domain = byId("domain").value.trim(); const revenue_band = byId("revenue").value; state.budget = Number(byId("budget").value || 50000);
    const scan = await api("/api/scan", { method: "POST", body: JSON.stringify({ domain, revenue_band, authorized: byId("authorised").checked }) });
    const [optimisation, trend, ledger] = await Promise.all([api("/api/optimize", { method: "POST", body: JSON.stringify({ scan_id: scan.scan_id, budget_inr: state.budget }) }), api(`/api/trend/${encodeURIComponent(scan.domain)}`), api(`/api/ledger/verify/${encodeURIComponent(scan.domain)}`)]);
    renderScan(scan, optimisation, trend, ledger);
  } catch (error) { setError(error.message); } finally { button.disabled = false; button.querySelector("span").textContent = "Assess risk"; }
});

byId("monitor-button").addEventListener("click", async () => {
  if (!state.scan) return; const button = byId("monitor-button"); button.disabled = true;
  try { const record = await api("/api/monitor", { method: "POST", body: JSON.stringify({ domain: state.scan.domain, revenue_band: state.scan.revenue_band, authorized: true, interval_minutes: 60 }) }); button.textContent = record.enabled ? "Monitoring enabled" : "Enable 60-min monitoring"; }
  catch (error) { setError(error.message); } finally { button.disabled = false; }
});
