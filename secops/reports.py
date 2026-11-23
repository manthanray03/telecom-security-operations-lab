"""Write the CSV exports, the Markdown management summary and the HTML dashboard."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from . import access_review, compliance, config, detections, incidents
from .util import write_csv


def write_all(out: Path, as_of: datetime, alerts, incs, findings, checks, m, period: tuple) -> list[Path]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "alerts.csv", alerts, detections.FIELDS + ["incident_id"])
    write_csv(out / "incidents.csv", incs, incidents.FIELDS)
    write_csv(out / "access_review.csv", findings, access_review.FIELDS)
    write_csv(out / "compliance_results.csv", checks, compliance.FIELDS)
    (out / "security_summary.md").write_text(summary_md(as_of, alerts, incs, findings, checks, m, period),
                                             encoding="utf-8")
    (out / "dashboard.html").write_text(dashboard_html(as_of, alerts, incs, findings, checks, m, period),
                                        encoding="utf-8")
    return [out / n for n in ("alerts.csv", "incidents.csv", "access_review.csv", "compliance_results.csv",
                              "security_summary.md", "dashboard.html")]


def _fmt_minutes(v) -> str:
    if v is None:
        return "n/a"
    v = round(v)
    return f"{v} min" if v < 120 else f"{v / 60:.1f} h"


def headline(alerts, incs, findings, checks, m) -> dict:
    rt = m["response_targets"][0]
    score = m["compliance_score"][0]
    return {
        "alerts": len(alerts),
        "incidents": len(incs),
        "critical": sum(1 for i in incs if i["severity"] == "Critical"),
        "not_closed": sum(1 for i in incs if i["status"] != "Closed"),
        "overdue": rt["overdue"],
        "ack_pct": round(100 * rt["ack_met"] / rt["incidents"]) if rt["incidents"] else 100,
        "contain_pct": round(100 * rt["contain_met"] / rt["incidents"]) if rt["incidents"] else 100,
        "findings": len(findings),
        "high_findings": sum(1 for f in findings if f["severity"] == "High"),
        "passed": score["passed"],
        "checks": score["checks"],
        "mttd": m["median_minutes"]["detect"],
        "mtta": m["median_minutes"]["ack"],
        "mttc": m["median_minutes"]["contain"],
    }


def recommendations(incs, findings, checks) -> list[str]:
    """Plain-language actions, ordered by risk. Built from what actually failed."""
    failed = {c["check_id"]: c for c in checks if c["result"] == "Fail"}
    recs = []
    if "CC-04" in failed:
        no_mfa = failed["CC-04"]["evidence"].split(": ", 1)[1]
        taken = [i["entity"] for i in incs if "DET-02" in i["rules"] and i["entity"] in no_mfa.split(", ")]
        recs.append(f"Enrol MFA on the privileged accounts that lack it ({no_mfa}) and block privileged sign-in "
                    "without MFA." + (f" {', '.join(taken)} was taken over this week after a brute-force attack "
                                      f"({', '.join(i['incident_id'] for i in incs if i['entity'] in taken)})."
                                      if taken else ""))
    if "CC-01" in failed:
        recs.append("Fix the leaver process: HR's termination notice must open a same-day disable ticket. "
                    f"Disable now: {failed['CC-01']['evidence'].split(': ', 1)[1]}.")
    if "CC-07" in failed:
        sim = [f["username"] for f in findings if f["check"].endswith("(SOD-04)")]
        fraud_agents = [i.get("_agent") for i in incs if i.get("_agent")]
        overlap = sorted({a for a in fraud_agents if a in sim})
        extra = (f" {', '.join(overlap)} can both perform and approve SIM swaps and processed "
                 f"{sum(fraud_agents.count(a) for a in overlap)} of this week's fraudulent ones.") if overlap else ""
        recs.append("Remove separation-of-duties conflicts, starting with SIM swap perform+approve in Customer "
                    "Care." + extra)
    if any(i["rules"] == "DET-07" for i in incs):
        recs.append("Stop approving SIM swaps by phone on knowledge-based questions alone; require a one-time code "
                    "to the current SIM or an in-store ID check, and a 24-hour hold on port-outs after a swap.")
    if "CC-11" in failed:
        late = [i for i in incs if i["ack_met"] != "Yes" and i["severity"] in ("High", "Critical")]
        recs.append("Page the on-call analyst for High alerts outside business hours, not only Critical, and "
                    "escalate a page that isn't answered in 10 minutes. "
                    f"{len(late)} High or Critical incidents missed the acknowledgement target "
                    f"({', '.join(i['incident_id'] for i in late)}).")
    if "CC-08" in failed:
        recs.append("Alert when a log source goes quiet for an hour. The firewall feed was missing for "
                    f"{failed['CC-08']['measured'].replace('missing ', '')} ({failed['CC-08']['evidence'].split(': ', 1)[1]}) "
                    "and nothing flagged it.")
    if "CC-06" in failed or "CC-02" in failed:
        recs.append("Disable dormant and orphaned accounts after manager confirmation; add contractors to the "
                    "HR system with an end date.")
    return recs


def summary_md(as_of, alerts, incs, findings, checks, m, period) -> str:
    h = headline(alerts, incs, findings, checks, m)
    lines = [
        "# Security operations summary",
        "",
        f"Prairie Lynx Telecom (fictional) | Logs {period[0]} to {period[1]} | Report as of {as_of:%Y-%m-%d}",
        "",
        "Generated by `run_lab.py` from synthetic data. Nothing here describes a real organization.",
        "",
        "## Headline",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Alerts raised | {h['alerts']} |",
        f"| Incidents (after grouping alerts) | {h['incidents']} ({h['critical']} Critical) |",
        f"| Incidents not yet closed | {h['not_closed']} ({h['overdue']} overdue) |",
        f"| Median time to detect | {_fmt_minutes(h['mttd'])} |",
        f"| Median time to acknowledge | {_fmt_minutes(h['mtta'])} |",
        f"| Median time to contain | {_fmt_minutes(h['mttc'])} |",
        f"| Acknowledged within target | {h['ack_pct']}% |",
        f"| Contained within SLA | {h['contain_pct']}% |",
        f"| Access review findings | {h['findings']} ({h['high_findings']} High) |",
        f"| Compliance checks passed | {h['passed']} of {h['checks']} |",
        "",
        "## Needs attention",
        "",
        "| Incident | Severity | Status | Opened | Contain by | SLA |",
        "|---|---|---|---|---|---|",
    ]
    for r in m["needs_attention"]:
        lines.append(f"| {r['incident_id']} {r['title']} | {r['severity']} | {r['status']} | {r['opened_at']} | "
                     f"{r['contain_due']} | {r['contain_met']} |")
    lines += ["", "## All incidents", "", "| Incident | Severity | Rules | Detect | Ack | Contain | Status |",
              "|---|---|---|---|---|---|---|"]
    for i in incs:
        lines.append(f"| {i['incident_id']} {i['title']} | {i['severity']} | {i['rules']} | "
                     f"{i['minutes_to_detect']} min | {_dash(i['minutes_to_ack'])} ({i['ack_met']}) | "
                     f"{_dash(i['minutes_to_contain'])} ({i['contain_met']}) | {i['status']} |")
    lines += ["", "Times are minutes from the incident opening. Detect is from the first malicious event.", "",
              "## Alerts by rule", "", "| Rule | MITRE ATT&CK | Alerts |", "|---|---|---|"]
    for r in m["alerts_by_rule"]:
        lines.append(f"| {r['rule_id']} {r['rule_name']} | {r['technique']} | {r['alerts']} |")
    lines += ["", "## Access review", "", "| Check | Standard | Severity | Accounts |", "|---|---|---|---|"]
    for r in m["findings_by_check"]:
        lines.append(f"| {r['check_name']} | {r['requirement']} | {r['severity']} | {r['accounts']} |")
    lines += ["", "Account-level detail: `access_review.csv`.", "", "## Compliance (NIST CSF 2.0)", "",
              "| Check | CSF | Control | Measured | Target | Result |", "|---|---|---|---|---|---|"]
    for c in checks:
        lines.append(f"| {c['check_id']} | {c['csf']} | {c['control']} | {c['measured']} | {c['target']} | "
                     f"{c['result']} |")
    lines += ["", "## Recommendations", ""]
    lines += [f"{n}. {r}" for n, r in enumerate(recommendations(incs, findings, checks), 1)]
    return "\n".join(lines) + "\n"


def _dash(v):
    return "-" if v in ("", None) else f"{v} min"


SEV_STATUS = {"Critical": ("critical", "!!"), "High": ("serious", "!"), "Medium": ("warning", "~"),
              "Low": ("muted", "-")}


def _chip(sev: str) -> str:
    cls, icon = SEV_STATUS.get(sev, ("muted", "-"))
    return f'<span class="chip {cls}"><span aria-hidden="true">{icon}</span> {html.escape(sev)}</span>'


def _result(res: str) -> str:
    ok = res in ("Pass", "Yes")
    cls = "good" if ok else ("warning" if res == "Pending" else "critical")
    icon = "&#10003;" if ok else ("&#8230;" if res == "Pending" else "&#10007;")
    return f'<span class="chip {cls}"><span aria-hidden="true">{icon}</span> {html.escape(res)}</span>'


def dashboard_html(as_of, alerts, incs, findings, checks, m, period) -> str:
    h = headline(alerts, incs, findings, checks, m)
    e = html.escape
    tiles = [
        ("Incidents", h["incidents"], f"{h['critical']} Critical, {h['not_closed']} not closed"),
        ("Median time to detect", _fmt_minutes(h["mttd"]), "first malicious event to alert"),
        ("Median time to contain", _fmt_minutes(h["mttc"]), f"{h['contain_pct']}% within SLA"),
        ("Acknowledged on time", f"{h['ack_pct']}%", "target 100%"),
        ("Access findings", h["findings"], f"{h['high_findings']} High"),
        ("Compliance checks", f"{h['passed']}/{h['checks']}", "passed (NIST CSF 2.0)"),
    ]
    tile_html = "".join(f'<div class="tile"><div class="label">{e(t)}</div><div class="value">{e(str(v))}</div>'
                        f'<div class="sub">{e(s)}</div></div>' for t, v, s in tiles)
    top = max((r["alerts"] for r in m["alerts_by_rule"]), default=1)
    bars = []
    for r in m["alerts_by_rule"]:
        pct = 100 * r["alerts"] / top
        tip = f"{r['rule_id']} {r['rule_name']}: {r['alerts']} alert{'s' if r['alerts'] != 1 else ''} ({r['technique']})"
        bars.append(f'<div class="bar-row" tabindex="0" data-tip="{e(tip)}"><div class="bar-label">'
                    f'{e(r["rule_id"])} {e(r["rule_name"])}</div><div class="bar-track"><div class="bar" '
                    f'style="width:{pct:.1f}%"></div></div><div class="bar-value">{r["alerts"]}</div></div>')
    inc_rows = "".join(
        f"<tr><td>{e(i['incident_id'])}</td><td>{e(i['title'])}</td><td>{_chip(i['severity'])}</td>"
        f"<td>{e(i['rules'])}</td><td>{e(i['opened_at'])}</td><td class='num'>{i['minutes_to_detect']}</td>"
        f"<td class='num'>{e(str(i['minutes_to_ack']) or '-')}</td><td>{_result(i['ack_met'])}</td>"
        f"<td class='num'>{e(str(i['minutes_to_contain']) or '-')}</td><td>{_result(i['contain_met'])}</td>"
        f"<td>{e(i['status'])}</td></tr>" for i in incs)
    find_rows = "".join(
        f"<tr><td>{e(r['check_name'])}</td><td>{e(r['requirement'])}</td><td>{_chip(r['severity'])}</td>"
        f"<td class='num'>{r['accounts']}</td></tr>" for r in m["findings_by_check"])
    comp_rows = "".join(
        f"<tr><td class='nw'>{e(c['check_id'])}</td><td class='nw'>{e(c['csf'])}</td><td>{e(c['control'])}</td>"
        f"<td>{e(c['measured'])}</td><td class='nw'>{e(c['target'])}</td><td>{_result(c['result'])}</td></tr>" for c in checks)
    recs = "".join(f"<li>{e(r)}</li>" for r in recommendations(incs, findings, checks))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security operations dashboard - Prairie Lynx Telecom (fictional)</title>
<style>
.viz-root {{
  color-scheme: light;
  --page: #f9f9f7; --surface-1: #fcfcfb; --text-primary: #0b0b0b; --text-secondary: #52514e;
  --muted: #898781; --grid: #e1e0d9; --border: rgba(11,11,11,0.10); --series-1: #2a78d6;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) .viz-root {{
    color-scheme: dark;
    --page: #0d0d0d; --surface-1: #1a1a19; --text-primary: #f0efec; --text-secondary: #c3c2b7;
    --grid: #2c2c2a; --border: rgba(255,255,255,0.10); --series-1: #3987e5;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; }}
.viz-root {{ background: var(--page); color: var(--text-primary); min-height: 100vh;
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; padding: 28px 32px 40px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
h2 {{ font-size: 15px; margin: 0 0 12px; }}
.meta {{ color: var(--text-secondary); margin-bottom: 20px; }}
.tiles {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }}
.tile, .card {{ background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
.tile .label {{ color: var(--text-secondary); font-size: 12px; }}
.tile .value {{ font-size: 28px; font-weight: 650; margin: 2px 0; font-variant-numeric: tabular-nums; }}
.tile .sub {{ color: var(--muted); font-size: 12px; }}
.grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
.card {{ margin-bottom: 16px; }} .grid2 .card {{ margin-bottom: 0; }}
.bar-row {{ display: grid; grid-template-columns: 290px 1fr 28px; align-items: center; gap: 10px; padding: 5px 0;
  position: relative; outline: none; }}
.bar-label {{ color: var(--text-secondary); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.bar-track {{ height: 14px; border-left: 1px solid var(--muted); }}
.bar {{ height: 14px; background: var(--series-1); border-radius: 0 4px 4px 0; }}
.bar-row:hover .bar, .bar-row:focus .bar {{ filter: brightness(0.9); }}
.bar-value {{ font-variant-numeric: tabular-nums; text-align: right; }}
.bar-row:hover::after, .bar-row:focus::after {{ content: attr(data-tip); position: absolute; left: 300px; top: -30px;
  background: var(--surface-1); color: var(--text-primary); border: 1px solid var(--border); border-radius: 6px;
  padding: 4px 8px; font-size: 12px; white-space: nowrap; box-shadow: 0 2px 8px rgba(0,0,0,0.12); z-index: 2; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--grid); padding: 6px 8px; }}
td {{ border-bottom: 1px solid var(--grid); padding: 6px 8px; vertical-align: top; }}
td.nw {{ white-space: nowrap; }}
td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.chip {{ display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap;
  color: #fff; }}
.chip.critical {{ background: var(--critical); }} .chip.serious {{ background: var(--serious); }}
.chip.warning {{ background: var(--warning); color: #0b0b0b; }} .chip.good {{ background: var(--good); }}
.chip.muted {{ background: var(--grid); color: var(--text-primary); }}
ol {{ margin: 0; padding-left: 20px; }} li {{ margin-bottom: 6px; }}
.foot {{ color: var(--muted); font-size: 12px; margin-top: 8px; }}
@media (max-width: 1100px) {{ .tiles {{ grid-template-columns: repeat(3, 1fr); }} .grid2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="viz-root">
<h1>Security operations dashboard</h1>
<div class="meta">Prairie Lynx Telecom (fictional) &middot; logs {e(period[0])} to {e(period[1])} &middot;
report as of {as_of:%Y-%m-%d} &middot; synthetic data</div>
<div class="tiles">{tile_html}</div>
<div class="grid2">
<div class="card"><h2>Alerts by detection rule</h2>{''.join(bars)}
<div class="foot">Hover a bar for the MITRE ATT&amp;CK technique. Table view: alerts.csv.</div></div>
<div class="card"><h2>Recommendations</h2><ol>{recs}</ol></div>
</div>
<div class="card"><h2>Incident register</h2>
<table><thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Rules</th><th>Opened</th><th class="num">Detect (min)</th>
<th class="num">Ack (min)</th><th>Ack target</th><th class="num">Contain (min)</th><th>SLA</th><th>Status</th></tr></thead>
<tbody>{inc_rows}</tbody></table></div>
<div class="grid2">
<div class="card"><h2>Access review findings</h2>
<table><thead><tr><th>Check</th><th>Standard</th><th>Severity</th><th class="num">Accounts</th></tr></thead>
<tbody>{find_rows}</tbody></table></div>
<div class="card"><h2>Compliance checks (NIST CSF 2.0)</h2>
<table><thead><tr><th>ID</th><th>CSF</th><th>Control</th><th>Measured</th><th>Target</th><th>Result</th></tr></thead>
<tbody>{comp_rows}</tbody></table></div>
</div>
<div class="foot">Generated by run_lab.py. All people, accounts, customers and addresses are fictional.</div>
</div>
</body>
</html>
"""
