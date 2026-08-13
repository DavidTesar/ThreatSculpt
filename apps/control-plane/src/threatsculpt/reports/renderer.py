"""Rendering the executive summary.

The document leads with business services at risk and explains every score,
because the audience decides budgets rather than patch schedules. A list of CVE
identifiers at the top would lose that reader on the first line.

Every interpolated value goes through ``html.escape``. Service names, hostnames
and CVE descriptions are all attacker-influenced — a hostname is whatever a
customer's DHCP said, and a CVE description comes from an upstream feed — so a
report is a place where stored XSS would land in front of an executive.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from html import escape
from typing import Final

from threatsculpt.dashboard.schemas import ExecutiveDashboard, ServiceAtRisk
from threatsculpt.findings.schemas import FindingOut

CONTENT_TYPE: Final = "text/html; charset=utf-8"

#: Findings listed under each heading. A report nobody finishes persuades nobody.
MAX_FINDINGS_IN_REPORT: Final = 25

_STYLE = """
:root { color-scheme: light dark; }
body { font: 16px/1.55 system-ui, -apple-system, Segoe UI, sans-serif;
       margin: 0 auto; max-width: 60rem; padding: 2.5rem 1.5rem; }
h1 { font-size: 2rem; margin-bottom: .25rem; }
h2 { font-size: 1.25rem; margin-top: 2.5rem; border-bottom: 1px solid #8884;
     padding-bottom: .3rem; }
.subtitle { opacity: .7; margin-top: 0; }
.posture { font-size: 3rem; font-weight: 700; line-height: 1; }
.band { text-transform: uppercase; letter-spacing: .08em; font-size: .8rem; opacity: .75; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #8883;
         vertical-align: top; }
th { font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; opacity: .7; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.why { font-size: .85rem; opacity: .8; }
.empty { opacity: .7; font-style: italic; }
footer { margin-top: 3rem; font-size: .8rem; opacity: .65; }
"""


def render_executive_summary(
    *,
    org_name: str,
    dashboard: ExecutiveDashboard,
    findings: tuple[FindingOut, ...],
    generated_at: datetime | None = None,
) -> str:
    stamp = (generated_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{escape(org_name)} — Executive risk summary</title>
<style>{_STYLE}</style></head><body>
<h1>Executive risk summary</h1>
<p class="subtitle">{escape(org_name)} &middot; generated {escape(stamp)}</p>
{_posture(dashboard)}
{_services(dashboard.services_at_risk)}
{_findings(findings)}
<footer>Scores combine the CVE's CVSS base score with how mature its exploits are,
how exposed the host is, and how critical the business services it supports are.
Every finding in the product carries the same breakdown.</footer>
</body></html>"""


def _posture(dashboard: ExecutiveDashboard) -> str:
    posture = dashboard.risk_posture
    direction = "down" if posture.trend_30d < 0 else ("up" if posture.trend_30d > 0 else "flat")
    progress = dashboard.remediation_progress
    return f"""<h2>Where we stand</h2>
<p class="posture">{posture.score}<span style="font-size:1rem;opacity:.6">/100</span></p>
<p class="band">{escape(posture.band)} &middot; {escape(direction)}
 {abs(posture.trend_30d)} points over 30 days</p>
<p>{progress.opened_30d} issues opened and {progress.resolved_30d} resolved in the last
30 days. {dashboard.kev_findings} open finding(s) are on CISA's list of
vulnerabilities known to be exploited in the wild.</p>
{_exposure(dashboard)}"""


def _exposure(dashboard: ExecutiveDashboard) -> str:
    summary = dashboard.exposure_summary
    return (
        f"<p>Estate exposure: {summary.internet} internet-facing, {summary.dmz} in the DMZ, "
        f"{summary.internal} internal, {summary.isolated} isolated.</p>"
    )


def _services(services: list[ServiceAtRisk]) -> str:
    if not services:
        return (
            "<h2>Business services at risk</h2>"
            '<p class="empty">No business service currently has an open finding.</p>'
        )
    rows = "".join(
        f"""<tr><td>{escape(service.name)}<div class="why">{escape(service.criticality)}
 criticality &middot; {service.assets_affected} asset(s)</div></td>
<td class="num">{service.open_findings}</td>
<td class="num">{service.worst_finding_score}</td>
<td class="num">{_money(service.revenue_at_risk)}</td></tr>"""
        for service in services
    )
    return f"""<h2>Business services at risk</h2>
<p>Ordered by business impact — the service's own criticality applied to its worst
open finding — not by raw CVSS.</p>
<table><thead><tr><th>Service</th><th>Open findings</th><th>Worst score</th>
<th>Revenue at risk</th></tr></thead><tbody>{rows}</tbody></table>"""


def _findings(findings: tuple[FindingOut, ...]) -> str:
    if not findings:
        return '<h2>Highest-risk findings</h2><p class="empty">No open findings.</p>'
    rows = "".join(_finding_row(finding) for finding in findings[:MAX_FINDINGS_IN_REPORT])
    return f"""<h2>Highest-risk findings</h2>
<table><thead><tr><th>Score</th><th>Vulnerability</th><th>Host</th>
<th>Why it scores this way</th></tr></thead><tbody>{rows}</tbody></table>"""


def _finding_row(finding: FindingOut) -> str:
    host = finding.asset.hostname or finding.asset.ip
    kev = " &middot; known exploited" if finding.cve.kev_listed else ""
    return f"""<tr><td class="num">{finding.business_risk_score}</td>
<td>{escape(finding.cve.cve_id)}<div class="why">CVSS
 {finding.cve.cvss_base if finding.cve.cvss_base is not None else "not published"}{kev}</div></td>
<td>{escape(host)}<div class="why">{escape(finding.asset.exposure)}</div></td>
<td class="why">{escape(finding.match.rationale or "")}</td></tr>"""


def _money(value: Decimal | None) -> str:
    if value is None:
        return "&mdash;"
    return f"{value:,.0f}"
