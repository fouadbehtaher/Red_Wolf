"""
report.py
---------
Turns raw EndpointResult / deep-probe output into human-readable
reports, formatted loosely like a bug bounty platform submission
(ID, target, VRT-style category, evidence, repro steps) so the output
can go almost straight into a HackerOne / Bugcrowd / Intigriti /
YesWeHack / Inspectiv report.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .scanner import EndpointResult


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%d %b %Y %H:%M:%S GMT+0")


def _vrt_guess(result: EndpointResult) -> str:
    """
    Very rough VRT (Vulnerability Rating Taxonomy) style classification,
    matching the category used in the equella-style report:
    Sensitive Data Exposure > Disclosure of Secrets > For Internal Asset
    """
    if result.sensitive_data_found and result.cors_wildcard:
        return "Sensitive Data Exposure > Disclosure of Secrets > For Internal Asset"
    if result.sensitive_data_found:
        return "Sensitive Data Exposure > Disclosure of Secrets"
    if result.cors_wildcard:
        return "Server Security Misconfiguration > Overly Permissive CORS Policy"
    return "Broken Access Control > Missing Authentication"


def _priority_guess(result: EndpointResult, deep_findings_count: int) -> str:
    """Crude severity heuristic -- a human must still confirm this."""
    if deep_findings_count > 0 and result.sensitive_data_found:
        return "P3"  # confirmed real file/data exposure
    if result.sensitive_data_found:
        return "P4"
    return "P5"


def build_report_data(
    base_url: str,
    results: List[EndpointResult],
    deep_findings: Optional[List[Dict[str, Any]]] = None,
    learning: Optional[Dict[str, Any]] = None,
) -> dict:
    deep_findings = deep_findings or []
    findings = [r for r in results if r.is_finding()]
    confirmed_downloads = [d for d in deep_findings if d.get("downloaded")]

    return {
        "scan_id": str(uuid.uuid4()),
        "submitted": _now_str(),
        "target_location": base_url,
        "target_category": "Web App",
        "total_endpoints_tested": len(results),
        "total_accessible_without_auth": len([r for r in results if r.accessible]),
        "findings_count": len(findings),
        "confirmed_unauth_downloads": len(confirmed_downloads),
        "learning": learning or {"enabled": False},
        "findings": [
            {
                "url": f.url,
                "method": f.method,
                "status_code": f.status_code,
                "cors_wildcard": f.cors_wildcard,
                "content_type": f.content_type,
                "response_size": f.response_size,
                "sensitive_data_found": f.sensitive_data_found,
                "sample_snippet": f.sample_snippet,
                "vrt": _vrt_guess(f),
                "priority": _priority_guess(f, len(confirmed_downloads)),
                "evidence_score": f.evidence_score,
                "evidence_reasons": f.evidence_reasons,
                "verification_status": f.verification_status,
                "verification_checks": f.verification_checks,
                "confidence": f.confidence,
            }
            for f in findings
        ],
        "deep_probe_downloads": deep_findings,
        "ai_analysis": None,  # filled in later by report.attach_ai_analysis() if requested
    }


def attach_ai_analysis(report_data: dict, analysis_text: str) -> dict:
    """Mutate + return report_data with the AI module's text attached."""
    report_data["ai_analysis"] = analysis_text
    return report_data


def to_json(report_data: dict) -> str:
    return json.dumps(report_data, indent=2, ensure_ascii=False)


def to_markdown(report_data: dict) -> str:
    lines = []
    lines.append(f"# Unauthenticated Access Scan Report\n")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Scan ID** | `{report_data['scan_id']}` |")
    lines.append(f"| **Submitted** | {report_data['submitted']} |")
    lines.append(f"| **Target Location** | `{report_data['target_location']}` |")
    lines.append(f"| **Target category** | {report_data['target_category']} |")
    lines.append(f"| **Endpoints tested** | {report_data['total_endpoints_tested']} |")
    lines.append(f"| **Accessible without auth** | {report_data['total_accessible_without_auth']} |")
    lines.append(f"| **Findings** | {report_data['findings_count']} |")
    lines.append(f"| **Confirmed unauth downloads** | {report_data['confirmed_unauth_downloads']} |")
    learning = report_data.get("learning", {})
    if learning.get("enabled"):
        lines.append(
            f"| **Local learning observations** | "
            f"{learning.get('target_specific_observations', 0)} |"
        )
    lines.append("")

    if not report_data["findings"]:
        lines.append("No findings matched the detection heuristics. "
                      "Review `accessible_endpoints` separately for manual triage.\n")
    else:
        lines.append("## Findings\n")
        for i, f in enumerate(report_data["findings"], 1):
            lines.append(f"### Finding {i}: {f['vrt']}")
            lines.append(f"- **Priority (heuristic):** {f['priority']}")
            lines.append(f"- **URL:** `{f['url']}`")
            lines.append(f"- **Method:** {f['method']}")
            lines.append(f"- **Status Code:** {f['status_code']}")
            lines.append(f"- **CORS Wildcard (`Access-Control-Allow-Origin: *`):** {f['cors_wildcard']}")
            lines.append(f"- **Content-Type:** {f['content_type']}")
            lines.append(f"- **Response Size:** {f['response_size']} bytes")
            lines.append(f"- **Sensitive keywords detected in body:** {f['sensitive_data_found']}")
            lines.append(f"- **Evidence score:** {f['evidence_score']}/100")
            lines.append(f"- **Automated verification:** {f['verification_status']} ({f['confidence']}% confidence)")
            if f["evidence_reasons"]:
                lines.append(f"- **Evidence signals:** {', '.join(f['evidence_reasons'])}")
            if f["verification_checks"]:
                lines.append(f"- **Verification checks:** {', '.join(f['verification_checks'])}")
            if f["sample_snippet"]:
                lines.append(f"- **Body preview:** `{f['sample_snippet']}`")
            lines.append("")

    if report_data["deep_probe_downloads"]:
        lines.append("## Deep Probe: File Download Verification\n")
        for d in report_data["deep_probe_downloads"]:
            status = "CONFIRMED DOWNLOADABLE" if d.get("downloaded") else "not downloadable"
            sources = ", ".join(f"`{s}`" for s in d.get("source_endpoints", []))
            lines.append(f"- `{d['resolved_url']}` — **{status}** "
                         f"(status {d.get('status_code')}, {d.get('size_bytes', 0)} bytes, "
                         f"referenced from: {sources})")
        lines.append("")

    if report_data.get("ai_analysis"):
        lines.append("## AI-Assisted Analysis\n")
        lines.append(report_data["ai_analysis"])
        lines.append("")

    lines.append("## Repro Template (fill in / adjust before submitting)\n")
    lines.append("```")
    lines.append("Step 1: List items without authentication")
    lines.append(f"curl -i '{report_data['target_location']}/<search-endpoint>'")
    lines.append("")
    lines.append("Step 2: Get item details without authentication")
    lines.append(f"curl -i '{report_data['target_location']}/<item-endpoint>/<id>'")
    lines.append("")
    lines.append("Step 3: Download the actual file without authentication")
    lines.append(f"curl -i '{report_data['target_location']}/<download-endpoint>'")
    lines.append("```")

    return "\n".join(lines)


def to_html(report_data: dict) -> str:
    """Minimal, dependency-free HTML wrapper around the markdown content."""
    md = to_markdown(report_data)
    # Not a full markdown renderer -- just enough structure to be readable
    # standalone in a browser without pulling in extra libraries.
    escaped = (
        md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Unauthenticated Access Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.5; color: #1a1a1a; }}
  pre {{ background: #f4f4f4; padding: 12px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 8px; }}
</style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""


def write_reports(report_data: dict, output_prefix: str, formats=("json", "md", "html")):
    """Write the requested report formats to disk. Returns list of file paths written."""
    written = []
    if "json" in formats:
        path = f"{output_prefix}.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_json(report_data))
        written.append(path)
    if "md" in formats:
        path = f"{output_prefix}.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_markdown(report_data))
        written.append(path)
    if "html" in formats:
        path = f"{output_prefix}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_html(report_data))
        written.append(path)
    return written
