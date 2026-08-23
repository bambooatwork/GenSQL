#!/usr/bin/env python
"""
GenSQL Report Engine
Author: Jeevraj
Generates HTML, JSON, and Markdown security assessment reports with CVSS 4.0 scoring.
Uses only Python stdlib — no external dependencies.
"""
import json
import time
import os
import html
import re


# ── CVSS 4.0 simplified scoring ────────────────────────────────────────────────
CVSS4_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},   # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},                           # Attack Complexity
    "AT": {"N": 0.85, "P": 0.62},                           # Attack Requirements
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},               # Privileges Required
    "UI": {"N": 0.85, "P": 0.62, "A": 0.43},               # User Interaction
    "VC": {"H": 0.56, "L": 0.22, "N": 0.0},                # Vulnerable Confidentiality
    "VI": {"H": 0.56, "L": 0.22, "N": 0.0},                # Vulnerable Integrity
    "VA": {"H": 0.56, "L": 0.22, "N": 0.0},                # Vulnerable Availability
}

SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]

SQLI_REMEDIATION = {
    "default": (
        "1. Use parameterized queries / prepared statements for ALL database interactions.\n"
        "2. Apply input validation and whitelist allowable characters.\n"
        "3. Use a Web Application Firewall (WAF) as a defence-in-depth measure.\n"
        "4. Apply the principle of least privilege for database accounts.\n"
        "5. Disable detailed error messages in production environments.\n"
        "6. Conduct regular security code reviews and penetration tests."
    ),
    "graphql": (
        "1. Use parameterized resolvers; never concatenate user input into queries.\n"
        "2. Disable introspection in production environments.\n"
        "3. Implement query depth/complexity limits to prevent batching attacks.\n"
        "4. Validate and sanitize all input types before passing to resolvers."
    ),
    "nosql": (
        "1. Never pass raw user input directly to NoSQL query operators.\n"
        "2. Validate input types — ensure strings, not objects, are received.\n"
        "3. Use an ODM/ORM with built-in query sanitization.\n"
        "4. Disable JavaScript execution ($where) in MongoDB unless required."
    ),
    "ssti": (
        "1. Never pass user-controlled input directly to template rendering functions.\n"
        "2. Use sandboxed template engines with restricted execution environments.\n"
        "3. Validate and sanitize all user input before template processing.\n"
        "4. Adopt Content Security Policy (CSP) as a defence-in-depth measure."
    ),
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GenSQL Security Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
.header{{background:linear-gradient(135deg,#161b22,#1f2937);padding:40px;border-bottom:2px solid #30363d}}
.header h1{{color:#58a6ff;font-size:2.2em;margin-bottom:8px}}
.header .meta{{color:#8b949e;font-size:.9em}}
.banner{{background:#161b22;padding:20px 40px;font-family:monospace;font-size:.75em;color:#7ee787;white-space:pre;overflow-x:auto}}
.container{{max-width:1200px;margin:0 auto;padding:30px}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:30px 0}}
.stat-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}}
.stat-card .num{{font-size:2.5em;font-weight:700;color:#58a6ff}}
.stat-card .label{{color:#8b949e;font-size:.9em;margin-top:4px}}
.stat-card.critical .num{{color:#ff7b72}}
.stat-card.high .num{{color:#ffa657}}
.stat-card.medium .num{{color:#ffd700}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:16px 0;overflow:hidden}}
.finding-header{{padding:16px 20px;display:flex;justify-content:space-between;align-items:center;cursor:pointer}}
.finding-header h3{{color:#58a6ff;font-size:1em}}
.badge{{padding:4px 12px;border-radius:20px;font-size:.75em;font-weight:700;text-transform:uppercase}}
.badge.critical{{background:#ff7b7222;color:#ff7b72;border:1px solid #ff7b72}}
.badge.high{{background:#ffa65722;color:#ffa657;border:1px solid #ffa657}}
.badge.medium{{background:#ffd70022;color:#ffd700;border:1px solid #ffd700}}
.badge.low{{background:#3fb95022;color:#3fb950;border:1px solid #3fb950}}
.badge.info{{background:#58a6ff22;color:#58a6ff;border:1px solid #58a6ff}}
.finding-body{{padding:20px;border-top:1px solid #30363d;display:none}}
.finding-body.open{{display:block}}
.field-label{{color:#8b949e;font-size:.8em;text-transform:uppercase;letter-spacing:.05em;margin-top:12px;margin-bottom:4px}}
.payload-box{{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:12px;font-family:monospace;font-size:.85em;color:#f0883e;word-break:break-all;margin-top:4px}}
.remediation{{background:#161b2290;border-left:3px solid #3fb950;padding:12px 16px;border-radius:0 4px 4px 0;margin-top:8px;font-size:.9em;white-space:pre-line}}
.footer{{text-align:center;padding:30px;color:#8b949e;font-size:.85em;border-top:1px solid #30363d;margin-top:40px}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}
th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #30363d;font-size:.9em}}
th{{color:#8b949e;font-weight:600;background:#0d1117}}
tr:hover td{{background:#161b2280}}
</style>
<script>
function toggle(id){{var b=document.getElementById('body-'+id);b.classList.toggle('open');}}
</script>
</head>
<body>
<div class="header">
  <h1>&#9889; GenSQL Security Assessment Report</h1>
  <div class="meta">
    Generated: {scan_time} &nbsp;|&nbsp; Target: {target} &nbsp;|&nbsp;
    GenSQL v{version} by Jeevraj &nbsp;|&nbsp; DBMS: {dbms}
  </div>
</div>
<div class="banner">{banner}</div>
<div class="container">
<div class="summary">
  <div class="stat-card"><div class="num">{total_vulns}</div><div class="label">Total Vulnerabilities</div></div>
  <div class="stat-card critical"><div class="num">{critical_count}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="num">{high_count}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="num">{medium_count}</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="num">{total_requests}</div><div class="label">Requests Sent</div></div>
  <div class="stat-card"><div class="num">{scan_duration}</div><div class="label">Scan Duration (s)</div></div>
</div>
{findings_html}
</div>
<div class="footer">
  GenSQL v{version} &mdash; Next-Generation SQL Injection Framework &mdash; by Jeevraj<br>
  <small>For authorized penetration testing only. Unauthorized use is illegal.</small>
</div>
</body>
</html>"""


class ReportEngine:
    """
    GenSQL Report Engine — generates HTML, JSON, and Markdown security reports.
    Author: Jeevraj
    """

    def __init__(self, html_path=None, json_path=None, md_path=None, cvss4=True):
        self.html_path   = html_path
        self.json_path   = json_path
        self.md_path     = md_path
        self.cvss4       = cvss4
        self.scan_start  = time.time()
        self._findings   = []
        self._meta       = {}

    # ── Finding registration ───────────────────────────────────────────────
    def add_finding(self, vuln_type, severity, url, parameter, payload,
                    evidence=None, dbms=None, technique=None, cvss_vector=None,
                    extra=None):
        """Register a discovered vulnerability."""
        finding = {
            "id":         len(self._findings) + 1,
            "type":       vuln_type,
            "severity":   severity.upper(),
            "url":        url,
            "parameter":  parameter,
            "payload":    payload,
            "evidence":   evidence or "",
            "dbms":       dbms or "",
            "technique":  technique or "",
            "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
            "extra":      extra or {},
        }
        if self.cvss4 and cvss_vector:
            finding["cvss4_score"], finding["cvss4_severity"] = self.calculate_cvss4(cvss_vector)
        self._findings.append(finding)
        return finding

    def set_meta(self, target=None, dbms=None, total_requests=None, version=None):
        """Set scan metadata."""
        self._meta.update({
            "target":         target or "",
            "dbms":           dbms or "",
            "total_requests": total_requests or 0,
            "version":        version or "2.0.0",
        })

    # ── CVSS 4.0 ──────────────────────────────────────────────────────────
    def calculate_cvss4(self, vector_string):
        """
        Calculate approximate CVSS 4.0 score from vector string.
        Example: 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H'
        """
        try:
            metrics = {}
            for part in vector_string.split("/"):
                k, v = part.split(":")
                metrics[k] = v
            score = 1.0
            for metric, value in metrics.items():
                if metric in CVSS4_METRICS and value in CVSS4_METRICS[metric]:
                    score *= CVSS4_METRICS[metric][value]
            score = round(min(10.0, score * 10), 1)
        except Exception:
            score = 0.0
        for threshold, sev in SEVERITY_THRESHOLDS:
            if score >= threshold:
                return score, sev
        return 0.0, "NONE"

    def severity_to_cvss_vector(self, severity, technique="boolean"):
        """Generate a reasonable CVSS 4.0 vector for common SQLi findings."""
        vectors = {
            "union":   "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "error":   "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N",
            "boolean": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N",
            "time":    "AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N",
            "stacked": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "default": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
        }
        return vectors.get((technique or "").lower(), vectors["default"])

    # ── Report generation ─────────────────────────────────────────────────
    def generate_html(self):
        """Generate full HTML security report."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self._findings:
            counts[f.get("severity", "INFO")] = counts.get(f.get("severity","INFO"),0) + 1

        findings_html = ""
        for i, f in enumerate(self._findings):
            sev   = f.get("severity", "INFO").lower()
            remed = SQLI_REMEDIATION.get(
                "graphql" if "graphql" in str(f.get("type","")).lower() else
                "nosql"   if "nosql"   in str(f.get("type","")).lower() else
                "ssti"    if "ssti"    in str(f.get("type","")).lower() else "default"
            )
            findings_html += """
<div class="finding">
  <div class="finding-header" onclick="toggle({id})">
    <h3>#{id} &mdash; {type} &mdash; Parameter: <code>{param}</code></h3>
    <span class="badge {sev_low}">{sev}</span>
  </div>
  <div class="finding-body" id="body-{id}">
    <div class="field-label">URL</div>
    <div>{url}</div>
    <div class="field-label">Parameter</div>
    <div>{param}</div>
    <div class="field-label">DBMS</div>
    <div>{dbms}</div>
    <div class="field-label">Technique</div>
    <div>{technique}</div>
    {cvss_block}
    <div class="field-label">Payload</div>
    <div class="payload-box">{payload_esc}</div>
    <div class="field-label">Evidence</div>
    <div class="payload-box">{evidence_esc}</div>
    <div class="field-label">Remediation</div>
    <div class="remediation">{remediation}</div>
  </div>
</div>""".format(
                id          = f["id"],
                type        = html.escape(str(f.get("type", "SQLi"))),
                param       = html.escape(str(f.get("parameter", ""))),
                sev         = f.get("severity", "INFO"),
                sev_low     = sev,
                url         = html.escape(str(f.get("url", ""))),
                dbms        = html.escape(str(f.get("dbms", "Unknown"))),
                technique   = html.escape(str(f.get("technique", ""))),
                cvss_block  = ('<div class="field-label">CVSS 4.0</div><div>%s (%s)</div>'
                               % (f.get("cvss4_score","N/A"), f.get("cvss4_severity","N/A")))
                              if "cvss4_score" in f else "",
                payload_esc = html.escape(str(f.get("payload", ""))),
                evidence_esc= html.escape(str(f.get("evidence", ""))[:500]),
                remediation = html.escape(remed),
            )

        meta = self._meta
        banner_txt = "GenSQL v%s | by Jeevraj | Advanced SQL Injection Framework" % meta.get("version","2.0.0")
        return HTML_TEMPLATE.format(
            scan_time      = time.strftime("%Y-%m-%d %H:%M:%S"),
            target         = html.escape(meta.get("target", "Unknown")),
            version        = meta.get("version", "2.0.0"),
            dbms           = html.escape(meta.get("dbms", "Unknown")),
            total_vulns    = len(self._findings),
            critical_count = counts["CRITICAL"],
            high_count     = counts["HIGH"],
            medium_count   = counts["MEDIUM"],
            total_requests = meta.get("total_requests", 0),
            scan_duration  = "%.1f" % (time.time() - self.scan_start),
            banner         = html.escape(banner_txt),
            findings_html  = findings_html or "<p style='color:#8b949e;padding:20px'>No vulnerabilities recorded.</p>",
        )

    def generate_json(self):
        """Generate JSON report."""
        return json.dumps({
            "meta": {
                "tool":       "GenSQL",
                "version":    "2.0.0",
                "author":     "Jeevraj",
                "scan_time":  time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration":   "%.1fs" % (time.time() - self.scan_start),
                **self._meta,
            },
            "summary": {
                "total":    len(self._findings),
                "critical": sum(1 for f in self._findings if f.get("severity") == "CRITICAL"),
                "high":     sum(1 for f in self._findings if f.get("severity") == "HIGH"),
                "medium":   sum(1 for f in self._findings if f.get("severity") == "MEDIUM"),
                "low":      sum(1 for f in self._findings if f.get("severity") == "LOW"),
            },
            "findings": self._findings,
        }, indent=2, ensure_ascii=False)

    def generate_markdown(self):
        """Generate Markdown report."""
        lines = [
            "# GenSQL Security Assessment Report",
            "",
            "**Author:** Jeevraj | **Tool:** GenSQL v2.0.0",
            "**Generated:** %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
            "**Target:** %s" % self._meta.get("target", "Unknown"),
            "**DBMS:** %s" % self._meta.get("dbms", "Unknown"),
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = sum(1 for f in self._findings if f.get("severity") == sev)
            lines.append("| %s | %d |" % (sev, n))
        lines.extend(["", "## Findings", ""])
        for f in self._findings:
            lines.extend([
                "### #%d — %s [%s]" % (f["id"], f.get("type","SQLi"), f.get("severity","INFO")),
                "",
                "- **URL:** `%s`" % f.get("url",""),
                "- **Parameter:** `%s`" % f.get("parameter",""),
                "- **DBMS:** %s" % f.get("dbms",""),
                "- **Technique:** %s" % f.get("technique",""),
                "",
                "**Payload:**",
                "```",
                str(f.get("payload","")),
                "```",
                "",
                "**Evidence:**",
                "```",
                str(f.get("evidence",""))[:300],
                "```",
                "",
            ])
        lines.extend(["---", "", "_GenSQL — Next-Generation SQL Injection Framework — by Jeevraj_"])
        return "\n".join(lines)

    # ── Finalize (write all configured report files) ───────────────────────
    def finalize(self):
        """Write all configured report files."""
        written = []
        if self.html_path:
            with open(self.html_path, "w", encoding="utf-8") as f:
                f.write(self.generate_html())
            written.append(self.html_path)
        if self.json_path:
            with open(self.json_path, "w", encoding="utf-8") as f:
                f.write(self.generate_json())
            written.append(self.json_path)
        if self.md_path:
            with open(self.md_path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown())
            written.append(self.md_path)
        return written
