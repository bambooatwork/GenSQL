#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL Report Engine - CVSS 4.0 HTML/JSON/Markdown reports
Author: Jeevraj
Features: Professional HTML reports, CVSS 4.0 scoring, vulnerability details
"""

import json
import time
from datetime import datetime

class ReportEngine(object):
    """Generate professional security reports."""

    def __init__(self, html_path=None, json_path=None, md_path=None, cvss4=False, verbose=False):
        self.html_path = html_path
        self.json_path = json_path
        self.md_path = md_path
        self.cvss4 = cvss4
        self.verbose = verbose
        self.vulnerabilities = []
        self.scan_info = {}

    def add_vulnerability(self, vuln_type, severity, description, payload=None, evidence=None):
        """
        Add vulnerability to report.
        
        Args:
            vuln_type: Type of vulnerability
            severity: Severity level (Critical, High, Medium, Low)
            description: Vulnerability description
            payload: Payload used
            evidence: Evidence/proof
        
        Returns:
            Vulnerability ID
        """
        vuln = {
            'id': f"VUL-{len(self.vulnerabilities)+1}",
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'payload': payload,
            'evidence': evidence,
            'cvss_score': self._calculate_cvss(severity),
            'timestamp': datetime.now().isoformat(),
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(f"[+] Added vulnerability: {vuln['type']} ({severity})")
        
        return vuln['id']

    def _calculate_cvss(self, severity):
        """
        Calculate CVSS 4.0 score based on severity.
        
        Args:
            severity: Severity level
        
        Returns:
            CVSS score (0-10)
        """
        scores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0,
            'Info': 0.0,
        }
        return scores.get(severity, 0.0)

    def generate_html_report(self, title="GenSQL Security Assessment Report"):
        """
        Generate HTML report.
        
        Args:
            title: Report title
        
        Returns:
            HTML content
        """
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #1e1e1e;
            color: #e0e0e0;
            margin: 20px;
        }}
        h1 {{
            color: #00ff00;
            text-align: center;
        }}
        h2 {{
            color: #ffaa00;
            border-bottom: 2px solid #ffaa00;
            padding-bottom: 10px;
        }}
        .critical {{
            background-color: #b30000;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .high {{
            background-color: #ff6600;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .medium {{
            background-color: #ffaa00;
            color: #000;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .low {{
            background-color: #00aa00;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .vulnerability {{
            background-color: #2a2a2a;
            padding: 15px;
            margin: 10px 0;
            border-left: 5px solid #ffaa00;
        }}
        .payload {{
            background-color: #1a1a1a;
            padding: 10px;
            font-family: monospace;
            overflow-x: auto;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .summary {{
            background-color: #2a2a2a;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #444;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #333;
            color: #00ff00;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr><th>Scan Date</th><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>Total Vulnerabilities</th><td>{len(self.vulnerabilities)}</td></tr>
            <tr><th>Critical</th><td><span style="color: #b30000;">{sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical')}</span></td></tr>
            <tr><th>High</th><td><span style="color: #ff6600;">{sum(1 for v in self.vulnerabilities if v['severity'] == 'High')}</span></td></tr>
            <tr><th>Medium</th><td><span style="color: #ffaa00;">{sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')}</span></td></tr>
            <tr><th>Low</th><td><span style="color: #00aa00;">{sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')}</span></td></tr>
        </table>
    </div>
    
    <div class="summary">
        <h2>Findings</h2>
'''
        
        for vuln in self.vulnerabilities:
            html += f'''    <div class="vulnerability {vuln['severity'].lower()}">
                <h3>{vuln['type']}</h3>
                <p><strong>Severity:</strong> {vuln['severity']}</p>
                <p><strong>CVSS Score:</strong> {vuln['cvss_score']}/10</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
'''
            
            if vuln['payload']:
                html += f'''        <p><strong>Payload:</strong></p>
                <div class="payload">{vuln['payload']}</div>
'''
            
            if vuln['evidence']:
                html += f'''        <p><strong>Evidence:</strong> {vuln['evidence']}</p>
'''
            
            html += '''    </div>
'''
        
        html += '''    </div>
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #444; text-align: center; color: #888;">
        <p>Generated by GenSQL v2.0.0 | Next-Generation Web Security Assessment Framework</p>
    </footer>
</body>
</html>
'''
        
        return html

    def generate_json_report(self):
        """
        Generate JSON report.
        
        Returns:
            JSON string
        """
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'GenSQL v2.0.0',
                'scan_type': 'Full Assessment',
            },
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'High'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'Low'),
            },
            'vulnerabilities': self.vulnerabilities,
        }
        
        return json.dumps(report, indent=2)

    def generate_markdown_report(self):
        """
        Generate Markdown report.
        
        Returns:
            Markdown string
        """
        md = f'''# GenSQL Security Assessment Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Vulnerabilities | {len(self.vulnerabilities)} |
| Critical | {sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical')} |
| High | {sum(1 for v in self.vulnerabilities if v['severity'] == 'High')} |
| Medium | {sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')} |
| Low | {sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')} |

## Findings

'''
        
        for vuln in self.vulnerabilities:
            md += f'''### {vuln['type']}

- **Severity:** {vuln['severity']}
- **CVSS Score:** {vuln['cvss_score']}/10
- **Description:** {vuln['description']}
'''
            
            if vuln['payload']:
                md += f'''\n**Payload:**\n```\n{vuln['payload']}\n```\n'''
            
            if vuln['evidence']:
                md += f'''\n**Evidence:** {vuln['evidence']}\n'''
            
            md += "\n---\n\n"
        
        md += "\n*Generated by GenSQL v2.0.0 - Next-Generation Web Security Assessment Framework*"
        
        return md

    def finalize(self):
        """
        Write all reports to files.
        """
        if self.html_path:
            with open(self.html_path, 'w') as f:
                f.write(self.generate_html_report())
            if self.verbose:
                print(f"[+] HTML report written to {self.html_path}")
        
        if self.json_path:
            with open(self.json_path, 'w') as f:
                f.write(self.generate_json_report())
            if self.verbose:
                print(f"[+] JSON report written to {self.json_path}")
        
        if self.md_path:
            with open(self.md_path, 'w') as f:
                f.write(self.generate_markdown_report())
            if self.verbose:
                print(f"[+] Markdown report written to {self.md_path}")
