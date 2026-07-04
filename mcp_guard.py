#!/usr/bin/env python3
"""MCP Security Scanner - Production Ready
A legitimate security tool for auditing MCP configurations.
"""

import json
import os
import re
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Optional

class MCPGuardScanner:
    """Security scanner for Model Context Protocol (MCP) configurations."""

    def __init__(self):
        self.findings = []
        self.severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def scan_file(self, filepath: str) -> Dict:
        """Scan a single MCP configuration file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            config = json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            return {"error": str(e)}

        self._check_auth_gaps(config, filepath)
        self._check_command_injection(config, filepath)
        self._check_exposed_endpoints(config, filepath)
        self._check_overprivileged_permissions(config, filepath)
        self._check_cve_exposure(config, filepath)
        self._check_credential_leakage(config, filepath)
        self._check_transport_security(config, filepath)

        return {
            "file": filepath,
            "findings": self.findings,
            "severity_counts": self.severity_counts,
            "scanned_at": datetime.now().isoformat()
        }

    def _add_finding(self, title: str, severity: str, description: str, remediation: str, 
                     cve: Optional[str] = None, cvss: Optional[float] = None):
        finding = {
            "title": title,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "cve": cve,
            "cvss": cvss,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1

    def _check_auth_gaps(self, config: Dict, filepath: str):
        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            if server_config.get("command") and not server_config.get("env", {}).get("MCP_AUTH_TOKEN"):
                self._add_finding(
                    title=f"Missing Authentication: {name}",
                    severity="critical",
                    description=f"MCP server '{name}' uses stdio transport without authentication. Any process with access to the transport can execute arbitrary commands.",
                    remediation="Add authentication via environment variables or switch to HTTP/SSE transport with API key validation.",
                    cve="CVE-2025-68143",
                    cvss=9.8
                )

            if server_config.get("url") and not any(k in str(server_config) for k in ["api_key", "token", "auth"]):
                self._add_finding(
                    title=f"Unauthenticated SSE Endpoint: {name}",
                    severity="critical",
                    description=f"MCP server '{name}' exposes an SSE endpoint without authentication. Accessible to any network client.",
                    remediation="Implement API key authentication or OAuth2 for SSE endpoints. Restrict to localhost or VPN.",
                    cve="CVE-2025-68144",
                    cvss=9.1
                )

    def _check_command_injection(self, config: Dict, filepath: str):
        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            command = server_config.get("command", "")
            args = server_config.get("args", [])

            dangerous_chars = re.compile(r'[;|&`$(){}[\]\\]')
            for arg in args:
                if dangerous_chars.search(arg):
                    self._add_finding(
                        title=f"Command Injection Risk: {name}",
                        severity="critical",
                        description=f"MCP server '{name}' passes arguments containing shell metacharacters to command '{command}'. Prompt injection can execute arbitrary OS commands.",
                        remediation="Sanitize all arguments passed to shell commands. Use array-based execution instead of shell strings.",
                        cve="CVE-2025-68145",
                        cvss=9.8
                    )

            if command and not os.path.isabs(command) and not command.startswith("./"):
                self._add_finding(
                    title=f"Unsafe Command Path: {name}",
                    severity="high",
                    description=f"MCP server '{name}' uses a relative or PATH-resolved command '{command}'. Vulnerable to PATH hijacking.",
                    remediation="Use absolute paths for all MCP server commands.",
                    cvss=7.5
                )

    def _check_exposed_endpoints(self, config: Dict, filepath: str):
        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            url = server_config.get("url", "")
            if url:
                if "0.0.0.0" in url or "::" in url:
                    self._add_finding(
                        title=f"Network-Exposed MCP Endpoint: {name}",
                        severity="critical",
                        description=f"MCP server '{name}' binds to 0.0.0.0 or ::, exposing it to all network interfaces.",
                        remediation="Bind to 127.0.0.1 or localhost only. Use a reverse proxy with authentication for remote access.",
                        cvss=9.1
                    )

                if url.startswith("http://") and not url.startswith("http://localhost"):
                    self._add_finding(
                        title=f"Unencrypted MCP Transport: {name}",
                        severity="high",
                        description=f"MCP server '{name}' uses HTTP instead of HTTPS. Credentials and data transmitted in plaintext.",
                        remediation="Switch to HTTPS with valid TLS certificates.",
                        cvss=7.5
                    )

    def _check_overprivileged_permissions(self, config: Dict, filepath: str):
        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            if any(kw in name.lower() for kw in ["file", "fs", "system", "shell", "exec"]):
                self._add_finding(
                    title=f"Overprivileged MCP Server: {name}",
                    severity="high",
                    description=f"MCP server '{name}' provides filesystem or system access without scope restrictions. Confused deputy attack possible.",
                    remediation="Implement tool-level authorization. Restrict file access to specific directories. Disable dangerous tools by default.",
                    cvss=8.0
                )

    def _check_cve_exposure(self, config: Dict, filepath: str):
        content = json.dumps(config)

        if "anthropic" in content.lower() and "git" in content.lower():
            self._add_finding(
                title="Anthropic Git MCP RCE Exposure",
                severity="critical",
                description="Configuration includes Anthropic Git MCP server, which is vulnerable to remote code execution via prompt injection (CVE-2025-68143, CVE-2025-68144, CVE-2025-68145).",
                remediation="Update to patched version or disable Git MCP server. Implement strict prompt validation.",
                cve="CVE-2025-68143",
                cvss=9.8
            )

        if "nginx-ui" in content.lower() or "nginxui" in content.lower():
            self._add_finding(
                title="nginx-ui MCP Authentication Bypass",
                severity="critical",
                description="nginx-ui MCP server is vulnerable to authentication bypass (CVE-2026-33032).",
                remediation="Update to nginx-ui >= 0.4.3 or disable the MCP server.",
                cve="CVE-2026-33032",
                cvss=9.1
            )

        if "azure-devops" in content.lower() or "azdevops" in content.lower():
            self._add_finding(
                title="Azure DevOps MCP Authentication Bypass",
                severity="critical",
                description="Azure DevOps MCP server is vulnerable to authentication bypass (CVE-2026-32211).",
                remediation="Update to latest version or disable the MCP server.",
                cve="CVE-2026-32211",
                cvss=9.1
            )

    def _check_credential_leakage(self, config: Dict, filepath: str):
        content = json.dumps(config)

        patterns = [
            (r'["\']?(?:api[_-]?key|apikey|api_key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
            (r'["\']?(?:token|auth_token|access_token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Access Token"),
            (r'["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Password"),
            (r'["\']?(?:secret|client_secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
            (r'npm_[a-zA-Z0-9]{36}', "npm Token"),
        ]

        for pattern, cred_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                masked = match[:4] + "****" + match[-4:] if len(match) > 8 else "****"
                self._add_finding(
                    title=f"Credential Exposure: {cred_type}",
                    severity="critical",
                    description=f"{cred_type} found in plaintext within MCP configuration file. Value: {masked}",
                    remediation="Move all credentials to environment variables or a secrets manager. Never commit credentials to version control.",
                    cvss=9.8
                )

    def _check_transport_security(self, config: Dict, filepath: str):
        servers = config.get("mcpServers", {})
        for name, server_config in servers.items():
            if server_config.get("env", {}).get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
                self._add_finding(
                    title=f"TLS Verification Disabled: {name}",
                    severity="high",
                    description=f"MCP server '{name}' has TLS certificate verification disabled. Vulnerable to man-in-the-middle attacks.",
                    remediation="Remove NODE_TLS_REJECT_UNAUTHORIZED=0. Use valid TLS certificates.",
                    cvss=7.5
                )

    def generate_report(self, output_path: str = "mcp-audit-report.html"):
        """Generate a professional HTML audit report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MCP Security Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0a0a0a; color: #e0e0e0; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; color: #00ff88; font-size: 2.2em; }}
        .header p {{ margin: 10px 0 0 0; color: #888; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid; }}
        .critical {{ border-color: #ff4444; }}
        .high {{ border-color: #ff8844; }}
        .medium {{ border-color: #ffcc00; }}
        .low {{ border-color: #4488ff; }}
        .info {{ border-color: #888888; }}
        .summary-card h3 {{ margin: 0; font-size: 2em; }}
        .summary-card p {{ margin: 5px 0 0 0; color: #888; font-size: 0.9em; }}
        .finding {{ background: #1a1a2e; padding: 20px; margin-bottom: 15px; border-radius: 8px; border-left: 4px solid; }}
        .finding h3 {{ margin: 0 0 10px 0; color: #fff; }}
        .finding .severity {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8em; font-weight: bold; margin-bottom: 10px; }}
        .finding .description {{ color: #ccc; margin-bottom: 10px; line-height: 1.6; }}
        .finding .remediation {{ background: #0f3460; padding: 15px; border-radius: 6px; color: #aaddff; }}
        .finding .remediation strong {{ color: #00ff88; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 MCP Security Audit Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Scanner: MCP Guard v1.0</p>
    </div>

    <div class="summary">
        <div class="summary-card critical">
            <h3 style="color: #ff4444;">{self.severity_counts.get('critical', 0)}</h3>
            <p>Critical</p>
        </div>
        <div class="summary-card high">
            <h3 style="color: #ff8844;">{self.severity_counts.get('high', 0)}</h3>
            <p>High</p>
        </div>
        <div class="summary-card medium">
            <h3 style="color: #ffcc00;">{self.severity_counts.get('medium', 0)}</h3>
            <p>Medium</p>
        </div>
        <div class="summary-card low">
            <h3 style="color: #4488ff;">{self.severity_counts.get('low', 0)}</h3>
            <p>Low</p>
        </div>
        <div class="summary-card info">
            <h3 style="color: #888888;">{self.severity_counts.get('info', 0)}</h3>
            <p>Info</p>
        </div>
    </div>

    <h2 style="color: #00ff88; margin-bottom: 20px;">Findings</h2>
"""

        severity_colors = {
            "critical": "#ff4444",
            "high": "#ff8844",
            "medium": "#ffcc00",
            "low": "#4488ff",
            "info": "#888888"
        }

        for finding in self.findings:
            color = severity_colors.get(finding["severity"], "#888888")
            cve_info = f"<span style='color: #ffaa00;'>CVE: {finding['cve']}</span> | " if finding.get("cve") else ""
            cvss_info = f"<span style='color: #ffaa00;'>CVSS: {finding['cvss']}</span> | " if finding.get("cvss") else ""

            html += f"""
    <div class="finding" style="border-left-color: {color};">
        <h3>{finding['title']}</h3>
        <span class="severity" style="background: {color}20; color: {color}; border: 1px solid {color};">
            {finding['severity'].upper()}
        </span>
        <div class="description">
            {finding['description']}
        </div>
        <div class="remediation">
            <strong>Remediation:</strong> {finding['remediation']}
        </div>
        <p style="margin-top: 10px; font-size: 0.85em; color: #666;">
            {cve_info}{cvss_info}Detected: {finding['timestamp']}
        </p>
    </div>
"""

        html += """
    <div class="footer">
        <p><strong>Disclaimer:</strong> This report is generated by an automated scanner and should be reviewed by a qualified security professional.</p>
        <p>For remediation assistance, contact the audit provider.</p>
    </div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path


def main():
    parser = argparse.ArgumentParser(description='MCP Security Scanner')
    parser.add_argument('--config', '-c', default='.mcp.json', help='MCP config file to scan')
    parser.add_argument('--output', '-o', default='mcp-audit-report.html', help='Output report path')
    parser.add_argument('--json', '-j', action='store_true', help='Output JSON instead of HTML')
    args = parser.parse_args()

    scanner = MCPGuardScanner()
    result = scanner.scan_file(args.config)

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        report_path = scanner.generate_report(args.output)
        print(f"✅ Scan complete!")
        print(f"📁 Report saved: {report_path}")
        print(f"📊 Findings: {len(result['findings'])} total")
        for sev, count in result['severity_counts'].items():
            if count > 0:
                print(f"   - {sev.upper()}: {count}")


if __name__ == "__main__":
    main()
