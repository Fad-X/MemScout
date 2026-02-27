"""
reports/generator.py
HTML and JSON report generation for MemScout.
Includes: findings, simple mode (OS info, users, cmdlines, network), URL extraction.
"""

import json
from pathlib import Path
from datetime import datetime

try:
    from jinja2 import Environment, select_autoescape
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

try:
    import weasyprint
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


SEVERITY_COLORS = {
    "CRITICAL": "#7c0000",
    "HIGH": "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW": "#f1c40f",
    "INFO": "#3498db",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MemScout Report — {{ meta.image_name }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
        .header { background: linear-gradient(135deg, #161b22, #1f2937); padding: 40px; border-bottom: 2px solid #30363d; }
        .header h1 { font-size: 2em; color: #58a6ff; margin-bottom: 6px; }
        .header .subtitle { color: #8b949e; font-size: 0.95em; }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px 20px; }
        .tabs { display: flex; gap: 4px; margin: 24px 0 0; border-bottom: 2px solid #30363d; flex-wrap: wrap; }
        .tab-btn { padding: 10px 20px; background: none; border: none; border-bottom: 3px solid transparent;
                   color: #8b949e; cursor: pointer; font-size: 0.9em; font-weight: 600;
                   margin-bottom: -2px; transition: all 0.2s; }
        .tab-btn:hover { color: #c9d1d9; }
        .tab-btn.active { color: #58a6ff; border-bottom-color: #58a6ff; }
        .tab-content { display: none; padding-top: 24px; }
        .tab-content.active { display: block; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }
        .meta-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
        .meta-card .label { font-size: 0.72em; color: #8b949e; text-transform: uppercase; letter-spacing: 0.6px; }
        .meta-card .value { font-size: 1.05em; color: #e6edf3; font-weight: 600; margin-top: 5px; }
        .summary-box { background: #1f2d1f; border: 1px solid #238636; border-radius: 8px; padding: 18px 22px; margin: 18px 0; }
        .summary-box.danger { background: #2d1f1f; border-color: #c0392b; }
        .summary-box p { color: #7ee787; font-size: 0.97em; }
        .summary-box.danger p { color: #f87171; }
        .severity-bar { display: flex; gap: 10px; flex-wrap: wrap; margin: 18px 0; }
        .sev-badge { padding: 6px 16px; border-radius: 20px; font-weight: 700; font-size: 0.85em; }
        .sev-HIGH     { background:#c0392b22;border:1px solid #c0392b;color:#e74c3c; }
        .sev-MEDIUM   { background:#e67e2222;border:1px solid #e67e22;color:#e67e22; }
        .sev-LOW      { background:#f1c40f22;border:1px solid #f1c40f;color:#f1c40f; }
        .sev-CRITICAL { background:#7c000022;border:1px solid #7c0000;color:#ff4444; }
        .sev-INFO     { background:#3498db22;border:1px solid #3498db;color:#3498db; }
        .section { margin: 28px 0; }
        .section-h { color: #58a6ff; font-size: 1.1em; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
        .finding { background: #161b22; border: 1px solid #30363d; border-left: 4px solid #555;
                   border-radius: 6px; padding: 14px 18px; margin-bottom: 10px; }
        .finding.HIGH     { border-left-color: #c0392b; }
        .finding.CRITICAL { border-left-color: #7c0000; }
        .finding.MEDIUM   { border-left-color: #e67e22; }
        .finding.LOW      { border-left-color: #f1c40f; }
        .finding.INFO     { border-left-color: #3498db; }
        .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 7px; }
        .finding-sev { font-size: 0.7em; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
        .finding-cat { font-size: 0.78em; color: #8b949e; }
        .finding-title { font-weight: 600; color: #e6edf3; }
        .finding-detail { color: #8b949e; font-size: 0.85em; margin-top: 6px; white-space: pre-wrap; font-family: monospace; }
        .info-table { width: 100%; border-collapse: collapse; }
        .info-table td { padding: 7px 14px; border-bottom: 1px solid #21262d; font-size: 0.9em; }
        .info-table td:first-child { color: #8b949e; font-weight: 600; width: 240px; }
        .info-table td:last-child { color: #e6edf3; font-family: monospace; word-break: break-all; }
        .net-table { width: 100%; border-collapse: collapse; font-size: 0.82em; margin-top: 10px; }
        .net-table th { background: #21262d; color: #8b949e; padding: 7px 10px; text-align: left; font-weight: 600; }
        .net-table td { padding: 6px 10px; border-bottom: 1px solid #21262d; color: #c9d1d9; font-family: monospace; }
        .net-table tr:hover td { background: #1c2128; }
        .ext-ip { color: #f97316; font-weight: 600; }
        .int-ip { color: #34d399; }
        .user-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
        .user-badge { background: #1c2d3d; border: 1px solid #1d6fa4; color: #58a6ff;
                      padding: 6px 16px; border-radius: 14px; font-size: 0.92em; font-weight: 600; }
        .cmdline-hit { background: #1e1410; border: 1px solid #c0392b44; border-left: 3px solid #c0392b;
                       border-radius: 5px; padding: 10px 14px; margin-bottom: 8px; }
        .cmdline-proc { color: #f87171; font-weight: 700; font-size: 0.88em; }
        .cmdline-cmd  { color: #8b949e; font-family: monospace; font-size: 0.82em; margin-top: 5px; word-break: break-all; }
        .kw-hl { color: #fbbf24; font-weight: 700; }
        .url-sus { background: #1e1410; border: 1px solid #c0392b44; border-left: 3px solid #c0392b;
                   border-radius: 5px; padding: 8px 14px; margin-bottom: 6px; font-family: monospace; font-size: 0.82em; }
        .url-sus .reason { color: #fbbf24; font-weight: 700; margin-right: 8px; }
        .url-sus .url    { color: #f87171; word-break: break-all; }
        .url-clean { color: #8b949e; font-family: monospace; font-size: 0.8em;
                     padding: 3px 8px; border-bottom: 1px solid #21262d; word-break: break-all; }
        .plugin-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
        .plugin-table th { background: #21262d; color: #8b949e; padding: 8px 12px; text-align: left; font-weight: 600; }
        .plugin-table td { padding: 7px 12px; border-bottom: 1px solid #21262d; color: #c9d1d9; }
        .no-data  { color: #3fb950; text-align: center; padding: 30px; }
        .footer   { text-align: center; padding: 22px; color: #484f58; font-size: 0.8em;
                    border-top: 1px solid #21262d; margin-top: 40px; }
        .badge-count { display: inline-block; background: #30363d; border-radius: 10px;
                       padding: 1px 8px; font-size: 0.78em; margin-left: 6px; color: #8b949e; }
        .sub-h { margin: 20px 0 10px; font-size: 1em; font-weight: 700; }
    </style>
</head>
<body>

<div class="header">
    <div class="container">
        <h1>🔍 MemScout Analysis Report</h1>
        <div class="subtitle">Memory Forensics Automation Tool &nbsp;|&nbsp; Generated {{ meta.generated_at }}</div>
    </div>
</div>

<div class="container">

    <div class="meta-grid">
        <div class="meta-card"><div class="label">Memory Image</div><div class="value">{{ meta.image_name }}</div></div>
        <div class="meta-card"><div class="label">OS Type</div><div class="value">{{ meta.os_type | upper }}</div></div>
        <div class="meta-card"><div class="label">Scan Duration</div><div class="value">{{ meta.elapsed_seconds }}s</div></div>
        <div class="meta-card"><div class="label">Plugins Run</div><div class="value">{{ meta.plugins_run }}</div></div>
        <div class="meta-card"><div class="label">Total Findings</div><div class="value">{{ stats.total_findings }}</div></div>
        <div class="meta-card"><div class="label">Scan Start</div><div class="value">{{ meta.scan_start }}</div></div>
    </div>

    {% set high_count = stats.by_severity.get('HIGH', 0) + stats.by_severity.get('CRITICAL', 0) %}
    <div class="summary-box {% if high_count > 0 %}danger{% endif %}">
        <p>{{ summary }}</p>
    </div>

    <div class="severity-bar">
        {% for sev, count in stats.by_severity.items() %}{% if count > 0 %}
        <div class="sev-badge sev-{{ sev }}">{{ sev }}: {{ count }}</div>
        {% endif %}{% endfor %}
    </div>

    <!-- Tabs -->
    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('findings', this)">⚠️ Findings <span class="badge-count">{{ findings | length }}</span></button>
        {% if simple %}<button class="tab-btn" onclick="switchTab('system', this)">🖥️ System Info</button>{% endif %}
        {% if simple %}<button class="tab-btn" onclick="switchTab('users', this)">👤 Users <span class="badge-count">{{ simple.logged_in_users | length }}</span></button>{% endif %}
        {% if simple %}<button class="tab-btn" onclick="switchTab('cmdlines', this)">💻 Cmdlines <span class="badge-count">{{ simple.suspicious_cmdlines | length }}</span></button>{% endif %}
        {% if simple %}<button class="tab-btn" onclick="switchTab('network', this)">🌐 Network</button>{% endif %}
        {% if urls %}<button class="tab-btn" onclick="switchTab('urls', this)">🔗 URLs <span class="badge-count">{{ urls.total_full_urls }}</span></button>{% endif %}
        <button class="tab-btn" onclick="switchTab('plugins', this)">🔧 Plugins</button>
    </div>

    <!-- FINDINGS -->
    <div id="tab-findings" class="tab-content active">
        {% if findings %}
            {% for f in findings %}
            <div class="finding {{ f.severity }}">
                <div class="finding-header">
                    <span class="finding-sev" style="background:{{ severity_colors.get(f.severity,'#555') }}33;color:{{ severity_colors.get(f.severity,'#aaa') }};border:1px solid {{ severity_colors.get(f.severity,'#555') }}">{{ f.severity }}</span>
                    <span class="finding-cat">{{ f.category }}</span>
                </div>
                <div class="finding-title">{{ f.title }}</div>
                <div class="finding-detail">{{ f.detail }}</div>
            </div>
            {% endfor %}
        {% else %}
            <div class="no-data">✅ No suspicious indicators detected.</div>
        {% endif %}
    </div>

    <!-- SYSTEM INFO -->
    {% if simple %}
    <div id="tab-system" class="tab-content">
        <h2 class="section-h">🖥️ OS & System Information</h2>
        <table class="info-table">
            <tr><td>OS Type</td><td>{{ simple.os_info.os_type | upper }}</td></tr>
            <tr><td>Kernel / Build</td><td>{{ simple.os_info.kernel_version }}</td></tr>
            <tr><td>System Time</td><td>{{ simple.os_info.system_time }}</td></tr>
            <tr><td>Memory Model</td><td>{{ simple.os_info.memory_model }}</td></tr>
            <tr><td>Image Type</td><td>{{ simple.os_info.image_type }}</td></tr>
            {% for k, v in simple.os_info.raw.items() %}
            <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <!-- USERS -->
    <div id="tab-users" class="tab-content">
        <h2 class="section-h">👤 Logged-in User Sessions</h2>
        <div class="user-list">
            {% for user in simple.logged_in_users %}
            <div class="user-badge">{{ user }}</div>
            {% else %}
            <p style="color:#8b949e">No user sessions detected.</p>
            {% endfor %}
        </div>
    </div>

    <!-- CMDLINES -->
    <div id="tab-cmdlines" class="tab-content">
        <h2 class="section-h">💻 Suspicious Command Lines</h2>
        {% if simple.suspicious_cmdlines %}
            {% for h in simple.suspicious_cmdlines %}
            <div class="cmdline-hit">
                <div class="cmdline-proc">
                    ⚠ {{ h.process }} &nbsp; (PID: {{ h.pid }}) &nbsp;→ keyword:
                    <span class="kw-hl">{{ h.matched_keyword }}</span>
                </div>
                <div class="cmdline-cmd">{{ h.cmdline }}</div>
            </div>
            {% endfor %}
        {% else %}
            <div class="no-data">✅ No suspicious command lines found.</div>
        {% endif %}
    </div>

    <!-- NETWORK -->
    <div id="tab-network" class="tab-content">
        <h2 class="section-h">🌐 Network Connections &nbsp;<span class="badge-count">{{ simple.network.raw_count }} total</span></h2>

        <p class="sub-h" style="color:#f97316">🌍 External IPs &nbsp;<span class="badge-count">{{ simple.network.external | length }}</span></p>
        {% if simple.network.external %}
        <table class="net-table">
            <tr><th>Proto</th><th>Local Address</th><th>Foreign (External)</th><th>State</th><th>PID / Owner</th></tr>
            {% for c in simple.network.external %}
            <tr>
                <td>{{ c.proto }}</td>
                <td class="int-ip">{{ c.local }}</td>
                <td class="ext-ip">{{ c.foreign }}</td>
                <td>{{ c.state }}</td>
                <td>{{ c.owner }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}<p style="color:#8b949e;margin:8px 0">No external connections found.</p>{% endif %}

        <p class="sub-h" style="color:#34d399;margin-top:28px">🏠 Internal IPs &nbsp;<span class="badge-count">{{ simple.network.internal | length }}</span></p>
        {% if simple.network.internal %}
        <table class="net-table">
            <tr><th>Proto</th><th>Local Address</th><th>Foreign (Internal)</th><th>State</th><th>PID / Owner</th></tr>
            {% for c in simple.network.internal %}
            <tr>
                <td>{{ c.proto }}</td>
                <td class="int-ip">{{ c.local }}</td>
                <td class="int-ip">{{ c.foreign }}</td>
                <td>{{ c.state }}</td>
                <td>{{ c.owner }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}<p style="color:#8b949e;margin:8px 0">No internal connections found.</p>{% endif %}
    </div>
    {% endif %}

    <!-- URLS -->
    {% if urls %}
    <div id="tab-urls" class="tab-content">
        <h2 class="section-h">🔗 URLs Extracted from Memory Strings</h2>
        <div class="meta-grid" style="margin-bottom:20px">
            <div class="meta-card"><div class="label">Full URLs Found</div><div class="value">{{ urls.total_full_urls }}</div></div>
            <div class="meta-card"><div class="label">Bare Domains</div><div class="value">{{ urls.total_bare_domains }}</div></div>
            <div class="meta-card"><div class="label">Suspicious</div><div class="value" style="color:#e74c3c">{{ urls.suspicious_urls | length }}</div></div>
        </div>

        {% if urls.suspicious_urls %}
        <p class="sub-h" style="color:#c0392b">⚠️ Suspicious URLs ({{ urls.suspicious_urls | length }})</p>
        {% for entry in urls.suspicious_urls %}
        <div class="url-sus">
            <span class="reason">[{{ entry.reason }}]</span>
            <span class="url">{{ entry.url }}</span>
        </div>
        {% endfor %}
        {% else %}
        <div class="no-data">✅ No suspicious URLs detected.</div>
        {% endif %}

        {% if urls.clean_urls %}
        <p class="sub-h" style="color:#58a6ff;margin-top:24px">🔗 All Full URLs ({{ urls.clean_urls | length }})</p>
        {% for entry in urls.clean_urls[:200] %}
        <div class="url-clean">{{ entry.url }}</div>
        {% endfor %}
        {% if urls.clean_urls | length > 200 %}
        <p style="color:#8b949e;font-size:0.82em;margin-top:8px">… {{ urls.clean_urls | length - 200 }} more — see extracted_urls.json</p>
        {% endif %}
        {% endif %}

        {% if urls.bare_domains %}
        <p class="sub-h" style="color:#58a6ff;margin-top:24px">🌐 Bare Domains ({{ urls.bare_domains | length }})</p>
        {% for entry in urls.bare_domains[:100] %}
        <div class="url-clean">{{ entry.url }}</div>
        {% endfor %}
        {% if urls.bare_domains | length > 100 %}
        <p style="color:#8b949e;font-size:0.82em;margin-top:8px">… {{ urls.bare_domains | length - 100 }} more — see extracted_urls.json</p>
        {% endif %}
        {% endif %}
    </div>
    {% endif %}

    <!-- PLUGINS -->
    <div id="tab-plugins" class="tab-content">
        <h2 class="section-h">🔧 Plugin Results Summary</h2>
        <table class="plugin-table">
            <tr><th>Plugin</th><th>Status</th><th>Rows</th></tr>
            {% for plugin, data in plugin_summary.items() %}
            <tr>
                <td>{{ plugin }}</td>
                <td style="color:{% if data.status=='OK' %}#3fb950{% else %}#f87171{% endif %}">{{ data.status }}</td>
                <td>{{ data.rows }}</td>
            </tr>
            {% endfor %}
            {% for plugin, error in errors.items() %}
            <tr>
                <td>{{ plugin }}</td>
                <td style="color:#f87171">FAILED</td>
                <td style="color:#8b949e;font-size:0.82em">{{ error[:70] }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

</div>

<div class="footer">
    Generated by MemScout &nbsp;|&nbsp; {{ meta.generated_at }} &nbsp;|&nbsp; For authorized forensic analysis only
</div>

<script>
function switchTab(name, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
}
</script>
</body>
</html>
"""


class ReportGenerator:
    """Generates HTML and JSON reports from MemScout analysis results."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        runner_summary: dict,
        scan_results: dict,
        analysis: dict,
        errors: dict = None,
    ) -> dict:
        errors = errors or {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_name = Path(runner_summary.get("image", "unknown")).name

        # Build plugin summary (skip internal __ keys)
        plugin_summary = {}
        for plugin, data in scan_results.items():
            if plugin.startswith("__"):
                continue
            plugin_summary[plugin] = {
                "status": "OK" if isinstance(data, dict) and data.get("returncode") == 0 else "FAILED",
                "rows": len(data.get("rows", [])) if isinstance(data, dict) else 0,
            }

        simple_data = scan_results.get("__simple__", None)
        url_data = scan_results.get("__urls__", None)

        context = {
            "meta": {
                "image_name": image_name,
                "os_type": runner_summary.get("os_type", "unknown"),
                "elapsed_seconds": runner_summary.get("elapsed_seconds", 0),
                "plugins_run": runner_summary.get("plugins_run", 0),
                "scan_start": runner_summary.get("scan_start", "N/A"),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "findings": analysis.get("findings", []),
            "stats": analysis.get("stats", {"total_findings": 0, "by_severity": {}, "by_category": {}}),
            "summary": analysis.get("summary", ""),
            "plugin_summary": plugin_summary,
            "errors": errors,
            "severity_colors": SEVERITY_COLORS,
            "simple": simple_data,
            "urls": url_data,
        }

        output_paths = {}

        html_path = self.output_dir / f"memscout_report_{timestamp}.html"
        self._write_html(context, html_path)
        output_paths["html"] = str(html_path)

        json_path = self.output_dir / f"memscout_report_{timestamp}.json"
        self._write_json(context, json_path)
        output_paths["json"] = str(json_path)

        if HAS_WEASYPRINT:
            pdf_path = self.output_dir / f"memscout_report_{timestamp}.pdf"
            self._write_pdf(html_path, pdf_path)
            output_paths["pdf"] = str(pdf_path)

        print(f"\n[+] Reports generated:")
        for fmt, path in output_paths.items():
            print(f"    [{fmt.upper()}] {path}")

        return output_paths

    def _write_html(self, context: dict, path: Path):
        if HAS_JINJA2:
            env = Environment(autoescape=select_autoescape())
            template = env.from_string(HTML_TEMPLATE)
            html = template.render(**context)
        else:
            html = self._simple_html(context)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[*] HTML report: {path}")

    def _write_json(self, context: dict, path: Path):
        report = {
            "meta": context["meta"],
            "summary": context["summary"],
            "stats": context["stats"],
            "findings": context["findings"],
            "simple": context["simple"],
            "urls_summary": {
                "total_full_urls": context["urls"].get("total_full_urls", 0) if context["urls"] else 0,
                "total_bare_domains": context["urls"].get("total_bare_domains", 0) if context["urls"] else 0,
                "suspicious_count": len(context["urls"].get("suspicious_urls", [])) if context["urls"] else 0,
            },
            "plugins": context["plugin_summary"],
            "errors": context["errors"],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] JSON report: {path}")

    def _write_pdf(self, html_path: Path, pdf_path: Path):
        try:
            weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            print(f"[*] PDF report: {pdf_path}")
        except Exception as e:
            print(f"[!] PDF generation failed: {e}")

    def _simple_html(self, context: dict) -> str:
        findings_html = "".join(
            f'<div style="border-left:4px solid red;padding:10px;margin:8px 0;background:#1a1a2e">'
            f'<strong>[{f["severity"]}] {f["title"]}</strong><br>'
            f'<small>{f["category"]}</small><br>'
            f'<pre style="font-size:.85em">{f["detail"][:300]}</pre></div>'
            for f in context["findings"]
        )
        return (
            f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MemScout Report</title>'
            f'<style>body{{background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px}}</style>'
            f'</head><body>'
            f'<h1>MemScout Report — {context["meta"]["image_name"]}</h1>'
            f'<p>OS: {context["meta"]["os_type"]} | Duration: {context["meta"]["elapsed_seconds"]}s</p>'
            f'<p><strong>{context["summary"]}</strong></p>'
            f'<h2>Findings</h2>{findings_html or "<p>No findings.</p>"}'
            f'</body></html>'
        )
