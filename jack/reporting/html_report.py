"""HTML report generator."""

from datetime import datetime
from .report import ReportGenerator, ReportData

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Jack the Ripper - Audit Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:#0a0a0a;color:#00ff41;padding:20px}
.container{max-width:900px;margin:0 auto}
.banner{text-align:center;padding:20px;border:1px solid #00ff41;margin-bottom:20px}
.banner h1{font-size:1.5em;color:#00ff41}
.banner p{color:#00aa2a}
.section{border:1px solid #00ff41;margin-bottom:20px;padding:15px}
.section h2{color:#00ff41;border-bottom:1px solid #00ff41;padding-bottom:5px;margin-bottom:10px}
.metric{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px dotted #003300}
.metric .label{color:#00aa2a}
.metric .value{color:#00ff41;font-weight:bold}
table{width:100%%;border-collapse:collapse}
th,td{padding:8px;text-align:left;border-bottom:1px solid #003300}
th{color:#00ff41;background:#001a00}
td{color:#00cc33}
.match{color:#ff4444;font-weight:bold}
.footer{text-align:center;color:#005500;padding:20px}
.warning{color:#ffaa00;border:1px solid #ffaa00;padding:10px;margin-bottom:20px}
</style>
</head>
<body>
<div class="container">
<div class="banner">
<h1>JACK THE RIPPER</h1>
<p>Offline Password Audit Report</p>
<p>Generated: %s</p>
</div>
<div class="warning">
AUTHORIZED AUDIT ONLY - This report contains sensitive security data.
</div>
<div class="section">
<h2>EXECUTIVE SUMMARY</h2>
<div class="metric"><span class="label">Session ID</span><span class="value">%s</span></div>
<div class="metric"><span class="label">Hash File</span><span class="value">%s</span></div>
<div class="metric"><span class="label">Attack Mode</span><span class="value">%s</span></div>
<div class="metric"><span class="label">Format</span><span class="value">%s</span></div>
</div>
<div class="section">
<h2>RESULTS</h2>
<div class="metric"><span class="label">Total Hashes</span><span class="value">%d</span></div>
<div class="metric"><span class="label">Candidates Tested</span><span class="value">%d</span></div>
<div class="metric"><span class="label">Matches Found</span><span class="value">%d</span></div>
<div class="metric"><span class="label">Recovery Rate</span><span class="value">%.1f%%</span></div>
<div class="metric"><span class="label">Speed</span><span class="value">%.1f H/s</span></div>
<div class="metric"><span class="label">Elapsed</span><span class="value">%.2f seconds</span></div>
</div>
<div class="section">
<h2>MATCHES</h2>
%s
</div>
<div class="footer">Jack the Ripper v2.0.0</div>
</div>
</body>
</html>"""


class HTMLReportGenerator(ReportGenerator):
    def generate(self, data: ReportData, filename: str = None) -> str:
        filename = filename or self._default_filename("html")
        filepath = self.output_dir / filename
        ts = datetime.fromtimestamp(data.timestamp).strftime('%Y-%m-%d %H:%M:%S') if data.timestamp else "N/A"
        mt = "<table>\n<tr><th>#</th><th>Password</th><th>Hash</th><th>Format</th><th>Strategy</th></tr>\n"
        for i, m in enumerate(data.matches, 1):
            hv = m.get("hash_value", "N/A")
            if len(hv) > 30:
                hv = hv[:30] + "..."
            mt += f'<tr><td>{i}</td><td class="match">{m.get("candidate","")}</td><td>{hv}</td><td>{m.get("format_name","")}</td><td>{m.get("strategy","")}</td></tr>\n'
        mt += "</table>"
        if not data.matches:
            mt = "<p>No matches found.</p>"
        html = HTML_TEMPLATE % (ts, data.session_id, data.hash_file, data.attack_mode,
            data.format_detected, data.total_hashes, data.candidates_tested,
            data.matches_found, data.recovery_rate, data.speed, data.elapsed, mt)
        filepath.write_text(html)
        return str(filepath)
