"""PDF report generator using Jinja2 + HTML to PDF conversion."""

from pathlib import Path
from datetime import datetime
from typing import Optional
from .report import ReportGenerator, ReportData


HTML_PDF_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Jack the Ripper - Audit Report</title>
<style>
@page { size: A4; margin: 2cm; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #333; line-height: 1.6; }
.header { text-align: center; padding: 30px 0; border-bottom: 3px solid #1a1a2e; margin-bottom: 30px; }
.header h1 { font-size: 28px; color: #1a1a2e; margin-bottom: 5px; }
.header p { color: #666; font-size: 14px; }
.warning { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 4px; margin-bottom: 25px; font-size: 13px; color: #856404; }
.section { margin-bottom: 25px; page-break-inside: avoid; }
.section h2 { font-size: 18px; color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 8px; margin-bottom: 15px; }
.metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.metric { padding: 10px; background: #f8f9fa; border-radius: 4px; }
.metric .label { font-size: 12px; color: #666; text-transform: uppercase; }
.metric .value { font-size: 20px; font-weight: bold; color: #1a1a2e; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }
th { background: #1a1a2e; color: white; font-size: 12px; text-transform: uppercase; }
td { font-size: 13px; }
.match { color: #dc3545; font-weight: bold; }
.footer { text-align: center; padding: 20px 0; border-top: 1px solid #dee2e6; margin-top: 30px; color: #999; font-size: 11px; }
.strength-bar { display: inline-block; height: 8px; border-radius: 4px; }
.strength-very_weak { background: #dc3545; }
.strength-weak { background: #fd7e14; }
.strength-moderate { background: #ffc107; }
.strength-strong { background: #28a745; }
.strength-very_strong { background: #007bff; }
</style>
</head>
<body>
<div class="header">
<h1>JACK THE RIPPER</h1>
<p>Password Audit Report</p>
<p>Generated: %s</p>
</div>
<div class="warning">
CONFIDENTIAL - This report contains sensitive security data. Handle according to your organization's security policy. Do not distribute outside authorized personnel.
</div>
<div class="section">
<h2>Executive Summary</h2>
<div class="metric-grid">
<div class="metric"><div class="label">Session ID</div><div class="value">%s</div></div>
<div class="metric"><div class="label">Hash File</div><div class="value">%s</div></div>
<div class="metric"><div class="label">Attack Mode</div><div class="value">%s</div></div>
<div class="metric"><div class="label">Format</div><div class="value">%s</div></div>
</div>
</div>
<div class="section">
<h2>Results</h2>
<div class="metric-grid">
<div class="metric"><div class="label">Total Hashes</div><div class="value">%d</div></div>
<div class="metric"><div class="label">Candidates Tested</div><div class="value">%d</div></div>
<div class="metric"><div class="label">Matches Found</div><div class="value">%d</div></div>
<div class="metric"><div class="label">Recovery Rate</div><div class="value">%.1f%%</div></div>
<div class="metric"><div class="label">Speed</div><div class="value">%.1f H/s</div></div>
<div class="metric"><div class="label">Elapsed</div><div class="value">%.2f seconds</div></div>
</div>
</div>
<div class="section">
<h2>Matches</h2>
%s
</div>
<div class="footer">
Jack the Ripper v2.0.0 - Offline Password Audit Framework<br>
This report was auto-generated and should be reviewed by qualified personnel.
</div>
</body>
</html>"""


class PDFReportGenerator(ReportGenerator):
    """Generates PDF-ready HTML reports (can be converted with wkhtmltopdf or similar)."""
    
    def generate(self, data: ReportData, filename: str = None) -> str:
        filename = filename or self._default_filename("html")
        filepath = self.output_dir / filename
        
        ts = datetime.fromtimestamp(data.timestamp).strftime('%Y-%m-%d %H:%M:%S') if data.timestamp else "N/A"
        
        # Build matches table
        mt = "<table><tr><th>#</th><th>Password</th><th>Hash</th><th>Format</th><th>Strategy</th></tr>"
        for i, m in enumerate(data.matches, 1):
            hv = m.get("hash_value", "N/A")
            if len(hv) > 30:
                hv = hv[:30] + "..."
            mt += f'<tr><td>{i}</td><td class="match">{m.get("candidate","")}</td><td>{hv}</td><td>{m.get("format_name","")}</td><td>{m.get("strategy","")}</td></tr>'
        mt += "</table>"
        if not data.matches:
            mt = "<p>No matches found.</p>"
        
        html = HTML_PDF_TEMPLATE % (
            ts, data.session_id, data.hash_file, data.attack_mode,
            data.format_detected, data.total_hashes, data.candidates_tested,
            data.matches_found, data.recovery_rate, data.speed, data.elapsed, mt
        )
        
        filepath.write_text(html)
        return str(filepath)
    
    def convert_to_pdf(self, html_path: str, pdf_path: str = None) -> Optional[str]:
        """Try to convert HTML to PDF using available tools."""
        html_file = Path(html_path)
        if not html_file.exists():
            return None
        
        if pdf_path is None:
            pdf_path = str(html_file.with_suffix('.pdf'))
        
        # Try wkhtmltopdf
        try:
            result = subprocess.run(
                ["wkhtmltopdf", "--quiet", str(html_file), pdf_path],
                capture_output=True, timeout=30
            )
            if result.returncode == 0:
                return pdf_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Try weasyprint
        try:
            from weasyprint import HTML
            HTML(filename=str(html_file)).write_pdf(pdf_path)
            return pdf_path
        except (ImportError, Exception):
            pass
        
        return None
