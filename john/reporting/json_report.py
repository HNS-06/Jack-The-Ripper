"""JSON report generator."""

import json
from .report import ReportGenerator, ReportData


class JSONReportGenerator(ReportGenerator):
    def generate(self, data: ReportData, filename: str = None) -> str:
        filename = filename or self._default_filename("json")
        filepath = self.output_dir / filename
        report = {
            "report_type": "password_audit",
            "generated_at": data.timestamp,
            "session_id": data.session_id,
            "summary": {
                "hash_file": data.hash_file,
                "attack_mode": data.attack_mode,
                "format_detected": data.format_detected,
                "total_hashes": data.total_hashes,
                "candidates_tested": data.candidates_tested,
                "matches_found": data.matches_found,
                "recovery_rate": f"{data.recovery_rate:.1f}%",
                "elapsed_seconds": data.elapsed,
                "speed_hps": data.speed,
            },
            "matches": data.matches,
        }
        filepath.write_text(json.dumps(report, indent=2))
        return str(filepath)
