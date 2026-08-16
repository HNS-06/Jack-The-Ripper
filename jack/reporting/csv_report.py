"""CSV report generator."""

import csv
from .report import ReportGenerator, ReportData


class CSVReportGenerator(ReportGenerator):
    def generate(self, data: ReportData, filename: str = None) -> str:
        filename = filename or self._default_filename("csv")
        filepath = self.output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["SUMMARY"])
            writer.writerow(["Session ID", data.session_id])
            writer.writerow(["Hash File", data.hash_file])
            writer.writerow(["Attack Mode", data.attack_mode])
            writer.writerow(["Format", data.format_detected])
            writer.writerow(["Total Hashes", data.total_hashes])
            writer.writerow(["Candidates Tested", data.candidates_tested])
            writer.writerow(["Matches Found", data.matches_found])
            writer.writerow(["Recovery Rate", f"{data.recovery_rate:.1f}%"])
            writer.writerow(["Elapsed (s)", f"{data.elapsed:.2f}"])
            writer.writerow(["Speed (H/s)", f"{data.speed:.1f}"])
            writer.writerow([])
            writer.writerow(["MATCHES"])
            if data.matches:
                headers = list(data.matches[0].keys())
                writer.writerow(headers)
                for match in data.matches:
                    writer.writerow([match.get(h, "") for h in headers])
        return str(filepath)
