"""Authorization and scope controls."""

from pathlib import Path
import time

AUTHORIZATION_WARNING = """
┌─ AUTHORIZED AUDIT ONLY ─────────────────────────┐
│ This tool operates on offline hash datasets.     │
│ Use only with explicit authorization.            │
│ Unauthorized access to systems is illegal.       │
└──────────────────────────────────────────────────┘
"""


class AuthorizationManager:
    def __init__(self):
        self._authorized = False
        self._audit_log: list = []

    def check_authorization(self, target: str) -> bool:
        path = Path(target)
        if not path.exists():
            self._log("DENIED", f"File not found: {target}")
            return False
        if not path.is_file():
            self._log("DENIED", f"Not a regular file: {target}")
            return False
        restricted = [
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "C:\\Windows\\System32\\config\\SAM",
        ]
        resolved = str(path.resolve())
        for r in restricted:
            if resolved.lower().startswith(r.lower()):
                self._log("DENIED", f"Restricted file: {target}")
                return False
        self._log("AUTHORIZED", f"Target: {target}")
        self._authorized = True
        return True

    def require_authorization(self, target: str):
        if not self.check_authorization(target):
            raise PermissionError(
                "Authorization required. This tool operates on offline hash datasets only."
            )

    def _log(self, status: str, message: str):
        self._audit_log.append({"timestamp": time.time(), "status": status, "message": message})

    def get_audit_log(self) -> list:
        return self._audit_log.copy()
