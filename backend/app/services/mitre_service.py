"""
MitreService – maps attack event signatures to MITRE ATT&CK techniques.

Supports mapping to:
  - T1110: Brute Force (Credential Access)
  - T1059: Command and Scripting Interpreter (Execution)
  - T1003: OS Credential Dumping (Credential Access)
  - T1046: Network Service Discovery (Discovery)
  - T1190: Exploit Public-Facing Application (Initial Access)
  - T1078: Valid Accounts (Defense Evasion)
"""
from __future__ import annotations

import re
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


# ── MITRE ATT&CK Technique Definitions ───────────────────────────────────────

TECHNIQUE_DEFINITIONS = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the operating system.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing application.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use credentials of existing accounts to gain access.",
    },
}


# ── Pattern Matchers ─────────────────────────────────────────────────────────

_CREDENTIAL_DUMP_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"/etc/shadow",
        r"/etc/passwd",
        r"mimikatz",
        r"hashdump",
        r"secretsdump",
        r"lsass",
        r"sam\s+dump",
    ]
]

_COMMAND_EXEC_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bbash\b",
        r"\bsh\b",
        r"\bzsh\b",
        r"\bpython\b",
        r"\bperl\b",
        r"\bruby\b",
        r"\bpowershell\b",
        r"\bcmd\.exe\b",
        r"base64\s+--decode",
        r"\bexec\b",
        r"\beval\b",
    ]
]

_NETWORK_SCAN_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bnmap\b",
        r"\bnetstat\b",
        r"\bss\s+-",
        r"\bnetcat\b",
        r"\bnc\s+-",
        r"port\s*scan",
        r"\btraceroute\b",
    ]
]

_EXPLOIT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\.\.\/",           # path traversal
        r"<script",          # XSS
        r"union\s+select",   # SQL injection
        r"exec\s*\(",        # code injection
        r"\bwget\b",
        r"\bcurl\b.*\|.*\bsh\b",
    ]
]

# Common default / well-known usernames → T1078 Valid Accounts
_VALID_ACCOUNTS_USERNAMES = {
    "root", "admin", "administrator", "test", "guest",
    "oracle", "postgres", "mysql", "ftp", "www-data",
}


class MitreService:
    """Maps attack event fields to MITRE ATT&CK techniques."""

    def map_event(self, event_dict: dict) -> list[dict]:
        """
        Analyse an event dict and return a list of matched techniques.

        Each result dict contains:
          - technique_id: e.g. "T1110"
          - technique_name: human-readable name
          - tactic: MITRE tactic category
          - confidence: 0-100 match confidence
        """
        matches: list[dict] = []
        command  = (event_dict.get("command") or "").strip()
        username = (event_dict.get("username") or "").strip()
        password = (event_dict.get("password") or "").strip()
        service  = (event_dict.get("service") or "").upper()
        endpoint = (event_dict.get("endpoint") or "").strip()
        payload  = (event_dict.get("payload") or "").strip()
        combined = f"{command} {endpoint} {payload}"

        # ── T1110: Brute Force ───────────────────────────────────────────
        if username and password:
            confidence = 70
            if service in ("SSH", "FTP", "TELNET", "RDP"):
                confidence = 90
            matches.append(self._build_match("T1110", confidence))

        # ── T1003: OS Credential Dumping ─────────────────────────────────
        if any(pat.search(combined) for pat in _CREDENTIAL_DUMP_PATTERNS):
            matches.append(self._build_match("T1003", 85))

        # ── T1059: Command and Scripting Interpreter ─────────────────────
        if any(pat.search(combined) for pat in _COMMAND_EXEC_PATTERNS):
            matches.append(self._build_match("T1059", 80))

        # ── T1046: Network Service Discovery ─────────────────────────────
        if any(pat.search(combined) for pat in _NETWORK_SCAN_PATTERNS):
            matches.append(self._build_match("T1046", 75))

        # ── T1190: Exploit Public-Facing Application ─────────────────────
        if service == "HTTP" and any(pat.search(combined) for pat in _EXPLOIT_PATTERNS):
            matches.append(self._build_match("T1190", 80))

        # ── T1078: Valid Accounts ────────────────────────────────────────
        if username.lower() in _VALID_ACCOUNTS_USERNAMES:
            matches.append(self._build_match("T1078", 60))

        if matches:
            technique_ids = [m["technique_id"] for m in matches]
            logger.debug("MITRE mapping: event matched %s", technique_ids)

        return matches

    @staticmethod
    def _build_match(technique_id: str, confidence: int) -> dict:
        """Build a technique match result dict."""
        defn = TECHNIQUE_DEFINITIONS[technique_id]
        return {
            "technique_id":   technique_id,
            "technique_name": defn["name"],
            "tactic":         defn["tactic"],
            "confidence":     confidence,
        }

    @staticmethod
    def get_all_techniques() -> dict:
        """Return all known technique definitions."""
        return TECHNIQUE_DEFINITIONS
