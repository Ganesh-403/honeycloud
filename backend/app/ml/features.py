"""
Feature extraction pipeline for ML threat detection.
Converts raw event dicts into a fixed-width numeric feature vector.
"""
from __future__ import annotations

import re
from typing import Optional

import numpy as np
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# ── Constants ─────────────────────────────────────────────────────────────────

SERVICE_PORT_MAP: dict[str, int] = {"SSH": 22, "FTP": 21, "HTTP": 80, "TELNET": 23, "SMTP": 25, "RDP": 3389, "EXTERNAL": 0}

DANGEROUS_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\brm\s+-rf\b",
        r"\bwget\b|\bcurl\b",
        r"/etc/passwd",
        r"/etc/shadow",
        r"\bnc\b|\bnetcat\b",
        r"\bchmod\b|\bchown\b",
        r"\bpython\b|\bperl\b|\bruby\b",
        r"\bbash\b|\bsh\b|\bzsh\b",
        r">\s*/dev/null",
        r"base64\s+--decode",
    ]
]

FEATURE_NAMES = [
    "service_port",
    "username_len",
    "password_len",
    "command_len",
    "source_port",
    "hour_of_day",
    "dangerous_pattern_count",
    "is_root_user",
    "is_anonymous_user",
    "has_command",
    "abuse_score",
    "total_reports",
    "is_whitelisted",
]

NUM_FEATURES = len(FEATURE_NAMES)

# Command tokenization constants
MAX_COMMAND_SEQUENCE_LENGTH = 50
MAX_VOCAB_SIZE = 1000

_tokenizer: Optional[Tokenizer] = None

def get_tokenizer() -> Tokenizer:
    global _tokenizer
    if _tokenizer is None:
        _tokenizer = Tokenizer(num_words=MAX_VOCAB_SIZE, oov_token="<unk>")
    return _tokenizer

def fit_tokenizer(commands: list[str]):
    tokenizer = get_tokenizer()
    tokenizer.fit_on_texts(commands)



# ── Public API ────────────────────────────────────────────────────────────────

def extract(event: dict) -> tuple[np.ndarray, np.ndarray]:
    """
    Extracts numerical features and tokenized command sequence from an event dict.
    Returns a tuple: (numerical_features, command_sequence).
    """

    """
    Extract a (1, NUM_FEATURES) float32 array from an event dict.

    All inputs are optional – missing/None values default to 0.
    """
    service    = (event.get("service") or "").upper()
    username   = event.get("username") or ""
    password   = event.get("password") or ""
    command    = event.get("command") or ""
    src_port   = event.get("source_port") or 0
    timestamp  = event.get("timestamp")

    hour = _extract_hour(timestamp)
    danger_count = sum(1 for pat in DANGEROUS_PATTERNS if pat.search(command))

    # Extract nested geo/abuse data if available
    geo = event.get("geolocation") or {}
    abuse_score = geo.get("abuse_score") or 0
    total_reports = geo.get("total_reports") or 0
    is_whitelisted = int(geo.get("is_whitelisted") or False)

    features = [
        SERVICE_PORT_MAP.get(service, 0),   # service_port
        len(username),                       # username_len
        len(password),                       # password_len
        len(command),                        # command_len
        src_port,                            # source_port
        hour,                                # hour_of_day
        danger_count,                        # dangerous_pattern_count
        int(username.lower() in ("root", "admin", "administrator")),
        int(username.lower() in ("anonymous", "guest", "visitor", "")),
        int(bool(command)),                  # has_command
        abuse_score,                         # abuse_score (from AbuseIPDB)
        total_reports,                       # total_reports (from AbuseIPDB)
        is_whitelisted,                      # is_whitelisted (from AbuseIPDB)
    ]

    numerical_features = np.array(features, dtype=np.float32).reshape(1, -1)

    # Tokenize and pad command
    tokenizer = get_tokenizer()
    command_sequence = tokenizer.texts_to_sequences([command])
    padded_command_sequence = pad_sequences(command_sequence, maxlen=MAX_COMMAND_SEQUENCE_LENGTH, padding=\'post\', truncating=\'post\')

    return numerical_features, padded_command_sequence


def _extract_hour(timestamp) -> int:
    """Best-effort extraction of hour-of-day from various timestamp types."""
    if timestamp is None:
        return 12
    if hasattr(timestamp, "hour"):
        return timestamp.hour
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(str(timestamp))
        return dt.hour
    except Exception:
        return 12
