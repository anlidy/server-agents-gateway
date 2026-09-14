"""
Secret redaction for audit logs and user-visible summaries.
Keeps zero third-party dependencies.
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple

# (pattern, replacement) — applied in order
_REDACTION_RULES: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"), r"\1***"),
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1***"),
    (re.compile(r"(?i)(cf-access-client-secret\s*:\s*)\S+"), r"\1***"),
    (re.compile(r"(?i)(cf-access-client-id\s*:\s*)\S+"), r"\1***"),
    (re.compile(r"\bsag_[A-Za-z0-9_]+\b"), "***TOKEN***"),
    (re.compile(r"\bcfast_[A-Za-z0-9]+\b"), "***SECRET***"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]+\b"), "***PAT***"),
    (re.compile(r"\bsk-[A-Za-z0-9]{10,}\b"), "***API_KEY***"),
]


def redact_secrets(text: str) -> str:
    """Redact common credential patterns from a string."""
    if not text:
        return text
    out = text
    for pattern, repl in _REDACTION_RULES:
        out = pattern.sub(repl, out)
    return out


def redact_structure(value: Any) -> Any:
    """Recursively redact strings inside dict/list structures."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: redact_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_structure(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(v) for v in value)
    return value
