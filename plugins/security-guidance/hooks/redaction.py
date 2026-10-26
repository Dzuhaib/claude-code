"""Redact high-confidence credentials before text leaves the local machine."""

import re

PATTERNS = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "SENDGRID_KEY",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    ),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]


def redact_text(text):
    if not isinstance(text, str) or not text:
        return text
    for name, pattern in PATTERNS:
        text = pattern.sub(f"[REDACTED:{name}]", text)
    return text


def redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value
