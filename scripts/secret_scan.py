"""Pre-publication secret scan.

    python scripts/secret_scan.py          # report, exit 1 on any finding

Checks every file that would be published for credential-shaped names and for
credential-shaped content. The repository is public, so this runs before any
push and again in CI. It is deliberately noisy about near-misses: a finding is
reported for a human to clear, never auto-suppressed.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".cache", ".venv", "venv"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".docx", ".whl", ".pyc"}

#: Filenames that must never be published, matched case-insensitively.
FORBIDDEN_NAMES = (
    re.compile(r"^\.env($|\.)", re.I),
    re.compile(r"\.(key|pem|p12|pfx|jks|keystore)$", re.I),
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$", re.I),
    re.compile(r"^(credentials|secrets?)(\.|$)", re.I),
    re.compile(r"\.netrc$|^\.npmrc$|^\.pypirc$", re.I),
)

#: Content patterns. Each is (label, regex, note).
CONTENT_PATTERNS = (
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub fine-grained PAT"),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "OpenAI-style API key"),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "Anthropic-style API key"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "JSON Web Token"),
    ("bearer_header", re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+\S{12,}"),
     "hard-coded bearer header"),
    ("assigned_secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token|client[_-]?secret)\b\s*[:=]\s*"
        r"['\"][^'\"\s]{8,}['\"]"), "assigned credential literal"),
    ("connection_string", re.compile(r"(?i)\b(postgres|mysql|mongodb(\+srv)?)://[^\s'\"]+:[^\s'\"]+@"),
     "connection string with inline password"),
)

#: Values the project legitimately contains: synthetic constants published by
#: the benchmark itself, and the project's own placeholder markers.
ALLOWLISTED_SUBSTRINGS = (
    "US133000000121212121212",   # AgentDojo banking injection-task attacker IBAN
    "GB29NWBK60161331926819",    # AgentDojo banking environment payee IBAN
    "DE89370400440532013000",    # synthetic IBAN used in the unit tests
    "new_password_12",           # synthetic injected password in a case file
    "www.secure-systems-252.com",
    "www.my-website-234.com/random",
    "PENDING",
)


def files_to_check() -> list[Path]:
    out = []
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file() or any(d in p.parts for d in SKIP_DIRS):
            continue
        out.append(p)
    return sorted(out)


def main() -> int:
    findings: list[tuple[str, str, str]] = []
    checked = 0
    for p in files_to_check():
        rel = p.relative_to(REPO_ROOT).as_posix()
        for rx in FORBIDDEN_NAMES:
            if rx.search(p.name):
                findings.append((rel, "filename", f"credential-shaped filename ({rx.pattern})"))
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        checked += 1
        for label, rx, note in CONTENT_PATTERNS:
            for m in rx.finditer(text):
                hit = m.group(0)
                if any(a in hit for a in ALLOWLISTED_SUBSTRINGS):
                    continue
                line = text[: m.start()].count("\n") + 1
                findings.append((f"{rel}:{line}", label, f"{note}: {hit[:40]}..."))

    print(f"secret scan: {len(files_to_check())} files present, {checked} text files inspected")
    print(f"patterns: {len(CONTENT_PATTERNS)} content, {len(FORBIDDEN_NAMES)} filename")
    if findings:
        print(f"\n{len(findings)} finding(s):")
        for where, label, note in findings:
            print(f"  [{label}] {where} - {note}")
        return 1
    print("no credential-shaped filenames or content found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
