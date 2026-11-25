"""Deterministic value matching for Rules A and B.

Rule A and Rule B both reduce to the question *does this value occur in that
text?*  The review (§2.6 item 1, checklist B1) requires the matching
procedure to be stated rather than left to implementation.  CAGE adopts the
reference procedure of ROPE [5]: **whole-value matching with explicit
token-boundary handling** — a value ``v`` occurs in text ``c`` only if the
characters surrounding the occurrence do not extend it.  Hence ``evil.com``
does not match inside ``notevil.com`` or inside ``evil.com.br``.

No fuzzy, semantic or embedding matching is used anywhere in the guard: the
decision function is a pure, deterministic function of the call arguments,
the call history and the policy.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

#: Characters that continue a token on their own: alphanumerics plus the
#: characters that occur *inside* the value types CAGE treats as sensitive
#: (emails, handles, paths).
CORE_CHARS = frozenset(string.ascii_letters + string.digits + "_@%+/")

#: Characters that continue a token only when themselves followed (or
#: preceded) by a core character.  A trailing full stop at the end of a
#: sentence does not extend an IBAN, but ``.br`` extends ``evil.com``.
SOFT_CHARS = frozenset(".-")

#: Retained for callers that inspect the character classes directly.
EXTENDING_CHARS = CORE_CHARS | SOFT_CHARS

#: Values shorter than this are never whole-value matched: a two-character
#: token matches too much text to be evidence of anything.
MIN_VALUE_LEN = 3

_WS = re.compile(r"\s+")

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Za-z0-9]{2,4}){2,7}\b")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,}\d(?![\w.])")

#: Imperative / instruction-like phrasings used by the Rule C heuristic.  This
#: list is a declared coverage heuristic, not a detector: its false denials
#: are measured and reported per case, and adaptive phrasings evade it by
#: construction (see Rule C in rules.py).
INSTRUCTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("override_prior", r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"),
    ("new_instruction", r"\b(new|updated|revised)\s+(instruction|instructions|task|directive)s?\b"),
    ("imperative_send", r"\b(send|forward|post|transfer|pay|wire|email)\b[^.\n]{0,30}\b(to|into)\b"),
    ("urgency", r"\b(urgent(ly)?|immediately|right now|as soon as possible)\b"),
    ("role_claim", r"\b(you are|act as|as an? (admin|administrator|assistant|agent))\b"),
    ("secrecy", r"\b(do not (tell|inform|mention)|without (telling|informing|asking)|silently)\b"),
)


def canonical(value: Any) -> str:
    """Lower-case, whitespace-trimmed form used for all comparisons.

    Lower-casing is index preserving, so occurrence offsets computed on the
    canonical form are valid offsets into the canonical text.
    """
    return str(value).strip().lower()


def collapse_spaces(text: str) -> str:
    """Remove internal whitespace (IBANs and card numbers are written both ways)."""
    return _WS.sub("", text)


def extends_right(text: str, end: int) -> bool:
    """True when the characters after ``end`` continue the matched token."""
    i = end
    while i < len(text) and text[i] in SOFT_CHARS:
        i += 1
    if i == end:
        return i < len(text) and text[i] in CORE_CHARS
    return i < len(text) and text[i] in CORE_CHARS


def extends_left(text: str, start: int) -> bool:
    """True when the characters before ``start`` continue the matched token."""
    i = start - 1
    while i >= 0 and text[i] in SOFT_CHARS:
        i -= 1
    return i >= 0 and text[i] in CORE_CHARS


def is_whole_value(text: str, start: int, end: int) -> bool:
    """Token-boundary test applied to one candidate occurrence."""
    return not extends_left(text, start) and not extends_right(text, end)


def find_occurrences(value: Any, text: Any, min_len: int = MIN_VALUE_LEN) -> list[tuple[int, int]]:
    """Return ``(start, end)`` offsets of whole-value occurrences of ``value``.

    An occurrence is reported only when the surrounding characters do not
    extend it: ``evil.com`` does not match inside ``notevil.com`` or
    ``evil.com.br``, while a sentence-final full stop or a bracket is not
    treated as an extension.
    """
    v, t = canonical(value), canonical(text)
    if len(v) < min_len or not t:
        return []
    out: list[tuple[int, int]] = []
    start = 0
    while True:
        i = t.find(v, start)
        if i < 0:
            return out
        end = i + len(v)
        if is_whole_value(t, i, end):
            out.append((i, end))
        start = i + 1


def _spaced_occurrence(value: str, text: str) -> bool:
    """Match ``value`` against ``text`` tolerating whitespace between characters.

    Account identifiers are written both grouped and ungrouped
    (``DE89 3704 ...`` and ``DE89370400...``).  Collapsing the whitespace out
    of the *text* would destroy the token boundary the match depends on, so
    the tolerance is expressed in the pattern instead and the boundary is
    still evaluated against the real surrounding characters.
    """
    pattern = r"\s*".join(re.escape(ch) for ch in value)
    return any(is_whole_value(text, m.start(), m.end()) for m in re.finditer(pattern, text))


def whole_value_match(value: Any, text: Any, min_len: int = MIN_VALUE_LEN) -> bool:
    """True when ``value`` occurs in ``text`` as a whole value.

    Tried three ways, all boundary-checked: the literal canonical forms; the
    space-collapsed value against the literal text (``DE89 3704 ...`` written
    as one token in the text); and the space-collapsed value as a
    whitespace-tolerant pattern over the literal text (the reverse case).
    """
    if find_occurrences(value, text, min_len=min_len):
        return True
    cv = collapse_spaces(canonical(value))
    ct = canonical(text)
    if len(cv) < min_len or not ct:
        return False
    if find_occurrences(cv, ct, min_len=min_len):
        return True
    return _spaced_occurrence(cv, ct)


def match_any(value: Any, texts: Iterable[Any], min_len: int = MIN_VALUE_LEN) -> bool:
    """True when ``value`` whole-value matches at least one of ``texts``."""
    return any(whole_value_match(value, t, min_len=min_len) for t in texts)


def to_amount(value: Any) -> Decimal | None:
    """Parse a monetary amount, tolerating currency symbols and separators."""
    s = re.sub(r"[^\d.,\-]", "", str(value)).strip()
    if not s:
        return None
    if "," in s and "." in s:
        s = s.replace(",", "") if s.rfind(".") > s.rfind(",") else s.replace(".", "").replace(",", ".")
    elif s.count(",") == 1 and len(s.split(",")[-1]) in (1, 2):
        s = s.replace(",", ".")
    else:
        s = s.replace(",", "")
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


def amounts_equal(a: Any, b: Any, tolerance: str | float = "0.01") -> bool:
    """Numeric equality for payment amounts, within ``tolerance``."""
    da, db = to_amount(a), to_amount(b)
    if da is None or db is None:
        return False
    return abs(da - db) <= Decimal(str(tolerance))


def amount_in_text(value: Any, text: Any, tolerance: str | float = "0.01") -> bool:
    """True when a numerically equal amount appears anywhere in ``text``."""
    target = to_amount(value)
    if target is None:
        return False
    for token in re.findall(r"[-+]?\d[\d.,]*", str(text)):
        cand = to_amount(token)
        if cand is not None and abs(cand - target) <= Decimal(str(tolerance)):
            return True
    return False


def extract_artifacts(text: Any) -> list[tuple[str, str]]:
    """Extract ``(kind, value)`` links, addresses and account identifiers.

    Used by Rule C to enumerate the checkable items in an outgoing message
    body.  Free prose is deliberately *not* decomposed: the instruction-like
    heuristic handles it separately and its limits are reported.
    """
    s = str(text or "")
    found: list[tuple[str, str]] = []
    seen = set()
    for kind, rx in (("url", URL_RE), ("email", EMAIL_RE), ("iban", IBAN_RE), ("phone", PHONE_RE)):
        for m in rx.finditer(s):
            v = m.group(0).rstrip(".,;:)")
            key = (kind, canonical(v))
            if key not in seen:
                seen.add(key)
                found.append((kind, v))
    return found


def instruction_like(text: Any) -> list[str]:
    """Return the names of instruction-like patterns present in ``text``."""
    s = canonical(text)
    return [name for name, rx in INSTRUCTION_PATTERNS if re.search(rx, s, re.IGNORECASE)]


def collect_strings(value: Any, _depth: int = 0) -> list[str]:
    """Flatten a tool-call argument structure into its string leaves."""
    if _depth > 6:
        return []
    if value is None or isinstance(value, bool):
        return []
    if isinstance(value, (str, int, float, Decimal)):
        return [str(value)]
    if isinstance(value, dict):
        out: list[str] = []
        for k, v in value.items():
            out.extend(collect_strings(k, _depth + 1))
            out.extend(collect_strings(v, _depth + 1))
        return out
    if isinstance(value, Sequence):
        out = []
        for v in value:
            out.extend(collect_strings(v, _depth + 1))
        return out
    return [str(value)]
