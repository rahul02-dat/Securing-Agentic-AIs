"""
gateway/shared/safe_regex.py

ReDoS (Regular Expression Denial of Service) mitigation layer.

WHY THIS EXISTS
----------------
`prompt_injection_detector.py` and `link_input_handler.py` run dozens of
regexes directly over attacker-controlled input (page HTML, hidden DOM
content, user text). Several of the original patterns contain nested
quantifiers / alternations over `.*?` spans (e.g. triple-quote string
matching, `position:absolute.*?(left|right|top|bottom)`), which are
classic catastrophic-backtracking shapes under Python's stdlib `re`
(a backtracking NFA engine). A crafted input can drive stdlib `re` to
exponential-time evaluation and lock a worker thread indefinitely.

STRATEGY (in priority order)
-----------------------------
1. **google-re2** (`import re2`) - a linear-time, guaranteed-no-backtracking
   engine. This is the preferred backend. It does NOT support
   backreferences or lookaround assertions. We audited every pattern in
   `prompt_injection_detector.py` and `link_input_handler.py`: none use
   backreferences or lookaround, so all of them compile under re2
   unmodified.
2. **regex** (mrab-regex, `import regex`) - used only if re2 is not
   installed, or if a specific pattern fails to compile under re2 (e.g. a
   future pattern that needs a lookaround). The `regex` module supports a
   native `timeout=` keyword on `search`/`match`/`finditer`/`fullmatch`,
   which aborts evaluation after N seconds *without* relying on
   `signal.alarm` (which only works on the main thread and would break the
   ThreadPoolExecutor-based parallel analysis in main.py). This gives us
   bounded execution time even for backtracking-capable patterns.
3. **stdlib re** - last-resort fallback only if neither of the above is
   installed. This path has NO catastrophic-backtracking protection beyond
   the input-length caps below, and is logged as a degraded security
   posture the first time it is used.

Regardless of backend, every entry point in this module truncates its
input to MAX_REGEX_INPUT_LENGTH *before* any regex is evaluated
(Objective 3: bounded string length ahead of regex evaluation). This
bounds worst-case work even in the stdlib-re fallback path, and prevents
memory/CPU blowups from megabyte-scale hidden payloads.
"""

import functools
import logging
import threading

logger = logging.getLogger("promptwall.safe_regex")
_warned_degraded = False
_warn_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
try:
    import re2 as _re2_backend
    _HAVE_RE2 = True
except ImportError:
    _re2_backend = None
    _HAVE_RE2 = False

try:
    import regex as _regex_backend
    _HAVE_REGEX = True
except ImportError:
    _regex_backend = None
    _HAVE_REGEX = False

import re as _stdlib_re  # always available; used for .escape() and as final fallback

# Objective 3: hard cap on input length evaluated by any regex in this module.
# Chosen generously above realistic page/element sizes while still bounding
# worst-case work; override via configure_limits() if a caller needs more.
MAX_REGEX_INPUT_LENGTH = 200_000

# Only meaningful for the `regex` backend's native timeout support.
DEFAULT_TIMEOUT_SECONDS = 2.0

# Flags: re2, regex, and stdlib re all define IGNORECASE/DOTALL/MULTILINE
# with the same integer values (they mirror stdlib re's flag module), so we
# can safely expose one canonical set of flag constants regardless of which
# backend ends up handling a given call.
IGNORECASE = _stdlib_re.IGNORECASE
DOTALL = _stdlib_re.DOTALL
MULTILINE = _stdlib_re.MULTILINE

# re.escape() only escapes literal characters for safe embedding in a
# pattern - it does not evaluate an untrusted pattern, so it carries no
# ReDoS risk and stdlib is fine here regardless of backend.
escape = _stdlib_re.escape


def configure_limits(max_input_length=None, timeout_seconds=None):
    """Allow callers (e.g. config-driven startup) to tune the caps above."""
    global MAX_REGEX_INPUT_LENGTH, DEFAULT_TIMEOUT_SECONDS
    if max_input_length is not None:
        MAX_REGEX_INPUT_LENGTH = max_input_length
    if timeout_seconds is not None:
        DEFAULT_TIMEOUT_SECONDS = timeout_seconds


def bounded_text(text, max_len=None):
    """Objective 3: truncate text before ANY regex touches it."""
    if text is None:
        return ""
    limit = max_len if max_len is not None else MAX_REGEX_INPUT_LENGTH
    if len(text) > limit:
        logger.warning(
            "safe_regex: input truncated from %d to %d chars before regex evaluation",
            len(text), limit
        )
        return text[:limit]
    return text


def _warn_degraded_once():
    global _warned_degraded
    with _warn_lock:
        if not _warned_degraded:
            logger.warning(
                "safe_regex: neither google-re2 nor the 'regex' package is installed; "
                "falling back to stdlib 're' with NO catastrophic-backtracking protection "
                "beyond input-length truncation. Install 'google-re2' (preferred) or "
                "'regex' to restore full ReDoS mitigation."
            )
            _warned_degraded = True


@functools.lru_cache(maxsize=512)
def _compile_re2(pattern, flags):
    prefix = ""
    if flags & _stdlib_re.IGNORECASE:
        prefix += "i"
    if flags & _stdlib_re.MULTILINE:
        prefix += "m"
    if flags & _stdlib_re.DOTALL:
        prefix += "s"
    if prefix:
        pattern = f"(?{prefix}){pattern}"
    return _re2_backend.compile(pattern)


@functools.lru_cache(maxsize=512)
def _compile_regex(pattern, flags):
    return _regex_backend.compile(pattern, flags)


@functools.lru_cache(maxsize=512)
def _compile_stdlib(pattern, flags):
    return _stdlib_re.compile(pattern, flags)


def _get_compiled(pattern, flags):
    """
    Return (compiled_pattern, backend_name) trying re2 first, then regex,
    then stdlib re. A pattern that re2 can't compile (e.g. it uses a
    lookaround/backreference we didn't anticipate) transparently falls
    through to the next backend instead of crashing the caller.
    """
    if _HAVE_RE2:
        try:
            return _compile_re2(pattern, flags), "re2"
        except _re2_backend.error:
            logger.info(
                "safe_regex: pattern not re2-compatible, falling back: %s", pattern[:80]
            )
    if _HAVE_REGEX:
        try:
            return _compile_regex(pattern, flags), "regex"
        except _regex_backend.error:
            logger.warning(
                "safe_regex: pattern failed to compile under 'regex' backend too: %s",
                pattern[:80]
            )
    _warn_degraded_once()
    return _compile_stdlib(pattern, flags), "re"


def finditer(pattern, text, flags=0, max_len=None, timeout=None):
    """Drop-in, ReDoS-bounded replacement for re.finditer -> returns a list."""
    text = bounded_text(text, max_len)
    compiled, backend = _get_compiled(pattern, flags)
    to = timeout if timeout is not None else DEFAULT_TIMEOUT_SECONDS
    if backend == "regex":
        try:
            return list(compiled.finditer(text, timeout=to))
        except TimeoutError:
            logger.warning("safe_regex: finditer timed out (%ss) for pattern: %s", to, pattern[:80])
            return []
    return list(compiled.finditer(text))


def search(pattern, text, flags=0, max_len=None, timeout=None):
    """Drop-in, ReDoS-bounded replacement for re.search."""
    text = bounded_text(text, max_len)
    compiled, backend = _get_compiled(pattern, flags)
    to = timeout if timeout is not None else DEFAULT_TIMEOUT_SECONDS
    if backend == "regex":
        try:
            return compiled.search(text, timeout=to)
        except TimeoutError:
            logger.warning("safe_regex: search timed out (%ss) for pattern: %s", to, pattern[:80])
            return None
    return compiled.search(text)


def match(pattern, text, flags=0, max_len=None, timeout=None):
    """Drop-in, ReDoS-bounded replacement for re.match."""
    text = bounded_text(text, max_len)
    compiled, backend = _get_compiled(pattern, flags)
    to = timeout if timeout is not None else DEFAULT_TIMEOUT_SECONDS
    if backend == "regex":
        try:
            return compiled.match(text, timeout=to)
        except TimeoutError:
            logger.warning("safe_regex: match timed out (%ss) for pattern: %s", to, pattern[:80])
            return None
    return compiled.match(text)


def sub(pattern, repl, text, flags=0, count=0, max_len=None, timeout=None):
    """
    Drop-in, ReDoS-bounded replacement for re.sub.

    Note: re2's `sub` does not accept a `timeout`; regex's does but only
    for the *matching* phase during substitution in recent versions. We
    still bound input length up front, which is the dominant protection
    for the sanitizer's fixed, non-catastrophic patterns.
    """
    text = bounded_text(text, max_len)
    compiled, backend = _get_compiled(pattern, flags)
    try:
        return compiled.sub(repl, text, count=count)
    except TimeoutError:
        logger.warning("safe_regex: sub timed out for pattern: %s", pattern[:80])
        return text


def active_backend():
    """Report which engine is actually in effect, for startup logging/diagnostics."""
    if _HAVE_RE2:
        return "re2"
    if _HAVE_REGEX:
        return "regex"
    return "re (degraded - no ReDoS protection)"