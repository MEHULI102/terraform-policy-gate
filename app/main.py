from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from urllib.parse import urlparse, unquote
from html import unescape
import re


app = FastAPI()


# ============================================================
# Configuration
# ============================================================

ALLOWED_HOSTS = {
    "cdn-itdr8us.example",
    "app-c5o95mc.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


# ============================================================
# Response helper
# ============================================================

def result(safe: bool, reason: str):
    return JSONResponse(
        content={
            "safe": safe,
            "reason": reason,
        },
        status_code=200,
    )


# ============================================================
# URL extraction
# ============================================================

def extract_html_urls(text: str):
    """
    Extract quoted src= and href= attribute values.
    """
    pattern = re.compile(
        r"""(?:src|href)\s*=\s*(["'])(.*?)\1""",
        re.IGNORECASE | re.DOTALL,
    )

    return [match.group(2) for match in pattern.finditer(text)]


def extract_markdown_urls(text: str):
    """
    Extract the target inside ](...).

    Supports:
        [text](https://example.com)
        [text](/local/path)
    """
    pattern = re.compile(
        r"""\]\(\s*(?:<([^>]+)>|([^)]+))\s*\)""",
        re.DOTALL,
    )

    urls = []

    for match in pattern.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        if value is not None:
            urls.append(value.strip())

    return urls


# ============================================================
# Dangerous scheme detection
# ============================================================

def has_dangerous_scheme_text(text: str) -> bool:
    """
    Detect javascript:, data:, vbscript:
    with optional whitespace before colon.
    """

    return re.search(
        r"(?:javascript|data|vbscript)\s*:",
        text,
        re.IGNORECASE,
    ) is not None


def parse_url_scheme(url: str):
    """
    Return parsed scheme.

    Protocol-relative URLs are treated as HTTPS.
    """
    url = url.strip()

    if url.startswith("//"):
        return "https", url[2:]

    parsed = urlparse(url)

    return parsed.scheme.lower(), url


def has_invalid_url_scheme(urls) -> bool:
    """
    Any extracted URL using a scheme other than
    http/https is dangerous.

    Relative references are allowed.
    Protocol-relative references count as HTTPS.
    """

    for url in urls:
        url = url.strip()

        if not url:
            continue

        if has_dangerous_scheme_text(url):
            return True

        scheme, _ = parse_url_scheme(url)

        # Relative reference
        if scheme == "":
            continue

        if scheme not in {"http", "https"}:
            return True

    return False


# ============================================================
# External exfiltration
# ============================================================

def is_external_absolute_url(url: str) -> bool:
    """
    Check whether an absolute URL goes to a host that
    is NOT exactly in the allowlist.
    """

    url = url.strip()

    if not url:
        return False

    # Protocol-relative URL is absolute and resolved as HTTPS.
    if url.startswith("//"):
        parsed = urlparse("https:" + url)
    else:
        parsed = urlparse(url)

    # Only absolute HTTP/HTTPS URLs are checked here.
    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    hostname = parsed.hostname

    if hostname is None:
        return False

    hostname = hostname.lower().rstrip(".")

    # EXACT hostname matching.
    return hostname not in ALLOWED_HOSTS


def has_external_exfil(urls) -> bool:
    for url in urls:
        if is_external_absolute_url(url):
            return True

    return False


# ============================================================
# HTML checks
# ============================================================

def html_reason(text: str):
    """
    HTML order:

    SCRIPT_TAG
    EVENT_HANDLER
    DANGEROUS_SCHEME
    EXTERNAL_EXFIL
    """

    # --------------------------------------------------------
    # 1. SCRIPT_TAG
    # Opening script / iframe / object / embed tags.
    # --------------------------------------------------------

    script_pattern = re.compile(
        r"<\s*(?:script|iframe|object|embed)\b",
        re.IGNORECASE,
    )

    if script_pattern.search(text):
        return "SCRIPT_TAG"

    # --------------------------------------------------------
    # 2. EVENT_HANDLER
    # Any on...= attribute.
    # Examples:
    # onclick=
    # onload=
    # onerror=
    # --------------------------------------------------------

    event_pattern = re.compile(
        r"\bon[a-zA-Z0-9_-]*\s*=",
        re.IGNORECASE,
    )

    if event_pattern.search(text):
        return "EVENT_HANDLER"

    # --------------------------------------------------------
    # 3. DANGEROUS_SCHEME
    # --------------------------------------------------------

    if has_dangerous_scheme_text(text):
        return "DANGEROUS_SCHEME"

    urls = extract_html_urls(text)

    if has_invalid_url_scheme(urls):
        return "DANGEROUS_SCHEME"

    # --------------------------------------------------------
    # 4. EXTERNAL_EXFIL
    # --------------------------------------------------------

    if has_external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# Markdown checks
# ============================================================

def markdown_reason(text: str):

    # --------------------------------------------------------
    # 1. DANGEROUS_SCHEME
    # --------------------------------------------------------

    if has_dangerous_scheme_text(text):
        return "DANGEROUS_SCHEME"

    urls = extract_markdown_urls(text)

    if has_invalid_url_scheme(urls):
        return "DANGEROUS_SCHEME"

    # --------------------------------------------------------
    # 2. EXTERNAL_EXFIL
    # --------------------------------------------------------

    if has_external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# URL checks
# ============================================================

def url_reason(text: str):

    trimmed = text.strip()

    if has_dangerous_scheme_text(trimmed):
        return "DANGEROUS_SCHEME"

    # Whole output is the URL.
    if has_invalid_url_scheme([trimmed]):
        return "DANGEROUS_SCHEME"

    if has_external_exfil([trimmed]):
        return "EXTERNAL_EXFIL"

    return None


# ============================================================
# SQL checks
# ============================================================

def sql_reason(text: str):

    # Single quote
    if "'" in text:
        return "SQL_METACHAR"

    # Double quote
    if '"' in text:
        return "SQL_METACHAR"

    # Semicolon
    if ";" in text:
        return "SQL_METACHAR"

    # SQL comment
    if "--" in text:
        return "SQL_METACHAR"

    if "/*" in text:
        return "SQL_METACHAR"

    # UNION as a word
    if re.search(r"\bunion\b", text, re.IGNORECASE):
        return "SQL_METACHAR"

    # OR 1=1
    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        text,
        re.IGNORECASE,
    ):
        return "SQL_METACHAR"

    return None


# ============================================================
# Shell checks
# ============================================================

def shell_reason(text: str):

    # ; & | ` < >
    if any(char in text for char in [";", "&", "|", "`", "<", ">"]):
        return "SHELL_METACHAR"

    # $(
    if "$(" in text:
        return "SHELL_METACHAR"

    # ${
    if "${" in text:
        return "SHELL_METACHAR"

    return None


# ============================================================
# Channel dispatcher
# ============================================================

def channel_reason(channel: str, text: str):

    if channel == "html":
        return html_reason(text)

    if channel == "markdown":
        return markdown_reason(text)

    if channel == "url":
        return url_reason(text)

    if channel == "sql":
        return sql_reason(text)

    if channel == "shell":
        return shell_reason(text)

    return None


# ============================================================
# Decode exactly once
# ============================================================

def decode_once(text: str) -> str:
    """
    Required order:

    1. Percent escapes
    2. HTML entities
    3. Literal \\uXXXX escapes

    Each transformation is performed once.
    """

    # 1. Percent escapes
    decoded = unquote(text)

    # 2. HTML entities
    decoded = unescape(decoded)

    # 3. Literal \uXXXX escapes
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        decoded,
    )

    return decoded


# ============================================================
# Main endpoint
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # --------------------------------------------------------
    # Read JSON safely
    # --------------------------------------------------------

    try:
        data = await request.json()
    except Exception:
        return result(False, "INVALID_SCHEMA")

    # --------------------------------------------------------
    # RULE 1 — INVALID_SCHEMA
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return result(False, "INVALID_SCHEMA")

    if "channel" not in data or "output" not in data:
        return result(False, "INVALID_SCHEMA")

    channel = data["channel"]
    output = data["output"]

    if channel not in VALID_CHANNELS:
        return result(False, "INVALID_SCHEMA")

    if not isinstance(output, str):
        return result(False, "INVALID_SCHEMA")

    if len(output) > 20000:
        return result(False, "INVALID_SCHEMA")

    # --------------------------------------------------------
    # RULE 2 — ENCODED_PAYLOAD
    #
    # Decode once.
    # If decoded differs and decoded content would trigger
    # the relevant channel rule, return ENCODED_PAYLOAD.
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = channel_reason(channel, decoded)

        if decoded_reason is not None:
            return result(False, "ENCODED_PAYLOAD")

    # --------------------------------------------------------
    # RULE 3 — Apply original-output channel rules
    # --------------------------------------------------------

    reason = channel_reason(channel, output)

    if reason is not None:
        return result(False, reason)

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    return result(True, "SAFE")