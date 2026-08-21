from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from urllib.parse import unquote, urlparse
import re

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-itdr8us.example",
    "app-c5o95mc.example",
}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def response(safe, reason):
    return JSONResponse(
        content={
            "safe": safe,
            "reason": reason
        },
        status_code=200
    )


# Decode exactly once:
# percent escapes -> selected HTML entities -> \uXXXX
def decode_once(value):
    decoded = unquote(value)

    entities = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    for old, new in entities.items():
        decoded = decoded.replace(old, new)

    def unicode_replace(match):
        return chr(int(match.group(1), 16))

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_replace,
        decoded
    )

    # Numeric HTML entities
    decoded = re.sub(
        r"&#([0-9]+);",
        lambda m: chr(int(m.group(1))),
        decoded
    )

    decoded = re.sub(
        r"&#x([0-9a-fA-F]+);",
        lambda m: chr(int(m.group(1), 16)),
        decoded
    )

    return decoded


def extract_urls(text, channel):
    if channel == "html":
        return re.findall(
            r"""(?is)(?:src|href)\s*=\s*["']([^"']*)["']""",
            text
        )

    if channel == "markdown":
        return re.findall(
            r"""\]\(\s*([^)]+?)\s*\)""",
            text
        )

    if channel == "url":
        return [text.strip()]

    return []


def parsed_url(value):
    try:
        value = value.strip()

        # Protocol-relative URL
        if value.startswith("//"):
            value = "https:" + value

        return urlparse(value)

    except Exception:
        return None


def has_dangerous_scheme(text, channel):
    # Explicit dangerous schemes anywhere in the text
    if re.search(
        r"(?i)(?:javascript|data|vbscript)\s*:",
        text
    ):
        return True

    # Extract URLs and inspect their schemes
    for value in extract_urls(text, channel):
        parsed = parsed_url(value)

        if parsed is None:
            continue

        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return True

    return False


def has_external_exfil(text, channel):
    for value in extract_urls(text, channel):

        parsed = parsed_url(value)

        if parsed is None:
            continue

        # Only absolute HTTP/HTTPS URLs are relevant here
        if parsed.scheme.lower() not in {"http", "https"}:
            continue

        hostname = parsed.hostname

        if hostname not in ALLOWED_HOSTS:
            return True

    return False


def check_html(text):

    # SCRIPT_TAG
    if re.search(
        r"(?is)<\s*(script|iframe|object|embed)\b",
        text
    ):
        return "SCRIPT_TAG"

    # EVENT_HANDLER
    if re.search(
        r"(?i)\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
        text
    ):
        return "EVENT_HANDLER"

    # DANGEROUS_SCHEME
    if has_dangerous_scheme(text, "html"):
        return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    if has_external_exfil(text, "html"):
        return "EXTERNAL_EXFIL"

    return None


def check_markdown(text):

    if has_dangerous_scheme(text, "markdown"):
        return "DANGEROUS_SCHEME"

    if has_external_exfil(text, "markdown"):
        return "EXTERNAL_EXFIL"

    return None


def check_url(text):

    if has_dangerous_scheme(text, "url"):
        return "DANGEROUS_SCHEME"

    if has_external_exfil(text, "url"):
        return "EXTERNAL_EXFIL"

    return None


def check_sql(text):

    if re.search(r"'", text):
        return "SQL_METACHAR"

    if re.search(r'"', text):
        return "SQL_METACHAR"

    if ";" in text:
        return "SQL_METACHAR"

    if "--" in text:
        return "SQL_METACHAR"

    if "/*" in text:
        return "SQL_METACHAR"

    if re.search(r"(?i)\bunion\b", text):
        return "SQL_METACHAR"

    if re.search(r"(?i)\bor\s+1\s*=\s*1\b", text):
        return "SQL_METACHAR"

    return None


def check_shell(text):

    if re.search(r"[;&|`<>]", text):
        return "SHELL_METACHAR"

    if "$(" in text:
        return "SHELL_METACHAR"

    if "${" in text:
        return "SHELL_METACHAR"

    return None


def check_original(text, channel):

    if channel == "html":
        return check_html(text)

    if channel == "markdown":
        return check_markdown(text)

    if channel == "url":
        return check_url(text)

    if channel == "sql":
        return check_sql(text)

    if channel == "shell":
        return check_shell(text)

    return None


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # =========================================================
    # 1. INVALID_SCHEMA
    # =========================================================

    try:
        data = await request.json()
    except Exception:
        return response(False, "INVALID_SCHEMA")

    if not isinstance(data, dict):
        return response(False, "INVALID_SCHEMA")

    if "channel" not in data:
        return response(False, "INVALID_SCHEMA")

    if "output" not in data:
        return response(False, "INVALID_SCHEMA")

    channel = data["channel"]
    output = data["output"]

    if channel not in CHANNELS:
        return response(False, "INVALID_SCHEMA")

    if not isinstance(output, str):
        return response(False, "INVALID_SCHEMA")

    if len(output) > 20000:
        return response(False, "INVALID_SCHEMA")

    # =========================================================
    # 2. ENCODED_PAYLOAD
    # =========================================================

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_original(
            decoded,
            channel
        )

        if decoded_reason is not None:
            return response(
                False,
                "ENCODED_PAYLOAD"
            )

    # =========================================================
    # 3. ORIGINAL OUTPUT
    # =========================================================

    reason = check_original(
        output,
        channel
    )

    if reason is not None:
        return response(False, reason)

    return response(True, "SAFE")