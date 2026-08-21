from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from urllib.parse import urlparse, unquote
from html import unescape
import re

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-itdr8us.example",
    "app-c5o95mc.example",
}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}


def result(safe, reason):
    return {"safe": safe, "reason": reason}


def decode_once(text):
    decoded = unquote(text)
    decoded = unescape(decoded)
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        decoded,
    )
    return decoded


def dangerous_scheme(text):
    if re.search(r"(?i)(javascript|data|vbscript)\s*:", text):
        return True

    urls = extract_urls(text)

    for value in urls:
        parsed = urlparse(
            "https:" + value if value.startswith("//") else value
        )

        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return True

    return False


def extract_urls(text, channel):
    if channel == "html":
        return re.findall(
            r"""(?i)(?:src|href)\s*=\s*["']([^"']+)["']""",
            text,
        )

    if channel == "markdown":
        return re.findall(r"""\]\(([^)]+)\)""", text)

    if channel == "url":
        return [text.strip()]

    return []


def external_exfil(text, channel):
    for value in extract_urls(text, channel):
        value = value.strip()

        if value.startswith("//"):
            value = "https:" + value

        parsed = urlparse(value)

        if parsed.scheme in {"http", "https"}:
            if parsed.hostname not in ALLOWED_HOSTS:
                return True

    return False


def html_check(text):
    if re.search(
        r"(?is)<\s*(script|iframe|object|embed)\b",
        text,
    ):
        return "SCRIPT_TAG"

    if re.search(
        r"(?i)\bon[a-zA-Z0-9_-]+\s*=",
        text,
    ):
        return "EVENT_HANDLER"

    if dangerous_scheme(text):
        return "DANGEROUS_SCHEME"

    if external_exfil(text, "html"):
        return "EXTERNAL_EXFIL"

    return None


def markdown_check(text):
    if dangerous_scheme(text):
        return "DANGEROUS_SCHEME"

    if external_exfil(text, "markdown"):
        return "EXTERNAL_EXFIL"

    return None


def url_check(text):
    if dangerous_scheme(text):
        return "DANGEROUS_SCHEME"

    if external_exfil(text, "url"):
        return "EXTERNAL_EXFIL"

    return None


def sql_check(text):
    if re.search(
        r"""(?i)('|")|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
        text,
    ):
        return "SQL_METACHAR"

    return None


def shell_check(text):
    if re.search(r"""[;&|`<>]|\$\(|\$\{""", text):
        return "SHELL_METACHAR"

    return None


@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    # Rule 1: schema
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    if not isinstance(data, dict):
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    if set(data.keys()) != {"channel", "output"}:
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    channel = data.get("channel")
    output = data.get("output")

    if channel not in CHANNELS:
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    if not isinstance(output, str):
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    if len(output) > 20000:
        return JSONResponse(result(False, "INVALID_SCHEMA"))

    # Rule 2: encoded payload
    decoded = decode_once(output)

    if decoded != output:
        if channel == "html":
            reason = html_check(decoded)
        elif channel == "markdown":
            reason = markdown_check(decoded)
        elif channel == "url":
            reason = url_check(decoded)
        elif channel == "sql":
            reason = sql_check(decoded)
        else:
            reason = shell_check(decoded)

        if reason:
            return JSONResponse(result(False, "ENCODED_PAYLOAD"))

    # Rule 3: original output
    if channel == "html":
        reason = html_check(output)
    elif channel == "markdown":
        reason = markdown_check(output)
    elif channel == "url":
        reason = url_check(output)
    elif channel == "sql":
        reason = sql_check(output)
    else:
        reason = shell_check(output)

    if reason:
        return JSONResponse(result(False, reason))

    return JSONResponse(result(True, "SAFE"))