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


def reply(safe, reason):
    return {"safe": safe, "reason": reason}


def decode_once(s):
    x = unquote(s)
    x = unescape(x)

    x = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        x,
    )

    return x


def extract_urls(text, channel):
    if channel == "html":
        return re.findall(
            r'''(?is)(?:src|href)\s*=\s*["']([^"']+)["']''',
            text,
        )

    if channel == "markdown":
        return re.findall(r"""\]\(\s*([^)]+?)\s*\)""", text)

    if channel == "url":
        return [text.strip()]

    return []


def dangerous_scheme(text, channel):
    if re.search(
        r"(?i)(?:javascript|data|vbscript)\s*:",
        text,
    ):
        return True

    for value in extract_urls(text, channel):
        value = value.strip()

        if value.startswith("//"):
            value = "https:" + value

        parsed = urlparse(value)

        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return True

    return False


def external_exfil(text, channel):
    for value in extract_urls(text, channel):
        value = value.strip()

        if value.startswith("//"):
            value = "https:" + value

        parsed = urlparse(value)

        if parsed.scheme.lower() in {"http", "https"}:
            if parsed.hostname not in ALLOWED_HOSTS:
                return True

    return False


def check_channel(text, channel):
    if channel == "html":

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

        if dangerous_scheme(text, channel):
            return "DANGEROUS_SCHEME"

        if external_exfil(text, channel):
            return "EXTERNAL_EXFIL"

    elif channel == "markdown":

        if dangerous_scheme(text, channel):
            return "DANGEROUS_SCHEME"

        if external_exfil(text, channel):
            return "EXTERNAL_EXFIL"

    elif channel == "url":

        if dangerous_scheme(text, channel):
            return "DANGEROUS_SCHEME"

        if external_exfil(text, channel):
            return "EXTERNAL_EXFIL"

    elif channel == "sql":

        if re.search(
            r"""(?i)('|")|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
            text,
        ):
            return "SQL_METACHAR"

    elif channel == "shell":

        if re.search(
            r"""[;&|`<>]|\$\(|\$\{""",
            text,
        ):
            return "SHELL_METACHAR"

    return None


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # 1. INVALID_SCHEMA
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    if not isinstance(data, dict):
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    if "channel" not in data or "output" not in data:
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    channel = data["channel"]
    output = data["output"]

    if channel not in CHANNELS:
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    if not isinstance(output, str):
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    if len(output) > 20000:
        return JSONResponse(reply(False, "INVALID_SCHEMA"))

    # 2. ENCODED_PAYLOAD
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_channel(decoded, channel)

        if decoded_reason is not None:
            return JSONResponse(
                reply(False, "ENCODED_PAYLOAD")
            )

    # 3. Original output
    reason = check_channel(output, channel)

    if reason:
        return JSONResponse(reply(False, reason))

    return JSONResponse(reply(True, "SAFE"))