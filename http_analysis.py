"""Analise HTTP/HTTPS: status, headers, titulo e cabecalhos de seguranca."""

import html
import http.client
import re
import ssl
import urllib.error
import urllib.request

from colors import info, paint, warn
from output import kv, table
from runner import describe_network_error, new_result

USER_AGENT = "CopaSec/2.0 (authorized recon)"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
INFO_HEADERS = ("server", "x-powered-by", "content-type", "content-length",
                "via", "x-generator", "last-modified")
SECURITY_HEADERS = (
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
)


def _pack(resp, url: str) -> dict:
    status = getattr(resp, "status", None) or getattr(resp, "code", 0)
    body = resp.read(65536).decode("utf-8", errors="replace")
    return {
        "status": status,
        "reason": getattr(resp, "reason", "") or "",
        "final_url": resp.geturl() if hasattr(resp, "geturl") else url,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "body": body,
    }


def _fetch(url: str, timeout: int, verify: bool) -> dict:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
            return _pack(resp, url)
    except urllib.error.HTTPError as exc:
        return _pack(exc, url)


def _attempt(url: str, timeout: int):
    """Retorna (pagina, certificado_valido, erro)."""
    try:
        return _fetch(url, timeout, True), True, ""
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            try:
                return _fetch(url, timeout, False), False, ""
            except (OSError, http.client.HTTPException, ValueError) as exc2:
                return None, False, describe_network_error(exc2)
        return None, True, describe_network_error(exc)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return None, True, describe_network_error(exc)


def fetch_page(target: str, timeout: int):
    """Tenta HTTPS primeiro e depois HTTP. Retorna (pagina, erro)."""
    errors = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}/"
        page, verified, err = _attempt(url, timeout)
        if page is not None:
            page.update(scheme=scheme, cert_verified=verified, url=url)
            return page, ""
        errors.append(f"{scheme}: {err}")
    return None, "; ".join(errors)


def http_analysis(target: str, config: dict) -> dict:
    result = new_result("http", "HTTP Analysis", target)
    page, err = fetch_page(target, config["timeout"])
    if page is None:
        result["error"] = err
        return result
    match = TITLE_RE.search(page["body"])
    title = html.unescape(" ".join(match.group(1).split()))[:100] if match else ""
    result["data"] = {
        "url": page["url"], "final_url": page["final_url"],
        "status": page["status"], "reason": page["reason"],
        "https": page["scheme"] == "https", "cert_verified": page["cert_verified"],
        "title": title,
        "headers": {k: page["headers"][k] for k in INFO_HEADERS if k in page["headers"]},
    }
    result["ok"] = True
    return result


def _status_styles(code: int):
    if 200 <= code < 300:
        return ("green", "bold")
    if 300 <= code < 400:
        return ("yellow", "bold")
    return ("red", "bold")


def render_http(result: dict) -> None:
    d = result["data"]
    https = paint("yes", "green") if d["https"] else paint("no (plain HTTP)", "yellow", "bold")
    cert = ""
    if d["https"]:
        cert = (paint("trusted", "green") if d["cert_verified"]
                else paint("NOT trusted (self-signed, expired or hostname mismatch)", "red"))
    kv([
        ("URL", d["url"]),
        ("Final URL", d["final_url"] if d["final_url"] != d["url"] else ""),
        ("Status", paint(f"{d['status']} {d['reason']}".strip(), *_status_styles(d["status"]))),
        ("HTTPS", https),
        ("Certificate", cert),
        ("Title", d["title"]),
    ])
    if d["headers"]:
        print()
        print(paint("  Headers", "dim"))
        kv([(k, v[:80]) for k, v in d["headers"].items()], indent=4)


def security_headers(target: str, config: dict) -> dict:
    result = new_result("security_headers", "Security Headers", target)
    page, err = fetch_page(target, config["timeout"])
    if page is None:
        result["error"] = err
        return result
    headers = page["headers"]
    rows = []
    for key, label in SECURITY_HEADERS:
        value = headers.get(key, "")
        if key == "strict-transport-security" and page["scheme"] != "https":
            status = "N/A"
        elif value:
            status = "PASS"
        elif key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            status, value = "PASS", "via CSP frame-ancestors"
        else:
            status = "MISSING"
        rows.append({"header": label, "status": status, "value": value})
    graded = [r for r in rows if r["status"] != "N/A"]
    leaks = [(k, headers[k]) for k in ("server", "x-powered-by")
             if k in headers and re.search(r"\d", headers[k])]
    result["data"] = {
        "rows": rows, "leaks": leaks, "total": len(graded),
        "passed": sum(1 for r in graded if r["status"] == "PASS"),
    }
    result["ok"] = True
    return result


def _audit_style(col: int, value: str):
    if value == "PASS":
        return ("green", "bold")
    if value == "MISSING":
        return ("red", "bold")
    if value == "N/A":
        return ("dim",)
    return ()


def render_security(result: dict) -> None:
    d = result["data"]
    rows = [[r["header"], r["status"], r["value"][:50] or "-"] for r in d["rows"]]
    table(["HEADER", "STATUS", "VALUE"], rows, styler=_audit_style)
    print()
    info(f"Score: {d['passed']}/{d['total']} security headers present")
    for name, value in d["leaks"]:
        warn(f"{name} reveals version information: {value[:60]}")
