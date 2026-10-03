"""Analise basica de HTTPS/TLS: certificado, validade e protocolo."""

import socket
import ssl
import time

from colors import paint, warn
from output import kv
from runner import describe_network_error, new_result


def _handshake(target: str, port: int, timeout: int, verify: bool) -> dict:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=target) as tls:
            return {
                "cert": tls.getpeercert() or {},
                "protocol": tls.version() or "",
                "cipher": tls.cipher() or ("", "", 0),
            }


def _days_left(not_after: str):
    if not not_after:
        return None
    try:
        return int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    except ValueError:
        return None


def tls_analysis(target: str, port: int, config: dict) -> dict:
    result = new_result("ssl", "SSL/TLS Analysis", f"{target}:{port}")
    timeout = config["timeout"]
    data = {"host": target, "port": port, "verified": True, "verify_error": ""}

    try:
        hs = _handshake(target, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as exc:
        data["verified"] = False
        data["verify_error"] = exc.verify_message or str(exc)
        try:
            hs = _handshake(target, port, timeout, verify=False)
        except OSError as exc2:
            result["error"] = describe_network_error(exc2)
            return result
    except OSError as exc:
        result["error"] = describe_network_error(exc)
        return result

    cert = hs["cert"]
    subject = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
    issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    cipher = hs["cipher"]
    data.update(
        protocol=hs["protocol"],
        cipher=f"{cipher[0]} ({cipher[2]} bits)" if cipher[0] else "",
        subject=subject.get("commonName", ""),
        issuer=issuer.get("organizationName") or issuer.get("commonName", ""),
        not_before=cert.get("notBefore", ""),
        not_after=cert.get("notAfter", ""),
        san=[v for t, v in cert.get("subjectAltName", ()) if t == "DNS"][:10],
        days_left=_days_left(cert.get("notAfter", "")),
    )
    result["data"] = data
    result["ok"] = True
    return result


def render_tls(result: dict) -> None:
    d = result["data"]
    days = d["days_left"]
    if days is None:
        expiry = ""
    elif days < 0:
        expiry = paint(f"EXPIRED {-days} day(s) ago", "red", "bold")
    elif days < 30:
        expiry = paint(f"{days} day(s) left", "yellow", "bold")
    else:
        expiry = paint(f"{days} day(s) left", "green")

    if d["verified"]:
        trust = paint("trusted", "green", "bold")
    else:
        trust = paint(f"NOT trusted ({d['verify_error']})", "red", "bold")
    old = d["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3")
    protocol = paint(d["protocol"], "yellow", "bold") if old else paint(d["protocol"], "green")

    kv([
        ("Host", f"{d['host']}:{d['port']}"),
        ("Trust", trust),
        ("Protocol", protocol),
        ("Cipher", d["cipher"]),
        ("Subject", d["subject"]),
        ("Issuer", d["issuer"]),
        ("Valid from", d["not_before"]),
        ("Valid until", d["not_after"]),
        ("Expires in", expiry),
        ("Alt names", ", ".join(d["san"])),
    ])
    if not d["verified"]:
        print()
        warn("Certificate details unavailable because validation failed.")
