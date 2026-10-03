"""Leitura do banner de um servico TCP (apenas leitura/HEAD simples)."""

import socket

from colors import warn
from output import kv
from runner import describe_network_error, new_result

HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


def _read(sock) -> bytes:
    sock.settimeout(2.0)
    try:
        return sock.recv(1024)
    except (socket.timeout, TimeoutError):
        return b""


def _clean(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() or ch in "\r\n" else "." for ch in text)


def grab_banner(target: str, port: int, config: dict) -> dict:
    result = new_result("banner", "Banner Grabber", f"{target}:{port}")
    timeout = min(config["timeout"], 10)
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            raw = _read(sock)
            probe = "passive"
            if not raw:
                sock.sendall(HTTP_PROBE)
                raw = _read(sock)
                probe = "HTTP HEAD"
    except OSError as exc:
        result["error"] = describe_network_error(exc)
        return result
    lines = [ln[:120] for ln in _clean(raw).splitlines() if ln.strip()][:15]
    result["data"] = {"port": port, "probe": probe, "lines": lines}
    result["ok"] = True
    return result


def render_banner(result: dict) -> None:
    d = result["data"]
    if not d["lines"]:
        warn("Port is open but the service sent no banner.")
        return
    kv([("Port", d["port"]), ("Probe", d["probe"])])
    print()
    for line in d["lines"]:
        print("    " + line)
