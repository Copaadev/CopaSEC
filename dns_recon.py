"""Consultas DNS basicas e descoberta de subdominios por wordlist."""

import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

from colors import accent, info, warn
from output import kv, table
from runner import new_result, run_command, tool_path

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

WORDLIST = (
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2", "dns",
    "vpn", "remote", "portal", "admin", "dev", "test", "staging", "stage", "beta",
    "api", "app", "apps", "cdn", "static", "assets", "img", "media", "blog", "shop",
    "store", "support", "help", "docs", "status", "git", "gitlab", "jenkins", "ci",
    "db", "sql", "intranet", "internal", "login", "auth", "sso", "monitor",
    "grafana", "backup", "old", "new", "m", "mobile",
)


def _socket_fallback(target: str) -> dict:
    records = {}
    try:
        infos = socket.getaddrinfo(target, None)
    except (socket.gaierror, OSError):
        return records
    for family, _, _, _, sockaddr in infos:
        key = "A" if family == socket.AF_INET else "AAAA" if family == socket.AF_INET6 else None
        if key:
            values = records.setdefault(key, [])
            if sockaddr[0] not in values:
                values.append(sockaddr[0])
    return records


def dns_lookup(target: str, config: dict) -> dict:
    result = new_result("dns", "DNS Recon", target)

    if target.replace(".", "").isdigit() or ":" in target:  # IP -> reverse lookup
        try:
            ptr = socket.gethostbyaddr(target)[0]
        except (socket.herror, socket.gaierror, OSError):
            ptr = ""
        result["data"] = {"mode": "reverse", "ptr": ptr}
        result["ok"] = True
        return result

    records = {}
    has_dig = tool_path("dig") is not None
    if has_dig:
        for rtype in RECORD_TYPES:
            res = run_command(["dig", "+short", "+time=3", "+tries=1", target, rtype],
                              timeout=config["timeout"])
            if res.error:
                result["error"] = res.error
                return result
            values = [ln.strip() for ln in res.stdout.splitlines()
                      if ln.strip() and not ln.startswith(";")]
            if values:
                records[rtype] = values
    else:
        records = _socket_fallback(target)

    result["data"] = {"mode": "forward", "records": records, "dig": has_dig}
    result["ok"] = True
    return result


def render_dns(result: dict) -> None:
    data = result["data"]
    if data["mode"] == "reverse":
        kv([("PTR", data["ptr"] or "no reverse record found")])
        return
    if not data["dig"]:
        warn("dig is not installed - showing A/AAAA only.")
        print("    Install on Arch Linux with:\n      sudo pacman -S bind\n")
    rows = [[rtype, value] for rtype, values in data["records"].items() for value in values]
    if not rows:
        warn("No records found. The domain may not exist or DNS is unreachable.")
        return
    table(["TYPE", "VALUE"], rows, styler=lambda col, v: (accent(), "bold") if col == 0 else ())


def _resolves(name: str) -> list:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(name, None)})
    except (socket.gaierror, OSError):
        return []


def find_subdomains(target: str, config: dict) -> dict:
    result = new_result("subdomains", "Subdomain Finder", target)
    if _resolves(f"copasec-{secrets.token_hex(6)}.{target}"):
        result["error"] = "Wildcard DNS detected - results would be unreliable."
        return result
    names = [f"{word}.{target}" for word in WORDLIST]
    with ThreadPoolExecutor(max_workers=20) as pool:
        answers = list(pool.map(_resolves, names))
    found = [{"name": n, "addresses": a} for n, a in zip(names, answers) if a]
    result["data"] = {"found": found, "checked": len(names)}
    result["ok"] = True
    return result


def render_subdomains(result: dict) -> None:
    data = result["data"]
    if not data["found"]:
        warn(f"No subdomains found ({data['checked']} names checked).")
        return
    rows = [[f["name"], ", ".join(f["addresses"])] for f in data["found"]]
    table(["SUBDOMAIN", "ADDRESS"], rows)
    print()
    info(f"{len(data['found'])} found out of {data['checked']} names checked")
