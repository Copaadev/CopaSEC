"""Integracao com o Nmap: descoberta de hosts, portas e servicos."""

import xml.etree.ElementTree as ET

from colors import info, paint, warn
from output import table
from runner import missing_tool_message, new_result, run_command, tool_path


def _scan_timeout(config: dict) -> int:
    return max(120, config["timeout"] * 10)


def _run_nmap(args: list, timeout: int):
    """Roda o nmap com saida XML. Retorna (root, erro)."""
    if tool_path("nmap") is None:
        return None, missing_tool_message("nmap")
    res = run_command(["nmap", "-oX", "-"] + args, timeout=timeout)
    if res.error:
        return None, res.error
    try:
        return ET.fromstring(res.stdout), ""
    except ET.ParseError:
        return None, res.stderr.strip() or "Could not parse nmap output."


def _parse_hosts(root) -> list:
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        host = {
            "address": "", "mac": "", "vendor": "", "hostname": "",
            "state": status.get("state", "unknown") if status is not None else "unknown",
            "latency_ms": "", "ports": [],
        }
        for a in h.findall("address"):
            kind = a.get("addrtype")
            if kind in ("ipv4", "ipv6"):
                host["address"] = a.get("addr", "")
            elif kind == "mac":
                host["mac"] = a.get("addr", "")
                host["vendor"] = a.get("vendor", "")
        name = h.find("hostnames/hostname")
        if name is not None:
            host["hostname"] = name.get("name", "")
        times = h.find("times")
        if times is not None and times.get("srtt"):
            try:
                host["latency_ms"] = f"{int(times.get('srtt')) / 1000:.1f} ms"
            except ValueError:
                pass
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            version = ""
            name_ = ""
            if svc is not None:
                name_ = svc.get("name", "")
                version = " ".join(x for x in (svc.get("product", ""), svc.get("version", ""),
                                               svc.get("extrainfo", "")) if x)
            host["ports"].append({
                "port": int(p.get("portid", 0)),
                "protocol": p.get("protocol", ""),
                "state": state.get("state", "") if state is not None else "",
                "service": name_,
                "version": version,
            })
        hosts.append(host)
    return hosts


def host_discovery(target: str, config: dict) -> dict:
    result = new_result("network", "Network Scanner", target)
    root, err = _run_nmap(["-sn", "-T4", target], _scan_timeout(config))
    if root is None:
        result["error"] = err
        return result
    hosts = _parse_hosts(root)
    stats = root.find("runstats/hosts")
    up = int(stats.get("up", 0)) if stats is not None else len(hosts)
    result["data"] = {"hosts": hosts, "up": up}
    result["ok"] = True
    return result


def _scan_ports(target, config, port_spec, title, module, extra) -> dict:
    result = new_result(module, title, target)
    args = ["-Pn", "-T4", "--open", "--host-timeout", "5m"] + extra + port_spec + [target]
    root, err = _run_nmap(args, _scan_timeout(config))
    if root is None:
        result["error"] = err
        return result
    result["data"] = {"hosts": _parse_hosts(root)}
    result["ok"] = True
    return result


def port_scan(target: str, config: dict, port_spec: list) -> dict:
    return _scan_ports(target, config, port_spec, "Port Scanner", "ports", [])


def service_detection(target: str, config: dict, port_spec: list) -> dict:
    return _scan_ports(target, config, port_spec, "Service Detection", "services", ["-sV"])


def _state_style(col: int, value: str):
    if value in ("up", "open"):
        return ("green", "bold")
    if value in ("down", "closed"):
        return ("red",)
    if "filtered" in value:
        return ("yellow",)
    return ()


def render_hosts(result: dict) -> None:
    hosts = result["data"]["hosts"]
    if not hosts:
        warn("No live hosts found. The target may be down or blocking probes.")
        return
    rows = []
    for h in hosts:
        mac = h["mac"] + (f" ({h['vendor']})" if h["vendor"] else "")
        rows.append([h["address"], h["state"], h["hostname"] or "-",
                     h["latency_ms"] or "-", mac or "-"])
    table(["HOST", "STATE", "HOSTNAME", "LATENCY", "MAC"], rows, styler=_state_style)
    print()
    info(f"{result['data']['up']} host(s) up")


def render_ports(result: dict, versions: bool = False) -> None:
    hosts = result["data"]["hosts"]
    if not hosts:
        warn("Host appears to be down or unreachable.")
        return
    for host in hosts:
        label = host["address"] + (f" ({host['hostname']})" if host["hostname"] else "")
        print(paint(f"  Host: {label}   [{host['state']}]", "white", "bold"))
        if not host["ports"]:
            warn("No open ports found in the scanned range.")
            continue
        headers = ["PORT", "STATE", "SERVICE"] + (["VERSION"] if versions else [])
        rows = []
        for p in host["ports"]:
            row = [f"{p['port']}/{p['protocol']}", p["state"], p["service"] or "-"]
            if versions:
                row.append(p["version"] or "-")
            rows.append(row)
        table(headers, rows, styler=_state_style)
        print()


def render_services(result: dict) -> None:
    render_ports(result, versions=True)
