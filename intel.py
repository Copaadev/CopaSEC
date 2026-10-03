"""Inteligencia passiva: WHOIS e traceroute."""

import re

from colors import accent, paint, warn
from output import kv
from runner import missing_tool_message, new_result, run_command, tool_path

WHOIS_KEYS = (
    "domain name", "registrar", "creation date", "registry expiry date", "updated date",
    "name server", "domain status", "registrant organization", "orgname", "org-name",
    "organization", "country", "netname", "netrange", "cidr", "nettype", "descr",
    "abuse-mailbox", "orgabuseemail",
)


def whois_lookup(target: str, config: dict) -> dict:
    result = new_result("whois", "WHOIS Lookup", target)
    if tool_path("whois") is None:
        result["error"] = missing_tool_message("whois")
        return result
    res = run_command(["whois", target], timeout=config["timeout"] + 15)
    if res.error:
        result["error"] = res.error
        return result
    if not res.stdout.strip():
        result["error"] = res.stderr.strip() or "No WHOIS data returned."
        return result
    fields, seen = [], set()
    for line in res.stdout.splitlines():
        if ":" not in line or line.lstrip().startswith(("%", "#", ">")):
            continue
        key, _, value = line.partition(":")
        item = (key.strip(), value.strip())
        if item[0].lower() in WHOIS_KEYS and item[1] and item not in seen:
            seen.add(item)
            fields.append(item)
    result["data"] = {"fields": fields[:40]}
    result["ok"] = True
    return result


def render_whois(result: dict) -> None:
    fields = result["data"]["fields"]
    if not fields:
        warn("No recognizable WHOIS fields in the response.")
        return
    kv(fields)


def trace_route(target: str, config: dict) -> dict:
    result = new_result("traceroute", "Traceroute", target)
    if tool_path("traceroute"):
        tool = "traceroute"
        args = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", target]
    elif tool_path("tracepath"):
        tool = "tracepath"
        args = ["tracepath", "-n", "-m", "20", target]
    else:
        result["error"] = missing_tool_message("traceroute")
        return result
    res = run_command(args, timeout=180)
    if res.error:
        result["error"] = res.error
        return result
    lines = [ln.rstrip() for ln in res.stdout.splitlines() if ln.strip()]
    if not lines:
        result["error"] = res.stderr.strip() or "No output from " + tool
        return result
    result["data"] = {"tool": tool, "lines": lines}
    result["ok"] = True
    return result


def render_trace(result: dict) -> None:
    for line in result["data"]["lines"]:
        match = re.match(r"^\s*(\d+\??:?)\s+(.*)$", line)
        if match:
            print("  " + paint(match.group(1).ljust(4), accent(), "bold") + match.group(2))
        else:
            print("  " + line)
