"""Liga as opcoes do menu aos modulos."""

import banner_grab
import dns_recon
import http_analysis
import intel
import nmap_scan
import ssl_analysis
from animation import Spinner
from output import section, show_failure
from prompts import ask_port, ask_ports, ask_target


def _execute(label: str, func, render) -> dict:
    with Spinner(label):
        result = func()
    section(f"{result['title']}  ·  {result['target']}")
    if result["ok"]:
        render(result)
    else:
        show_failure(result)
    return result


def make_handlers(config: dict) -> dict:
    def network():
        target = ask_target(allow_cidr=True)
        if target:
            _execute("Discovering hosts...",
                     lambda: nmap_scan.host_discovery(target, config), nmap_scan.render_hosts)

    def ports():
        target = ask_target()
        spec = ask_ports() if target else None
        if target and spec:
            _execute("Scanning ports...",
                     lambda: nmap_scan.port_scan(target, config, spec), nmap_scan.render_ports)

    def services():
        target = ask_target()
        spec = ask_ports() if target else None
        if target and spec:
            _execute("Detecting services...",
                     lambda: nmap_scan.service_detection(target, config, spec),
                     nmap_scan.render_services)

    def banner():
        target = ask_target()
        port = ask_port("Port") if target else None
        if target and port:
            _execute("Grabbing banner...",
                     lambda: banner_grab.grab_banner(target, port, config),
                     banner_grab.render_banner)

    def dns():
        target = ask_target()
        if target:
            _execute("Querying DNS...",
                     lambda: dns_recon.dns_lookup(target, config), dns_recon.render_dns)

    def subdomains():
        target = ask_target(domain_only=True)
        if target:
            _execute("Checking subdomains...",
                     lambda: dns_recon.find_subdomains(target, config),
                     dns_recon.render_subdomains)

    def http():
        target = ask_target()
        if target:
            _execute("Requesting page...",
                     lambda: http_analysis.http_analysis(target, config),
                     http_analysis.render_http)

    def sec_headers():
        target = ask_target()
        if target:
            _execute("Auditing headers...",
                     lambda: http_analysis.security_headers(target, config),
                     http_analysis.render_security)

    def tls():
        target = ask_target()
        port = ask_port("Port", default=443) if target else None
        if target and port:
            _execute("Inspecting TLS...",
                     lambda: ssl_analysis.tls_analysis(target, port, config),
                     ssl_analysis.render_tls)

    def whois():
        target = ask_target()
        if target:
            _execute("Querying WHOIS...",
                     lambda: intel.whois_lookup(target, config), intel.render_whois)

    def traceroute():
        target = ask_target()
        if target:
            _execute("Tracing route...",
                     lambda: intel.trace_route(target, config), intel.render_trace)

    return {
        "1": network, "2": ports, "3": services, "4": banner, "5": dns,
        "6": subdomains, "7": http, "8": sec_headers, "9": tls,
        "10": whois, "11": traceroute,
    }
