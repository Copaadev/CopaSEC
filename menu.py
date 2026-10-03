"""Menu interativo do CopaSec."""

import platform

from banner import CONTENT_WIDTH, left_margin, print_banner
from colors import accent, clear_screen, error, paint, warn
from runner import TOOLS, tool_path

W = CONTENT_WIDTH - 2  # largura interna da caixa
HEAD_W = 8
LABEL_W = 20

SECTIONS = [
    ("RECON", [
        ("1", "Network Scanner", "host discovery"),
        ("2", "Port Scanner", "open ports"),
        ("3", "Service Detection", "service versions"),
        ("4", "Banner Grabber", "raw service banner"),
    ]),
    ("WEB & DNS", [
        ("5", "DNS Recon", "A, MX, NS, TXT records"),
        ("6", "Subdomain Finder", "wordlist DNS check"),
        ("7", "HTTP Analysis", "status, headers, title"),
        ("8", "Security Headers", "hardening audit"),
        ("9", "SSL/TLS Analysis", "certificate details"),
    ]),
    ("INTEL", [
        ("10", "WHOIS Lookup", "ownership data"),
        ("11", "Traceroute", "network path"),
    ]),
    ("FRAMEWORK", [
        ("12", "Full Recon", "next stage"),
        ("13", "Reports", "next stage"),
        ("14", "Settings", "next stage"),
        ("0", "Exit", ""),
    ]),
]

VALID_KEYS = {key for _, items in SECTIONS for key, _, _ in items}


def _rule(title: str, left: str, right: str) -> str:
    t = f" {title} " if title else ""
    fill = "─" * (W - 1 - len(t))
    return (paint(left + "─", accent()) + paint(t, accent(), "bold")
            + paint(fill + right, accent()))


def _row(key: str, label: str, desc: str) -> str:
    head = f"  [{key}]".ljust(HEAD_W)
    desc_w = W - HEAD_W - LABEL_W
    return (paint("│", accent()) + paint(head, accent(), "bold")
            + paint(label.ljust(LABEL_W), "white") + paint(desc.ljust(desc_w), "dim")
            + paint("│", accent()))


def _status_line() -> str:
    parts = []
    for tool in TOOLS:
        found = tool_path(tool) is not None
        mark = paint("✓", "green", "bold") if found else paint("✗", "red", "bold")
        parts.append(f"{tool} {mark}")
    return paint("tools  ", "dim") + "   ".join(parts)


def _prompt_text() -> str:
    host = platform.node().split(".")[0] or "host"
    return f"copa@{host} > "


def render_menu(version: str) -> None:
    print_banner(version)
    pad = left_margin()
    for i, (title, items) in enumerate(SECTIONS):
        first = i == 0
        print(pad + _rule(title, "╭" if first else "├", "╮" if first else "┤"))
        for key, label, desc in items:
            print(pad + _row(key, label, desc))
    print(pad + _rule("", "╰", "╯"))
    print(pad + " " + _status_line())
    print()


def _wait_enter() -> None:
    try:
        input(paint("\nPress ENTER to continue...", "dim"))
    except EOFError:
        pass


def run_menu(handlers: dict, version: str = "2.0.0") -> None:
    """Loop principal. `handlers` mapeia a tecla do menu para uma funcao."""
    while True:
        clear_screen()
        render_menu(version)
        try:
            choice = input(left_margin() + paint(_prompt_text(), accent(), "bold")).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if choice == "0":
            break
        if choice not in VALID_KEYS:
            error(f"Invalid option: {choice!r}")
            _wait_enter()
            continue

        handler = handlers.get(choice)
        if handler is None:
            warn("This feature is not implemented yet.")
            _wait_enter()
            continue

        try:
            handler()
        except KeyboardInterrupt:
            print()
            warn("Operation cancelled.")
        except Exception as exc:
            error(f"Unexpected error: {exc}")
        _wait_enter()
