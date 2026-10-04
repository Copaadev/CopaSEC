"""Entrada interativa validada."""

from colors import accent, error, paint, warn
from targets import (InvalidInput, is_ip, parse_port, parse_target,
                     parse_web_target, port_args)

_AUTHORIZED = set()


def _ask(label: str) -> str:
    return input(paint(f"  {label}: ", accent(), "bold")).strip()


def confirm_authorized(target: str) -> bool:
    """Pede confirmacao de autorizacao uma vez por alvo na sessao."""
    if target in _AUTHORIZED:
        return True
    warn("Use only on systems you own or are explicitly authorized to test.")
    answer = _ask(f"Do you have authorization for {target}? [y/N]").lower()
    if answer in ("y", "yes", "s", "sim"):
        _AUTHORIZED.add(target)
        return True
    warn("Operation cancelled.")
    return False


def ask_target(label: str = "Target (IP or domain)", allow_cidr: bool = False,
               domain_only: bool = False, web: bool = False):
    raw = _ask(label)
    if not raw:
        return None
    try:
        if web:
            target = parse_web_target(raw)
        else:
            target = parse_target(raw, allow_cidr=allow_cidr)
    except InvalidInput as exc:
        error(str(exc))
        return None
    if domain_only and is_ip(target):
        error("This module needs a domain name, not an IP address.")
        return None
    return target if confirm_authorized(target) else None


def ask_port(label: str = "Port", default=None):
    suffix = f" [{default}]" if default else ""
    raw = _ask(f"{label}{suffix}")
    if not raw and default:
        return default
    try:
        return parse_port(raw)
    except InvalidInput as exc:
        error(str(exc))
        return None


def ask_ports():
    raw = _ask("Ports (ENTER=top 100 | top1000 | all | 22,80 | 1-1024)")
    try:
        return port_args(raw)
    except InvalidInput as exc:
        error(str(exc))
        return None
