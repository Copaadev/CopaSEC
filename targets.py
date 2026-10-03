"""Validacao de alvos e portas. Toda entrada do usuario passa por aqui."""

import ipaddress
import re

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
PORT_SPEC_RE = re.compile(r"^\d{1,5}([,-]\d{1,5})*$")
MAX_CIDR_ADDRESSES = 1024


class InvalidInput(ValueError):
    """Entrada invalida do usuario (alvo ou porta)."""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_target(raw: str, allow_cidr: bool = False) -> str:
    """Valida e normaliza IP, dominio ou (opcionalmente) rede CIDR."""
    value = (raw or "").strip()
    if not value:
        raise InvalidInput("Empty target.")
    if "://" in value:
        value = value.split("://", 1)[1]

    if allow_cidr and "/" in value and not any(c.isalpha() for c in value.split("/")[0]):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise InvalidInput(f"Invalid network: {raw!r}")
        if net.num_addresses > MAX_CIDR_ADDRESSES:
            raise InvalidInput("Network too large (maximum is a /22).")
        return str(net)

    value = value.split("/", 1)[0]
    if is_ip(value):
        return str(ipaddress.ip_address(value))

    if value.count(":") == 1:
        host, port = value.split(":")
        if port.isdigit():
            value = host

    value = value.rstrip(".").lower()
    if not HOSTNAME_RE.match(value):
        raise InvalidInput(f"Invalid target: {raw!r}")
    return value


def parse_port(raw: str) -> int:
    try:
        port = int(str(raw).strip())
    except ValueError:
        raise InvalidInput(f"Invalid port: {raw!r}")
    if not 1 <= port <= 65535:
        raise InvalidInput("Port must be between 1 and 65535.")
    return port


def port_args(spec: str) -> list:
    """Converte a escolha do usuario em argumentos seguros do nmap."""
    spec = (spec or "").strip().lower()
    if spec in ("", "top100"):
        return ["--top-ports", "100"]
    if spec == "top1000":
        return ["--top-ports", "1000"]
    if spec == "all":
        return ["-p", "1-65535"]
    if not PORT_SPEC_RE.match(spec):
        raise InvalidInput("Invalid port list. Use e.g. 22,80,443 or 1-1024.")
    for number in re.findall(r"\d+", spec):
        if not 1 <= int(number) <= 65535:
            raise InvalidInput("Ports must be between 1 and 65535.")
    return ["-p", spec]
