"""Execucao segura de ferramentas externas (sempre sem shell)."""

import shutil
import socket
import ssl
import subprocess
import urllib.error
from dataclasses import dataclass

TOOLS = ("nmap", "dig", "whois", "traceroute")
ARCH_PACKAGES = {"nmap": "nmap", "dig": "bind", "whois": "whois", "traceroute": "traceroute"}


@dataclass
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    error: str = ""


def new_result(module: str, title: str, target: str) -> dict:
    """Formato padrao de resultado de todos os modulos."""
    return {"module": module, "title": title, "target": target,
            "ok": False, "error": "", "data": {}}


def tool_path(name: str):
    return shutil.which(name)


def missing_tool_message(name: str) -> str:
    pkg = ARCH_PACKAGES.get(name, name)
    return f"{name} is not installed.\nInstall on Arch Linux with:\n  sudo pacman -S {pkg}"


def run_command(args, timeout: int = 60) -> CommandResult:
    """Executa um comando com argumentos separados. Nunca usa shell."""
    args = [str(a) for a in args]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace",
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return CommandResult(False, error=f"{args[0]} was not found.")
    except subprocess.TimeoutExpired:
        return CommandResult(False, error=f"Command timed out after {timeout}s.")
    except PermissionError:
        return CommandResult(False, error=f"Permission denied running {args[0]}.")
    except OSError as exc:
        return CommandResult(False, error=f"Could not run {args[0]}: {exc}")
    return CommandResult(proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode)


def describe_network_error(exc) -> str:
    """Mensagem amigavel para erros de rede."""
    if isinstance(exc, urllib.error.URLError):
        exc = exc.reason
    if isinstance(exc, str):
        return exc
    if isinstance(exc, socket.gaierror):
        return "Could not resolve host."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out."
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused."
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc.reason or exc}"
    if isinstance(exc, PermissionError):
        return "Permission denied."
    return f"Network error: {exc}"
