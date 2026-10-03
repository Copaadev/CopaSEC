"""Cores ANSI, temas e mensagens de status."""

import os
import sys

CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "white": "37",
}

THEMES = {"dark": "cyan", "matrix": "green", "red": "red", "purple": "magenta"}
_accent = "cyan"


def set_theme(name: str) -> None:
    global _accent
    _accent = THEMES.get(name, "cyan")


def accent() -> str:
    return _accent


def colors_enabled() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text: str, *styles: str) -> str:
    if not colors_enabled():
        return text
    prefix = "".join(f"\033[{CODES[s]}m" for s in styles if s in CODES)
    return f"{prefix}{text}\033[0m"


def info(msg: str) -> None:
    print(f"{paint('[+]', accent(), 'bold')} {msg}")


def ok(msg: str) -> None:
    print(f"{paint('[✓]', 'green', 'bold')} {msg}")


def warn(msg: str) -> None:
    print(f"{paint('[!]', 'yellow', 'bold')} {msg}")


def error(msg: str) -> None:
    print(f"{paint('[-]', 'red', 'bold')} {msg}")


def clear_screen() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
