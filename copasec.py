#!/usr/bin/env python3
"""CopaSec 2.0 - Security Recon Framework (uso autorizado)."""

import sys
import time

from actions import make_handlers
from animation import run_step
from banner import print_banner
from colors import clear_screen, error, info, paint, set_theme, warn
from menu import run_menu
from runner import ARCH_PACKAGES, TOOLS, tool_path
from settings import load_config

VERSION = "2.0.0"


def missing_tools() -> list:
    return [tool for tool in TOOLS if tool_path(tool) is None]


def check_dependencies() -> str:
    missing = missing_tools()
    if missing:
        raise RuntimeError("missing: " + ", ".join(missing))
    return "all tools found"


def boot(config: dict) -> None:
    clear_screen()
    print_banner(VERSION)
    info("Initializing CopaSec...")
    run_step("Loading modules")
    run_step("Checking dependencies", check_dependencies)
    run_step("Loading configuration", lambda: f"timeout={config['timeout']}s")
    run_step("System ready")
    missing = missing_tools()
    if missing:
        packages = " ".join(sorted({ARCH_PACKAGES[tool] for tool in missing}))
        warn(f"Optional tools missing: {', '.join(missing)}")
        print(f"    Install with: sudo pacman -S {packages}")
        time.sleep(2.0)
    else:
        time.sleep(0.6)


def main() -> int:
    config = load_config()
    set_theme(config["theme"])
    boot(config)
    run_menu(handlers=make_handlers(config), version=VERSION)
    print(paint("\nGoodbye.", "dim"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        error(f"Fatal error: {exc}")
        sys.exit(1)
