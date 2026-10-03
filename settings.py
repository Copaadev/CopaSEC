"""Carregamento e validacao da configuracao do CopaSec."""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"

DEFAULTS = {
    "theme": "dark",
    "timeout": 30,
    "report_dir": "reports",
    "log_dir": "logs",
    "verbosity": "normal",
}

VALID_VERBOSITY = ("quiet", "normal", "verbose")


def _sanitize(data: dict) -> dict:
    config = dict(DEFAULTS)
    config.update({k: v for k, v in data.items() if k in DEFAULTS})

    timeout = config["timeout"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 600:
        config["timeout"] = DEFAULTS["timeout"]

    if config["verbosity"] not in VALID_VERBOSITY:
        config["verbosity"] = DEFAULTS["verbosity"]

    for key in ("theme", "report_dir", "log_dir"):
        if not isinstance(config[key], str) or not config[key].strip():
            config[key] = DEFAULTS[key]

    return config


def load_config() -> dict:
    """Le config.json. Nunca levanta excecao: usa padroes em caso de erro."""
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return dict(DEFAULTS)
        return _sanitize(data)
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULTS)


def save_config(config: dict) -> bool:
    try:
        with CONFIG_FILE.open("w", encoding="utf-8") as fh:
            json.dump(_sanitize(config), fh, indent=2)
            fh.write("\n")
        return True
    except OSError:
        return False


def resolve_dir(name: str) -> Path:
    path = Path(name)
    return path if path.is_absolute() else BASE_DIR / path
