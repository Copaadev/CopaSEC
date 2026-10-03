"""Animacoes: etapas de boot e spinner para operacoes longas."""

import sys
import threading
import time

from colors import accent, colors_enabled, paint

FRAMES = ["|", "/", "-", "\\"]


def run_step(label: str, action=None, delay: float = 0.3) -> bool:
    """Etapa de boot com spinner curto. Falha vira aviso [!], sem traceback."""
    animated = colors_enabled()

    if animated:
        end = time.time() + delay
        i = 0
        while time.time() < end:
            frame = FRAMES[i % len(FRAMES)]
            sys.stdout.write(f"\r\033[2K{paint('[' + frame + ']', accent())} {label}")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    success = True
    detail = ""
    if action is not None:
        try:
            result = action()
            detail = result if isinstance(result, str) else ""
        except Exception as exc:
            success = False
            detail = str(exc)

    mark = paint("[✓]", "green", "bold") if success else paint("[!]", "yellow", "bold")
    line = f"{mark} {label}"
    if detail:
        line += paint(f"  ({detail})", "dim")
    prefix = "\r\033[2K" if animated else ""
    print(f"{prefix}{line}")
    return success


class Spinner:
    """Context manager: mostra um spinner enquanto o bloco roda."""

    def __init__(self, label: str):
        self.label = label
        self._stop = threading.Event()
        self._thread = None

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = FRAMES[i % len(FRAMES)]
            sys.stdout.write(f"\r\033[2K{paint('[' + frame + ']', accent())} {self.label}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    def __enter__(self):
        if colors_enabled():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(self.label)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._thread is not None:
            self._stop.set()
            self._thread.join()
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()
        return False
