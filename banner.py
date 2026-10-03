"""Banner ASCII do CopaSec."""

import shutil

from colors import accent, paint

ASCII_LOGO = [
    "   ██████╗ ██████╗ ██████╗  █████╗ ███████╗███████╗ ██████╗",
    "  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝",
    "  ██║     ██║   ██║██████╔╝███████║███████╗█████╗  ██║     ",
    "  ██║     ██║   ██║██╔═══╝ ██╔══██║╚════██║██╔══╝  ██║     ",
    "  ╚██████╗╚██████╔╝██║     ██║  ██║███████║███████╗╚██████╗",
    "   ╚═════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝",
]

SUBTITLE = "S E C U R I T Y   R E C O N   F R A M E W O R K"
CONTENT_WIDTH = 64
MIN_ROWS_FULL_BANNER = 38


def left_margin(width: int = CONTENT_WIDTH) -> str:
    cols = shutil.get_terminal_size((80, 24)).columns
    return " " * max(0, (cols - width) // 2)


def print_banner(version: str = "2.0.0", compact=None) -> None:
    """Logo grande se o terminal for alto o bastante; senao, cabecalho compacto."""
    if compact is None:
        compact = shutil.get_terminal_size((80, 24)).lines < MIN_ROWS_FULL_BANNER

    pad = left_margin()
    print()

    if compact:
        title = f"C O P A S E C  ·  Security Recon Framework  ·  v{version}"
        print(pad + paint(title.center(CONTENT_WIDTH), accent(), "bold"))
        print(pad + paint("authorized use only".center(CONTENT_WIDTH), "dim"))
        print()
        return

    logo_w = max(len(line) for line in ASCII_LOGO)
    block_pad = " " * max(0, (CONTENT_WIDTH - logo_w) // 2)
    for line in ASCII_LOGO:
        print(pad + block_pad + paint(line.ljust(logo_w), accent(), "bold"))
    print()
    print(pad + paint(SUBTITLE.center(CONTENT_WIDTH), "white", "bold"))
    print(pad + paint(f"v{version} · authorized use only".center(CONTENT_WIDTH), "dim"))
    print()
