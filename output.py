"""Helpers de saida: secoes, pares chave/valor, tabelas e erros."""

from colors import accent, error, paint


def section(title: str) -> None:
    print()
    print(paint("▌", accent(), "bold") + " " + paint(title, "white", "bold"))
    print(paint("─" * (len(title) + 2), accent()))


def kv(pairs, indent: int = 2) -> None:
    pairs = [(k, v) for k, v in pairs if v not in (None, "")]
    if not pairs:
        return
    width = max(len(k) for k, _ in pairs)
    for key, value in pairs:
        print(" " * indent + paint(key.ljust(width), "dim") + "  " + str(value))


def table(headers, rows, styler=None, indent: int = 2) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    pad = " " * indent
    print(pad + "  ".join(paint(h.ljust(widths[i]), accent(), "bold") for i, h in enumerate(headers)))
    print(pad + "  ".join(paint("─" * w, "dim") for w in widths))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            text = str(cell).ljust(widths[i])
            styles = styler(i, str(cell)) if styler else ()
            cells.append(paint(text, *styles) if styles else text)
        print(pad + "  ".join(cells))


def show_failure(result: dict) -> None:
    lines = str(result.get("error") or "Unknown error").splitlines() or ["Unknown error"]
    error(lines[0])
    for line in lines[1:]:
        print("    " + line)
