from pathlib import Path
from typing import TextIO


def open_log_file(path: Path) -> TextIO:
    return path.open(
        mode="r",
        encoding="utf-8",
        errors="replace",
        newline="",
    )
