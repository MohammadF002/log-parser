import gzip
from pathlib import Path
from typing import TextIO


def open_log_file(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(
            path,
            mode="rt",
            encoding="utf-8",
            errors="replace",
            newline="",
        )

    return path.open(
        mode="r",
        encoding="utf-8",
        errors="replace",
        newline="",
    )
