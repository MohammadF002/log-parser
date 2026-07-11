import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from typing import TextIO

from .analyzer import LogAnalyzer
from .readers import open_log_file
from .report import TextReportFormatter


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m access_log_analyzer",
        description="Analyze an access log in Combined Log Format.",
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="path to the access log file",
    )
    return parser


def run(
    arguments: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = stdout if stdout is not None else sys.stdout
    error_output = stderr if stderr is not None else sys.stderr
    options = create_argument_parser().parse_args(arguments)

    started_at = perf_counter()
    try:
        with open_log_file(options.log_file) as lines:
            result = LogAnalyzer().analyze(lines)
    except OSError as error:
        reason = error.strerror or str(error)
        print(
            f"error: cannot read '{options.log_file}': {reason}",
            file=error_output,
        )
        return 1

    elapsed_seconds = perf_counter() - started_at
    report = TextReportFormatter().format(
        result=result,
        source_path=options.log_file,
        elapsed_seconds=elapsed_seconds,
    )
    print(report, file=output)
    return 0
