import argparse
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import TextIO

from .analyzer import LogAnalyzer, TimeRange
from .readers import open_log_file
from .report import JsonReportFormatter, TextReportFormatter


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return number


def iso_datetime(value: str) -> datetime:
    normalized_value = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed_value = datetime.fromisoformat(normalized_value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an ISO-8601 datetime") from error
    if parsed_value.utcoffset() is None:
        raise argparse.ArgumentTypeError("must include a timezone offset")
    return parsed_value


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
    parser.add_argument(
        "--top",
        type=positive_integer,
        default=10,
        metavar="N",
        help="number of top endpoints to report (default: 10)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="report output format (default: text)",
    )
    parser.add_argument(
        "--since",
        type=iso_datetime,
        help="include records at or after this ISO-8601 datetime",
    )
    parser.add_argument(
        "--until",
        type=iso_datetime,
        help="include records before this ISO-8601 datetime",
    )
    parser.add_argument(
        "--login-failure-threshold",
        type=positive_integer,
        default=20,
        metavar="N",
        help="flag IPs with at least N /login 401 responses (default: 20)",
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
    argument_parser = create_argument_parser()
    options = argument_parser.parse_args(arguments)
    try:
        time_range = TimeRange(since=options.since, until=options.until)
    except ValueError as error:
        argument_parser.error(str(error))

    started_at = perf_counter()
    try:
        with open_log_file(options.log_file) as lines:
            result = LogAnalyzer(
                time_range=time_range,
                login_failure_threshold=options.login_failure_threshold,
            ).analyze(lines)
    except OSError as error:
        reason = error.strerror or str(error)
        print(
            f"error: cannot read '{options.log_file}': {reason}",
            file=error_output,
        )
        return 1

    elapsed_seconds = perf_counter() - started_at
    if options.output_format == "json":
        formatter = JsonReportFormatter(top_count=options.top)
    else:
        formatter = TextReportFormatter(top_count=options.top)

    report = formatter.format(
        result=result,
        source_path=options.log_file,
        elapsed_seconds=elapsed_seconds,
    )
    print(report, file=output)
    return 0
