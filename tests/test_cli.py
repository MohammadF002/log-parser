import argparse
import gzip
import json
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from access_log_analyzer.cli import iso_datetime, positive_integer, run


class CliTests(unittest.TestCase):
    def test_positive_integer_rejects_invalid_values(self) -> None:
        self.assertEqual(positive_integer("3"), 3)
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_integer("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_integer("not-a-number")

    def test_iso_datetime_requires_timezone(self) -> None:
        self.assertEqual(
            iso_datetime("2026-06-01T09:00:00Z"),
            datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
        )
        with self.assertRaises(argparse.ArgumentTypeError):
            iso_datetime("2026-06-01T09:00:00")

    def test_run_analyzes_file_and_writes_report(self) -> None:
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample.log"
            log_path.write_text(
                "\n".join(
                    (
                        '203.0.113.1 - - [01/Jun/2026:09:00:00 +0000] '
                        '"GET / HTTP/1.1" 200 100 "-" "agent"',
                        "garbage <<< malformed line",
                    )
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()

            exit_code = run([str(log_path)], stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("Processed lines:    2", stdout.getvalue())
        self.assertIn("Valid requests:     1", stdout.getvalue())
        self.assertIn("Malformed lines:    1", stdout.getvalue())

    def test_run_analyzes_gzip_file(self) -> None:
        log_line = (
            '203.0.113.1 - - [01/Jun/2026:09:00:00 +0000] '
            '"GET /health HTTP/1.1" 200 100 "-" "agent"\n'
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample.log.gz"
            log_path.write_bytes(gzip.compress(log_line.encode("utf-8")))
            stdout = StringIO()
            stderr = StringIO()

            exit_code = run([str(log_path)], stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("Valid requests:     1", stdout.getvalue())
        self.assertIn("/health", stdout.getvalue())

    def test_run_supports_json_output_and_top_limit(self) -> None:
        lines = (
            '203.0.113.1 - - [01/Jun/2026:09:00:00 +0000] '
            '"GET /products HTTP/1.1" 200 100 "-" "agent"\n',
            '203.0.113.2 - - [01/Jun/2026:09:00:01 +0000] '
            '"GET /login HTTP/1.1" 401 100 "-" "agent"\n',
            '203.0.113.3 - - [01/Jun/2026:09:00:02 +0000] '
            '"GET /products HTTP/1.1" 200 100 "-" "agent"\n',
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample.log"
            log_path.write_text("".join(lines), encoding="utf-8")
            stdout = StringIO()
            stderr = StringIO()

            exit_code = run(
                [str(log_path), "--format", "json", "--top", "1"],
                stdout=stdout,
                stderr=stderr,
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            report["top_endpoints"],
            [{"endpoint": "/products", "request_count": 2}],
        )

    def test_run_filters_requested_time_range(self) -> None:
        lines = (
            '203.0.113.1 - - [01/Jun/2026:08:59:59 +0000] '
            '"GET /before HTTP/1.1" 200 100 "-" "agent"\n',
            '203.0.113.2 - - [01/Jun/2026:09:00:00 +0000] '
            '"GET /inside HTTP/1.1" 200 100 "-" "agent"\n',
            '203.0.113.3 - - [01/Jun/2026:10:00:00 +0000] '
            '"GET /after HTTP/1.1" 200 100 "-" "agent"\n',
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample.log"
            log_path.write_text("".join(lines), encoding="utf-8")
            stdout = StringIO()

            exit_code = run(
                [
                    str(log_path),
                    "--format",
                    "json",
                    "--since",
                    "2026-06-01T09:00:00Z",
                    "--until",
                    "2026-06-01T10:00:00Z",
                ],
                stdout=stdout,
                stderr=StringIO(),
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["valid_requests"], 3)
        self.assertEqual(report["filtered_requests"], 2)
        self.assertEqual(report["analyzed_requests"], 1)
        self.assertEqual(
            report["top_endpoints"],
            [{"endpoint": "/inside", "request_count": 1}],
        )

    def test_run_reports_suspicious_login_activity(self) -> None:
        line = (
            '203.0.113.9 - - [01/Jun/2026:09:00:00 +0000] '
            '"POST /login HTTP/1.1" 401 100 "-" "agent"\n'
        )
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample.log"
            log_path.write_text(line * 2, encoding="utf-8")
            stdout = StringIO()

            exit_code = run(
                [
                    str(log_path),
                    "--format",
                    "json",
                    "--login-failure-threshold",
                    "2",
                ],
                stdout=stdout,
                stderr=StringIO(),
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            report["suspicious_login_activity"],
            [{"client_ip": "203.0.113.9", "failure_count": 2}],
        )

    def test_run_reports_unreadable_file(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        exit_code = run(
            ["file-that-does-not-exist.log"],
            stdout=stdout,
            stderr=stderr,
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error: cannot read", stderr.getvalue())
