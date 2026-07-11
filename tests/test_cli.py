import argparse
import gzip
import json
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from access_log_analyzer.cli import positive_integer, run


class CliTests(unittest.TestCase):
    def test_positive_integer_rejects_invalid_values(self) -> None:
        self.assertEqual(positive_integer("3"), 3)
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_integer("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_integer("not-a-number")

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
