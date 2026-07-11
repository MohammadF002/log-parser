import gzip
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from access_log_analyzer.readers import open_log_file


class OpenLogFileTests(unittest.TestCase):
    def test_open_plain_text_log(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            path.write_bytes(b"first line\nsecond line\n")

            with open_log_file(path) as source:
                lines = list(source)

        self.assertEqual(lines, ["first line\n", "second line\n"])

    def test_open_gzip_log(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "access.log.gz"
            path.write_bytes(gzip.compress(b"first line\nsecond line\n"))

            with open_log_file(path) as source:
                lines = list(source)

        self.assertEqual(lines, ["first line\n", "second line\n"])
