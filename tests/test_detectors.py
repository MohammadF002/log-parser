import unittest
from datetime import datetime, timezone

from access_log_analyzer.detectors import LoginFailureDetector
from access_log_analyzer.models import AccessLogRecord, SuspiciousLoginActivity


def make_record(
    client_ip: str,
    request_target: str = "/login",
    status_code: int = 401,
) -> AccessLogRecord:
    return AccessLogRecord(
        client_ip=client_ip,
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        method="POST",
        request_target=request_target,
        protocol="HTTP/1.1",
        status_code=status_code,
        response_size=100,
        referrer="-",
        user_agent="agent",
    )


class LoginFailureDetectorTests(unittest.TestCase):
    def test_findings_include_ips_that_reach_threshold(self) -> None:
        detector = LoginFailureDetector(threshold=3)
        detector.observe(make_record("203.0.113.1"))
        detector.observe(make_record("203.0.113.1", request_target="/login?next=/"))
        detector.observe(make_record("203.0.113.1"))
        detector.observe(make_record("203.0.113.2"))

        self.assertEqual(
            detector.findings(),
            (
                SuspiciousLoginActivity(
                    client_ip="203.0.113.1",
                    failure_count=3,
                ),
            ),
        )

    def test_detector_ignores_other_endpoints_and_statuses(self) -> None:
        detector = LoginFailureDetector(threshold=1)
        detector.observe(make_record("203.0.113.1", request_target="/products"))
        detector.observe(make_record("203.0.113.1", status_code=200))

        self.assertEqual(detector.findings(), ())

    def test_threshold_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            LoginFailureDetector(threshold=0)
