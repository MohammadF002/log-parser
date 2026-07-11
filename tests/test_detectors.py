import unittest
from datetime import datetime, timedelta, timezone

from access_log_analyzer.detectors import LoginFailureDetector, ServerErrorSpikeDetector
from access_log_analyzer.models import AccessLogRecord, SuspiciousLoginActivity


def make_record(
    client_ip: str,
    request_target: str = "/login",
    status_code: int = 401,
    timestamp: datetime | None = None,
) -> AccessLogRecord:
    return AccessLogRecord(
        client_ip=client_ip,
        timestamp=timestamp or datetime(2026, 6, 1, tzinfo=timezone.utc),
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


class ServerErrorSpikeDetectorTests(unittest.TestCase):
    def test_analyze_groups_consecutive_anomalous_minutes(self) -> None:
        detector = ServerErrorSpikeDetector(minimum_requests_per_bucket=20)
        start = datetime(2026, 6, 1, 9, tzinfo=timezone.utc)
        for minute_index in range(6):
            error_count = 40 if minute_index in (3, 4) else 1
            for request_index in range(100):
                detector.observe(
                    make_record(
                        client_ip="203.0.113.1",
                        request_target="/products",
                        status_code=500 if request_index < error_count else 200,
                        timestamp=start + timedelta(minutes=minute_index),
                    )
                )

        analysis = detector.analyze()

        self.assertEqual(analysis.baseline_error_rate_percent, 1.0)
        self.assertEqual(analysis.threshold_error_rate_percent, 10.0)
        self.assertEqual(len(analysis.incidents), 1)
        incident = analysis.incidents[0]
        self.assertEqual(incident.start, start + timedelta(minutes=3))
        self.assertEqual(incident.end, start + timedelta(minutes=5))
        self.assertEqual(incident.request_count, 200)
        self.assertEqual(incident.server_error_count, 80)
        self.assertEqual(incident.error_rate_percent, 40.0)
        self.assertEqual(incident.peak_error_rate_percent, 40.0)

    def test_analyze_ignores_low_volume_minutes(self) -> None:
        detector = ServerErrorSpikeDetector(minimum_requests_per_bucket=20)
        for _ in range(10):
            detector.observe(make_record("203.0.113.1", status_code=500))

        analysis = detector.analyze()

        self.assertEqual(analysis.incidents, ())
