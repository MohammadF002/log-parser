from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.parse import urlsplit

from .detectors import LoginFailureDetector
from .models import AnalysisResult, EndpointTraffic, HourlyTraffic
from .parser import CombinedLogParser, ParseResult


class LineParser(Protocol):
    def parse(self, line: str) -> ParseResult:
        ...


@dataclass(frozen=True, slots=True)
class TimeRange:
    since: datetime | None = None
    until: datetime | None = None

    def __post_init__(self) -> None:
        for name, boundary in (("since", self.since), ("until", self.until)):
            if boundary is not None and boundary.utcoffset() is None:
                raise ValueError(f"{name} must include a timezone offset")
        if self.since is not None and self.until is not None:
            if self.since > self.until:
                raise ValueError("since must not be later than until")

    def contains(self, timestamp: datetime) -> bool:
        if timestamp.utcoffset() is None:
            raise ValueError("record timestamp must include a timezone offset")
        if self.since is not None and timestamp < self.since:
            return False
        if self.until is not None and timestamp >= self.until:
            return False
        return True


class LogAnalyzer:
    def __init__(
        self,
        parser: LineParser | None = None,
        time_range: TimeRange | None = None,
        login_failure_threshold: int = 20,
    ) -> None:
        if login_failure_threshold < 1:
            raise ValueError("login failure threshold must be at least one")
        self._parser = parser if parser is not None else CombinedLogParser()
        self._time_range = time_range if time_range is not None else TimeRange()
        self._login_failure_threshold = login_failure_threshold

    def analyze(self, lines: Iterable[str]) -> AnalysisResult:
        processed_lines = 0
        valid_requests = 0
        malformed_lines = 0
        filtered_requests = 0
        error_requests = 0
        unique_ips: set[str] = set()
        endpoint_counts: Counter[str] = Counter()
        hourly_counts: Counter[datetime] = Counter()
        login_failure_detector = LoginFailureDetector(
            threshold=self._login_failure_threshold
        )

        for line in lines:
            processed_lines += 1
            parse_result = self._parser.parse(line)
            if not parse_result.is_success:
                malformed_lines += 1
                continue

            record = parse_result.record
            if record is None:
                raise RuntimeError("successful parse result does not contain a record")

            valid_requests += 1
            if not self._time_range.contains(record.timestamp):
                filtered_requests += 1
                continue

            login_failure_detector.observe(record)
            unique_ips.add(record.client_ip)
            endpoint_counts[self._endpoint_from(record.request_target)] += 1

            hour = record.timestamp.astimezone(timezone.utc).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            hourly_counts[hour] += 1

            if 400 <= record.status_code <= 599:
                error_requests += 1

        endpoint_traffic = tuple(
            EndpointTraffic(endpoint=endpoint, request_count=request_count)
            for endpoint, request_count in sorted(
                endpoint_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        )
        hourly_traffic = tuple(
            HourlyTraffic(hour=hour, request_count=request_count)
            for hour, request_count in sorted(hourly_counts.items())
        )

        return AnalysisResult(
            processed_lines=processed_lines,
            valid_requests=valid_requests,
            malformed_lines=malformed_lines,
            unique_ip_count=len(unique_ips),
            error_requests=error_requests,
            endpoint_traffic=endpoint_traffic,
            hourly_traffic=hourly_traffic,
            filtered_requests=filtered_requests,
            suspicious_login_activity=login_failure_detector.findings(),
        )

    @staticmethod
    def _endpoint_from(request_target: str) -> str:
        parsed_target = urlsplit(request_target)
        if parsed_target.scheme and parsed_target.netloc:
            return parsed_target.path or "/"
        return parsed_target.path or request_target
