from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import median

from .models import (
    AccessLogRecord,
    ServerErrorIncident,
    ServerErrorSpikeAnalysis,
    SuspiciousLoginActivity,
)


class LoginFailureDetector:
    def __init__(self, threshold: int = 20) -> None:
        if threshold < 1:
            raise ValueError("login failure threshold must be at least one")
        self._threshold = threshold
        self._failure_counts: Counter[str] = Counter()

    def observe(self, record: AccessLogRecord) -> None:
        endpoint = record.request_target.partition("?")[0]
        if endpoint == "/login" and record.status_code == 401:
            self._failure_counts[record.client_ip] += 1

    def findings(self) -> tuple[SuspiciousLoginActivity, ...]:
        suspicious_counts = (
            (client_ip, failure_count)
            for client_ip, failure_count in self._failure_counts.items()
            if failure_count >= self._threshold
        )
        return tuple(
            SuspiciousLoginActivity(
                client_ip=client_ip,
                failure_count=failure_count,
            )
            for client_ip, failure_count in sorted(
                suspicious_counts,
                key=lambda item: (-item[1], item[0]),
            )
        )


class ServerErrorSpikeDetector:
    def __init__(
        self,
        minimum_requests_per_bucket: int = 20,
        minimum_error_rate: float = 0.10,
        minimum_rate_increase: float = 0.05,
        mad_multiplier: float = 6.0,
    ) -> None:
        if minimum_requests_per_bucket < 1:
            raise ValueError("minimum requests per bucket must be at least one")
        if not 0 <= minimum_error_rate <= 1:
            raise ValueError("minimum error rate must be between zero and one")
        if minimum_rate_increase < 0:
            raise ValueError("minimum rate increase cannot be negative")
        if mad_multiplier < 0:
            raise ValueError("MAD multiplier cannot be negative")

        self._minimum_requests_per_bucket = minimum_requests_per_bucket
        self._minimum_error_rate = minimum_error_rate
        self._minimum_rate_increase = minimum_rate_increase
        self._mad_multiplier = mad_multiplier
        self._request_counts: Counter[datetime] = Counter()
        self._server_error_counts: Counter[datetime] = Counter()

    def observe(self, record: AccessLogRecord) -> None:
        minute = record.timestamp.astimezone(timezone.utc).replace(
            second=0,
            microsecond=0,
        )
        self._request_counts[minute] += 1
        if 500 <= record.status_code <= 599:
            self._server_error_counts[minute] += 1

    def analyze(self) -> ServerErrorSpikeAnalysis:
        eligible_minutes = tuple(
            minute
            for minute, request_count in self._request_counts.items()
            if request_count >= self._minimum_requests_per_bucket
        )
        error_rates = tuple(self._error_rate(minute) for minute in eligible_minutes)

        if error_rates:
            baseline = median(error_rates)
            median_absolute_deviation = median(
                abs(error_rate - baseline) for error_rate in error_rates
            )
        else:
            baseline = 0.0
            median_absolute_deviation = 0.0

        threshold = max(
            self._minimum_error_rate,
            baseline
            + max(
                self._minimum_rate_increase,
                self._mad_multiplier * median_absolute_deviation,
            ),
        )
        anomalous_minutes = sorted(
            minute
            for minute in eligible_minutes
            if self._error_rate(minute) >= threshold
        )

        incidents = tuple(
            self._build_incident(group)
            for group in self._group_consecutive_minutes(anomalous_minutes)
        )
        return ServerErrorSpikeAnalysis(
            bucket_minutes=1,
            baseline_error_rate_percent=baseline * 100,
            threshold_error_rate_percent=threshold * 100,
            incidents=incidents,
        )

    def _error_rate(self, minute: datetime) -> float:
        return self._server_error_counts[minute] / self._request_counts[minute]

    def _build_incident(self, minutes: tuple[datetime, ...]) -> ServerErrorIncident:
        request_count = sum(self._request_counts[minute] for minute in minutes)
        server_error_count = sum(
            self._server_error_counts[minute] for minute in minutes
        )
        return ServerErrorIncident(
            start=minutes[0],
            end=minutes[-1] + timedelta(minutes=1),
            request_count=request_count,
            server_error_count=server_error_count,
            peak_error_rate_percent=max(self._error_rate(minute) for minute in minutes)
            * 100,
        )

    @staticmethod
    def _group_consecutive_minutes(
        minutes: list[datetime],
    ) -> tuple[tuple[datetime, ...], ...]:
        if not minutes:
            return ()

        groups: list[list[datetime]] = [[minutes[0]]]
        for minute in minutes[1:]:
            if minute == groups[-1][-1] + timedelta(minutes=1):
                groups[-1].append(minute)
            else:
                groups.append([minute])
        return tuple(tuple(group) for group in groups)
