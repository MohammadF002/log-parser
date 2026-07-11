from collections import Counter

from .models import AccessLogRecord, SuspiciousLoginActivity


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
