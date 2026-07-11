from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class AccessLogRecord:
    client_ip: str
    timestamp: datetime
    method: str
    request_target: str
    protocol: str
    status_code: int
    response_size: int | None
    referrer: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class EndpointTraffic:
    endpoint: str
    request_count: int


@dataclass(frozen=True, slots=True)
class HourlyTraffic:
    hour: datetime
    request_count: int


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    processed_lines: int
    valid_requests: int
    malformed_lines: int
    unique_ip_count: int
    error_requests: int
    endpoint_traffic: tuple[EndpointTraffic, ...]
    hourly_traffic: tuple[HourlyTraffic, ...]
    filtered_requests: int = 0

    def __post_init__(self) -> None:
        if self.processed_lines != self.valid_requests + self.malformed_lines:
            raise ValueError("processed lines must equal valid and malformed lines")
        if not 0 <= self.filtered_requests <= self.valid_requests:
            raise ValueError("filtered requests must be within the valid request count")
        if not 0 <= self.error_requests <= self.analyzed_requests:
            raise ValueError("error requests must be within the analyzed request count")
        if not 0 <= self.unique_ip_count <= self.analyzed_requests:
            raise ValueError("unique IP count must be within the analyzed request count")

    @property
    def analyzed_requests(self) -> int:
        return self.valid_requests - self.filtered_requests

    @property
    def error_rate_percent(self) -> float:
        if self.analyzed_requests == 0:
            return 0.0
        return self.error_requests / self.analyzed_requests * 100

    def top_endpoints(self, count: int) -> tuple[EndpointTraffic, ...]:
        if count < 1:
            raise ValueError("endpoint count must be at least one")
        return self.endpoint_traffic[:count]
