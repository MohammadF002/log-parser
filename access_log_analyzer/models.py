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
