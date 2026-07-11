import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from .models import AccessLogRecord


_LOG_LINE_PATTERN = re.compile(
    r"^(?P<client_ip>\S+) \S+ \S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<request>(?:\\.|[^"])*)" '
    r"(?P<status_code>\d{3}) "
    r"(?P<response_size>\d+|-) "
    r'"(?P<referrer>(?:\\.|[^"])*)" '
    r'"(?P<user_agent>(?:\\.|[^"])*)"\s*$'
)
_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<offset_sign>[+-])(?P<offset_hour>\d{2})(?P<offset_minute>\d{2})$"
)
_HTTP_METHOD_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HTTP_PROTOCOL_PATTERN = re.compile(r"^HTTP/\d+(?:\.\d+)?$")
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass(frozen=True, slots=True)
class ParseResult:
    record: AccessLogRecord | None
    error: str | None

    def __post_init__(self) -> None:
        has_record = self.record is not None
        has_error = self.error is not None
        if has_record == has_error:
            raise ValueError("a parse result must contain either a record or an error")
        if self.error == "":
            raise ValueError("a parse failure requires a non-empty error")

    @property
    def is_success(self) -> bool:
        return self.record is not None and self.error is None

    @classmethod
    def success(cls, record: AccessLogRecord) -> "ParseResult":
        return cls(record=record, error=None)

    @classmethod
    def failure(cls, error: str) -> "ParseResult":
        if not error:
            raise ValueError("a parse failure requires a non-empty error")
        return cls(record=None, error=error)


class CombinedLogParser:
    def parse(self, line: str) -> ParseResult:
        if not line or not line.rstrip("\r\n"):
            return ParseResult.failure("line is empty")

        match = _LOG_LINE_PATTERN.fullmatch(line.rstrip("\r\n"))
        if match is None:
            return ParseResult.failure("line does not match Combined Log Format")

        fields = match.groupdict()

        try:
            ip_address(fields["client_ip"])
        except ValueError:
            return ParseResult.failure("client IP is invalid")

        timestamp = self._parse_timestamp(fields["timestamp"])
        if timestamp is None:
            return ParseResult.failure("timestamp is invalid")

        request_parts = fields["request"].split()
        if len(request_parts) != 3:
            return ParseResult.failure("request line must contain method, target, and protocol")

        method, request_target, protocol = request_parts
        if _HTTP_METHOD_PATTERN.fullmatch(method) is None:
            return ParseResult.failure("HTTP method is invalid")
        if not request_target:
            return ParseResult.failure("request target is empty")
        if _HTTP_PROTOCOL_PATTERN.fullmatch(protocol) is None:
            return ParseResult.failure("HTTP protocol is invalid")

        status_code = int(fields["status_code"])
        if not 100 <= status_code <= 599:
            return ParseResult.failure("HTTP status code is outside the valid range")

        response_size_text = fields["response_size"]
        response_size = None if response_size_text == "-" else int(response_size_text)

        record = AccessLogRecord(
            client_ip=fields["client_ip"],
            timestamp=timestamp,
            method=method,
            request_target=request_target,
            protocol=protocol,
            status_code=status_code,
            response_size=response_size,
            referrer=self._unescape_quoted_field(fields["referrer"]),
            user_agent=self._unescape_quoted_field(fields["user_agent"]),
        )
        return ParseResult.success(record)

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        match = _TIMESTAMP_PATTERN.fullmatch(value)
        if match is None:
            return None

        parts = match.groupdict()
        month = _MONTHS.get(parts["month"])
        if month is None:
            return None

        offset_hour = int(parts["offset_hour"])
        offset_minute = int(parts["offset_minute"])
        if offset_hour > 23 or offset_minute > 59:
            return None

        offset = timedelta(hours=offset_hour, minutes=offset_minute)
        if parts["offset_sign"] == "-":
            offset = -offset

        try:
            return datetime(
                year=int(parts["year"]),
                month=month,
                day=int(parts["day"]),
                hour=int(parts["hour"]),
                minute=int(parts["minute"]),
                second=int(parts["second"]),
                tzinfo=timezone(offset),
            )
        except ValueError:
            return None

    @staticmethod
    def _unescape_quoted_field(value: str) -> str:
        return value.replace('\\"', '"').replace("\\\\", "\\")
