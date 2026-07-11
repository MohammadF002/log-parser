import json
from pathlib import Path

from .models import AnalysisResult


class TextReportFormatter:
    def __init__(self, top_count: int = 10, histogram_width: int = 40) -> None:
        if top_count < 1:
            raise ValueError("top endpoint count must be at least one")
        if histogram_width < 1:
            raise ValueError("histogram width must be at least one")
        self._top_count = top_count
        self._histogram_width = histogram_width

    def format(
        self,
        result: AnalysisResult,
        source_path: Path,
        elapsed_seconds: float,
    ) -> str:
        if elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")

        sections = (
            self._format_summary(result, source_path, elapsed_seconds),
            self._format_top_endpoints(result),
            self._format_hourly_traffic(result),
            self._format_suspicious_logins(result),
            self._format_server_error_spikes(result),
        )
        return "\n\n".join(sections)

    @staticmethod
    def _format_summary(
        result: AnalysisResult,
        source_path: Path,
        elapsed_seconds: float,
    ) -> str:
        return "\n".join(
            (
                "Access Log Analysis",
                "===================",
                f"Source:             {source_path}",
                f"Processed lines:    {result.processed_lines:,}",
                f"Valid requests:     {result.valid_requests:,}",
                f"Filtered requests:  {result.filtered_requests:,}",
                f"Analyzed requests:  {result.analyzed_requests:,}",
                f"Malformed lines:    {result.malformed_lines:,}",
                f"Unique client IPs:  {result.unique_ip_count:,}",
                f"Error requests:     {result.error_requests:,}",
                f"Error rate:         {result.error_rate_percent:.2f}%",
                f"Elapsed time:       {elapsed_seconds:.3f} seconds",
            )
        )

    def _format_top_endpoints(self, result: AnalysisResult) -> str:
        heading = f"Top {self._top_count} Endpoints"
        endpoint_traffic = result.top_endpoints(self._top_count)
        if not endpoint_traffic:
            return f"{heading}\n{'-' * len(heading)}\n(no valid requests)"

        rows = [heading, "-" * len(heading), "Rank     Requests  Endpoint"]
        rows.extend(
            f"{rank:>4}  {item.request_count:>11,}  {item.endpoint}"
            for rank, item in enumerate(endpoint_traffic, start=1)
        )
        return "\n".join(rows)

    def _format_hourly_traffic(self, result: AnalysisResult) -> str:
        heading = "Hourly Traffic (UTC)"
        if not result.hourly_traffic:
            return f"{heading}\n{'-' * len(heading)}\n(no valid requests)"

        peak_requests = max(item.request_count for item in result.hourly_traffic)
        rows = [heading, "-" * len(heading), "Hour                     Requests  Traffic"]
        for item in result.hourly_traffic:
            bar_length = max(
                1,
                round(item.request_count / peak_requests * self._histogram_width),
            )
            rows.append(
                f"{item.hour.isoformat():<25} "
                f"{item.request_count:>8,}  "
                f"{'#' * bar_length}"
            )
        return "\n".join(rows)

    @staticmethod
    def _format_suspicious_logins(result: AnalysisResult) -> str:
        heading = "Suspicious Login Activity"
        if not result.suspicious_login_activity:
            return f"{heading}\n{'-' * len(heading)}\n(none detected)"

        rows = [heading, "-" * len(heading), "401 Responses  Client IP"]
        rows.extend(
            f"{item.failure_count:>13,}  {item.client_ip}"
            for item in result.suspicious_login_activity
        )
        return "\n".join(rows)

    @staticmethod
    def _format_server_error_spikes(result: AnalysisResult) -> str:
        heading = "5xx Spike Detection"
        analysis = result.server_error_spike_analysis
        if analysis is None:
            return f"{heading}\n{'-' * len(heading)}\n(not available)"

        rows = [
            heading,
            "-" * len(heading),
            f"Baseline rate:  {analysis.baseline_error_rate_percent:.2f}%",
            f"Spike threshold: {analysis.threshold_error_rate_percent:.2f}%",
        ]
        if not analysis.incidents:
            rows.append("(none detected)")
            return "\n".join(rows)

        rows.extend(
            (
                "Start                      End                        "
                "Requests       5xx   Rate   Peak",
                *(
                    f"{incident.start.isoformat():<26} "
                    f"{incident.end.isoformat():<26} "
                    f"{incident.request_count:>8,} "
                    f"{incident.server_error_count:>9,} "
                    f"{incident.error_rate_percent:>6.2f}% "
                    f"{incident.peak_error_rate_percent:>6.2f}%"
                    for incident in analysis.incidents
                ),
            )
        )
        return "\n".join(rows)


class JsonReportFormatter:
    def __init__(self, top_count: int = 10) -> None:
        if top_count < 1:
            raise ValueError("top endpoint count must be at least one")
        self._top_count = top_count

    def format(
        self,
        result: AnalysisResult,
        source_path: Path,
        elapsed_seconds: float,
    ) -> str:
        if elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")

        report = {
            "source": str(source_path),
            "processed_lines": result.processed_lines,
            "valid_requests": result.valid_requests,
            "filtered_requests": result.filtered_requests,
            "analyzed_requests": result.analyzed_requests,
            "malformed_lines": result.malformed_lines,
            "unique_client_ips": result.unique_ip_count,
            "error_requests": result.error_requests,
            "error_rate_percent": result.error_rate_percent,
            "elapsed_seconds": elapsed_seconds,
            "top_endpoints": [
                {
                    "endpoint": item.endpoint,
                    "request_count": item.request_count,
                }
                for item in result.top_endpoints(self._top_count)
            ],
            "hourly_traffic": [
                {
                    "hour": item.hour.isoformat(),
                    "request_count": item.request_count,
                }
                for item in result.hourly_traffic
            ],
            "suspicious_login_activity": [
                {
                    "client_ip": item.client_ip,
                    "failure_count": item.failure_count,
                }
                for item in result.suspicious_login_activity
            ],
            "server_error_spike_analysis": self._server_error_spike_analysis(result),
        }
        return json.dumps(report, indent=2)

    @staticmethod
    def _server_error_spike_analysis(result: AnalysisResult) -> dict | None:
        analysis = result.server_error_spike_analysis
        if analysis is None:
            return None
        return {
            "bucket_minutes": analysis.bucket_minutes,
            "baseline_error_rate_percent": analysis.baseline_error_rate_percent,
            "threshold_error_rate_percent": analysis.threshold_error_rate_percent,
            "incidents": [
                {
                    "start": incident.start.isoformat(),
                    "end": incident.end.isoformat(),
                    "request_count": incident.request_count,
                    "server_error_count": incident.server_error_count,
                    "error_rate_percent": incident.error_rate_percent,
                    "peak_error_rate_percent": incident.peak_error_rate_percent,
                }
                for incident in analysis.incidents
            ],
        }
