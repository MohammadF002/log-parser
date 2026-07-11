# Access Log Analyzer

A standard-library-only Python command-line application for analyzing web server
access logs in Combined Log Format. It processes input incrementally, tolerates
malformed records, produces operational traffic statistics, and detects two
useful classes of anomalous behavior.

## Requirements

- Python 3.10 or newer
- No third-party runtime or test dependencies

The application can be run directly from the repository root. Installation is
not required.

## Quick start

Analyze a plain-text log and print the default human-readable report:

```console
python -m access_log_analyzer access.log/access.log
```

Run the test suite:

```console
python -m unittest discover -s tests -v
```

Show all CLI options:

```console
python -m access_log_analyzer --help
```

## Command-line usage

```text
python -m access_log_analyzer [OPTIONS] LOG_FILE
```

| Option | Description |
| --- | --- |
| `LOG_FILE` | Path to a plain-text or `.gz` access log. |
| `--top N` | Number of busiest endpoints to include. Default: `10`. |
| `--format text\|json` | Output format. Default: `text`. |
| `--since DATETIME` | Include records at or after this ISO-8601 datetime. |
| `--until DATETIME` | Include records before this ISO-8601 datetime. |
| `--login-failure-threshold N` | Flag IPs with at least this many `/login` 401 responses. Default: `20`. |

`--top` and `--login-failure-threshold` require positive integers. Time filter
values must include a timezone offset; `Z` is accepted for UTC. The time range
uses an inclusive start and an exclusive end: `[since, until)`.

### Examples

Report only the five busiest endpoints:

```console
python -m access_log_analyzer access.log/access.log --top 5
```

Analyze a gzip-compressed log directly:

```console
python -m access_log_analyzer access.log.gz
```

Produce machine-readable JSON:

```console
python -m access_log_analyzer access.log/access.log --format json
```

Analyze one UTC hour and return the three busiest endpoints as JSON:

```console
python -m access_log_analyzer access.log/access.log --since 2026-06-01T09:00:00Z --until 2026-06-01T10:00:00Z --top 3 --format json
```

Use a different suspicious-login threshold:

```console
python -m access_log_analyzer access.log/access.log --login-failure-threshold 50
```

The program returns exit code `0` after a successful analysis and `1` when the
input file cannot be read. Invalid command-line arguments are handled by
`argparse` and return exit code `2`.

## Input format

The parser accepts Combined Log Format records such as:

```text
203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"
```

Each valid record captures:

- client IPv4 or IPv6 address;
- timezone-aware timestamp;
- HTTP method, request target, and protocol;
- status code;
- response size, with `-` represented internally as no size;
- referrer and user agent.

The parser validates the record structure and important field types. Invalid or
incomplete lines are counted and skipped instead of terminating the analysis.
Input is decoded as UTF-8, with invalid byte sequences replaced so a damaged
user-agent field cannot crash a complete run.

## Report contents

Both output formats contain the same analysis:

- physical lines processed;
- valid and malformed record counts;
- records excluded by optional time filters;
- requests included in the analysis;
- exact unique client IP count;
- busiest endpoints;
- combined 4xx and 5xx error count and percentage;
- request totals per UTC hour;
- suspicious login activity;
- automatically detected 5xx spike intervals;
- measured execution time.

Query strings are excluded when endpoint traffic is aggregated. For example,
`/products?page=1` and `/products?page=2` are counted as the same endpoint.

The text report displays hourly traffic as a scaled histogram. JSON output uses
stable named fields and ISO-8601 timestamps, making it suitable for scripts and
other tools.

## Anomaly detection

### Suspicious login activity

The analyzer counts 401 responses from `/login` for every client IP. An IP is
reported when its count reaches `--login-failure-threshold`. Query strings on
the login endpoint are supported, and time filters are applied before detection.

### Automatic 5xx spike intervals

The spike detector uses an explainable robust baseline:

1. Group analyzed requests into one-minute UTC buckets.
2. Ignore buckets containing fewer than 20 requests.
3. Calculate each bucket's 5xx response rate.
4. Use the median rate as the baseline and median absolute deviation (MAD) as
   the variability measure.
5. Set the spike threshold to the largest of:
   - a 10% absolute 5xx rate;
   - the baseline plus five percentage points;
   - the baseline plus six MADs.
6. Merge consecutive anomalous minutes into incident intervals.

Each incident includes its inclusive start, exclusive end, request count, 5xx
count, aggregate error rate, and peak one-minute error rate.

## Architecture

The code uses a small layered streaming architecture:

```text
CLI
 ├── input reader ──> plain text or gzip line stream
 ├── analyzer
 │    ├── Combined Log parser
 │    ├── statistics accumulator
 │    └── anomaly detectors
 └── report formatter ──> text or JSON
```

The modules have focused responsibilities:

```text
access_log_analyzer/
├── __main__.py   Package entry point
├── cli.py        Arguments, orchestration, timing, and exit codes
├── readers.py    Plain-text and gzip input adapters
├── parser.py     Combined Log Format parsing and validation
├── analyzer.py   Single-pass aggregation and time filtering
├── detectors.py  Suspicious-login and 5xx-spike detection
├── models.py     Immutable domain and report models
└── report.py     Human-readable and JSON formatters
```

The CLI is the composition root. File handling and terminal output stay at the
edges, while the parser, analyzer, and detectors can be exercised using
in-memory iterables. This keeps the application logic independent of a specific
file source or presentation format.

## Important design decisions

### Streaming processing

The input is iterated once and records are analyzed immediately. The application
does not create a list containing the full file. Repeated records therefore do
not cause retained record objects to accumulate.

Exact statistics still require aggregated analytical state:

- a set of unique IP addresses;
- endpoint counters;
- hourly and minute-level counters;
- per-IP failed-login counters.

The streaming phase is `O(n)`, where `n` is the number of lines. Final ordering
adds `O(e log e + t log t)`, where `e` is the number of unique endpoints and `t`
is the number of time buckets. Memory complexity is `O(i + e + t)`, where `i`
is the number of unique IPs. The application retains counters and sets, not
complete log records.

### Explicit parsing results

Parsing returns a `ParseResult` containing either an immutable
`AccessLogRecord` or an error reason. The result prevents invalid states such as
simultaneously containing a record and an error. Malformed data is therefore an
expected outcome rather than an exception that interrupts the stream.

### Time handling

Input timestamps retain their timezone information. Aggregated hourly and
minute buckets are normalized to UTC so equivalent instants with different
offsets are not split into separate buckets.

### Standard library only

Parsing, CLI handling, gzip support, JSON serialization, statistics, and tests
all use Python's standard library. No library performs or assists with the core
log-parsing task.

## Testing

The test suite uses `unittest` and covers:

- valid IPv4 and IPv6 records;
- malformed and incomplete lines;
- timezone and response-size edge cases;
- single-pass aggregation;
- endpoint normalization and deterministic ranking;
- error-rate and UTC time-bucket calculations;
- inclusive/exclusive time-filter boundaries;
- plain-text and gzip readers;
- text and JSON reports;
- CLI success and failure paths;
- suspicious-login detection;
- automatic 5xx baseline, threshold, and interval grouping.

Run all tests from the repository root:

```console
python -m unittest discover -s tests -v
```

## Sample results and performance

For the supplied 500,000-line sample:

```text
Valid requests:       495,044
Malformed lines:        4,956
Unique client IPs:      4,001
4xx/5xx responses:     51,075
Error rate:            10.32%
```

The suspicious-login detector identifies one IP with 7,464 `/login` 401
responses. The automatic 5xx detector identifies an incident from
`2026-06-01T04:53:00Z` to `2026-06-01T05:23:00Z`, containing 10,353 server
errors among 25,494 requests.

Profiling initially measured approximately 7.5-7.7 seconds for the complete
sample. Bounded caches were then added for repeated IP validation, timestamp
parsing, request-field validation, quoted-field decoding, and endpoint
normalization. The same analysis subsequently measured approximately 4.9-5.35
seconds in the development environment. The CLI always reports the elapsed time
for the current machine and input.

## Implementation challenge

The main performance challenge was that apparently small validation operations
were repeated hundreds of thousands of times. Profiling showed that IP address
validation alone consumed several seconds, even though the sample contained only
4,001 unique client IPs. Many records also shared the same timestamp, protocol,
method, user agent, and endpoint.

The solution was to keep the strict validation while adding bounded LRU caches
only to the measured repeated operations. Bounded caches preserve predictable
memory behavior on high-cardinality or hostile input. Regression tests and
full-sample comparisons confirmed that the optimization did not change counts,
rankings, suspicious activity, or detected incident boundaries.

## Assumptions and limitations

- The client field must be a valid IPv4 or IPv6 address rather than a hostname.
- Records must follow Combined Log Format with quoted request, referrer, and
  user-agent fields.
- Gzip input is selected by a case-insensitive `.gz` filename suffix.
- ZIP archives are not read directly; provide a plain-text file or `.gz` stream.
- Exact unique-IP and endpoint counts require memory proportional to their
  cardinality, although complete records are never retained.
- Spike detection requires sufficient traffic and variation to establish a
  meaningful baseline; low-volume minute buckets are deliberately ignored.
