# Security Event Detector

A Python-based defensive security monitoring platform for authentication telemetry, behavioral detection, incident correlation, explainable risk scoring, investigation workflows, real-time monitoring, and persistent incident tracking.

## Features

- Ubuntu authentication log parsing
- SSH brute-force detection
- Multi-account authentication detection
- Sensitive privileged-command detection
- Account-management detection
- Configurable detection thresholds
- Event normalization
- Detection correlation
- Rolling-window streaming detection
- Duplicate detection suppression
- Streaming incident correlation
- Explainable 0-100 risk scoring
- Confidence assessment
- Investigation findings and rationale
- Recommended investigation actions
- JSON and Markdown reports
- Persistent JSONL live-incident storage
- Incident lifecycle management
- Automated unit and integration tests

## Architecture

```text
Authentication Log
       |
       v
   Ingestion
       |
       v
     Parsing
       |
       v
  Normalization
       |
       v
    Detection
       |
       +----------------------+
       |                      |
       v                      v
 Batch Analysis         Live Monitoring
       |                      |
       v                      v
 Correlation           Rolling Window
       |                      |
       +----------+-----------+
                  |
                  v
             Risk Scoring
                  |
                  v
          Investigation
                  |
          +-------+-------+
          |               |
          v               v
       Reports         Persistence
                          |
                          v
                    Incident Lifecycle
```

## Detection Rules

### AUTH-001 — SSH Brute-Force Pattern

Detects repeated failed SSH authentication attempts from the same source within a configured time window.

### AUTH-002 — Multi-Account Authentication Pattern

Detects authentication activity from one source against multiple accounts within a configured time window.

### SUDO-001 — Sensitive Privileged Execution

Identifies sensitive privileged commands and actions for investigation.

### ACCOUNT-001 — Account Management Activity

Detects bursts of account-management activity such as user and group changes.

Configuration is stored in `config/detections.json`.

## Risk Scoring

Incidents receive an explainable score from 0 to 100.

Risk factors include event volume, compressed activity windows, multiple detection rules, multiple accounts, and detection severity.

Overlapping evidence is deduplicated so the same underlying event is not double-counted.

## Investigation

Each incident can contain a finding, confidence, rationale, risk factors, supporting detections, recommended investigation actions, relevant accounts, and an event timeline.

The system separates observed evidence from analyst conclusions.

## Real-Time Monitoring

Run the live monitor with:

```bash
python3 -m src.cli.main --follow data/lab/live_auth.log
```

For an authorized Ubuntu system:

```bash
sudo python3 -m src.cli.main --follow /var/log/auth.log
```

The streaming pipeline is:

```text
log line -> parse -> normalize -> detect -> correlate -> score -> investigate -> persist
```

## Incident Correlation

Related detections from the same activity window can become one incident.

```text
AUTH-001 + AUTH-002
        |
        v
  INC-LIVE-0001
```

Exact duplicate detections are suppressed.

## Incident Lifecycle

```text
NEW -> OPEN -> INVESTIGATING -> RESOLVED
                         \\-> FALSE_POSITIVE
```

Status transitions are validated and retain timestamps and analyst notes.

## Reporting

Historical analysis generates:

`reports/security_report.json`

`reports/security_report.md`

Live monitoring generates or updates:

`reports/live_incidents.jsonl`

Generated runtime reports are excluded from Git.

## Running Historical Analysis

```bash
python3 -m src.cli.main data/samples/sample_auth.log
```

## Lab Demonstration

Controlled synthetic data is provided in `data/lab/live_auth.log`.

Example:

```bash
: > data/lab/live_auth.log
rm -f reports/live_incidents.jsonl
python3 -m src.cli.main --follow data/lab/live_auth.log
```

## Testing

Run the complete suite:

```bash
python3 -m unittest discover -s tests -v
```

The current v1.0 release contains 71 automated tests covering parsing, normalization, detection, correlation, scoring, investigation, streaming, persistence, lifecycle management, CLI behavior, and integration workflows.

## Requirements

- Python 3.10+
- Linux or WSL recommended for Ubuntu authentication-log support
- No external Python packages are required for the current implementation

## Security Boundaries

This project is intended for authorized defensive security analysis and educational use.

It does not perform unauthorized access, exploitation, automated retaliation, destructive remediation, or automatic blocking.

Only monitor systems and logs that you are authorized to inspect.

## Project Structure

```text
security-event-detector/
|-- config/
|   `-- detections.json
|-- data/
|   |-- lab/
|   |   `-- live_auth.log
|   `-- samples/
|       `-- sample_auth.log
|-- docs/
|   `-- RELEASE.md
|-- src/
|   |-- analysis.py
|   |-- config.py
|   |-- cli/
|   |   `-- main.py
|   |-- correlation/
|   |-- detection/
|   |-- ingestion/
|   |-- investigation/
|   |-- lifecycle/
|   |-- parsing/
|   |-- reporting/
|   |-- scoring/
|   |-- storage/
|   `-- streaming/
|-- tests/
|-- .gitignore
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
`-- SECURITY.md
```

## Release

### v1.0.0

The first stable portfolio release provides an end-to-end defensive monitoring workflow:

`ingest -> parse -> normalize -> detect -> correlate -> score -> investigate -> persist -> track lifecycle`

The v1.0 feature set is intentionally frozen. Larger additions such as dashboards, databases, enrichment, and additional telemetry integrations belong in future releases.

## Roadmap

- Dashboard visualization
- Database-backed persistence
- Additional telemetry formats
- Additional detection rules
- Threat-intelligence enrichment
- Improved log rotation handling
- Advanced false-positive analysis
- Packaging and deployment automation

## Security

See `SECURITY.md` for the security policy.

## Contributing

See `CONTRIBUTING.md` for contribution guidelines.

## License

MIT License.

Copyright (c) 2026 SamarthSom
