# Security Event Detector

A small Python security monitoring project for authentication logs.

It started as a simple log parser and grew into a complete little detection pipeline: parse events, normalize them, detect suspicious patterns, correlate related detections, score the incident, and produce something an analyst can actually investigate.

## What it does

- Parses synthetic and Ubuntu authentication logs
- Normalizes different log formats into a common `SecurityEvent`
- Detects SSH brute-force activity
- Detects authentication attempts against multiple accounts
- Detects sensitive sudo activity
- Detects account-management activity
- Correlates related detections into incidents
- Calculates explainable risk scores and confidence
- Produces investigation findings and recommended actions
- Follows a growing log in near real time
- Suppresses duplicate streaming alerts
- Persists live incidents as JSONL
- Tracks basic incident lifecycle states
- Generates JSON and Markdown reports
## Quick start

Python 3.10+ is required. The current project has no external Python package requirements.

Analyze a sample log:

```bash
python3 -m src.cli.main data/samples/sample_auth.log
```

Run the live lab monitor:

```bash
python3 -m src.cli.main --follow data/lab/live_auth.log
```

Run the full test suite:

```bash
python3 -m unittest discover -s tests -v
```

## How it works

```text
log line
   -> parse
   -> normalize
   -> detect
   -> correlate
   -> risk score
   -> investigate
   -> persist
```

The `SecurityEvent` model is the common boundary between parsing and detection. Parsers can understand different log formats while the detection engine works with one consistent event representation.
## A few problems I had to solve

The interesting part of this project was not getting the first detection to fire. It was making the system behave correctly once several pieces started interacting.

### Duplicate streaming alerts

A rolling detector can keep seeing the same pattern as new events arrive. Without state, the same detection would be emitted repeatedly. The streaming detector therefore keeps track of detections it has already emitted and suppresses exact duplicates.

### Overlapping evidence

Two rules can reference the same underlying events.

For example:

```text
AUTH-001 -> events A B C D E
AUTH-002 -> events A B C D E F G H
```

Simply adding those counts would give 13 supporting events even though there are only 8 unique events. The scoring path now deduplicates the underlying evidence before calculating event-volume-related risk.

### Correlation

Two detections from the same source can be different signals from the same activity. The streaming correlator can combine related detections into one incident when their source and timing match the configured correlation window.

```text
AUTH-001 + AUTH-002
        |
        v
   one incident
```

### Batch vs streaming

The project supports both completed-log analysis and near-real-time monitoring while sharing the same parsing, normalization, detection, scoring, and investigation concepts.
## Risk scoring

Incidents receive a 0-100 prioritization score.

Possible factors include:

- multiple detection rules
- event volume
- compressed activity windows
- multiple accounts
- detection severity

The score is not a probability of compromise. A 90/100 incident means the current scoring model considers the activity a high investigation priority.

## Investigation output

An incident can include:

- finding
- confidence
- rationale
- risk factors
- contributing detections
- recommended investigation actions
- accounts involved
- event timeline

The system is intentionally cautious about claims. It reports observed evidence and recommended investigation steps rather than declaring that a compromise has been proven.

## Incident lifecycle

```text
NEW -> OPEN -> INVESTIGATING -> RESOLVED
                         \\-> FALSE_POSITIVE
```

Lifecycle transitions are validated and can retain timestamps and notes.
## Known limitations

This is a v1.0 portfolio project, not a full SIEM or enterprise SOC platform.

Current limitations include:

- rule-based detection
- limited telemetry formats
- in-memory streaming state
- JSONL persistence rather than a database
- no centralized multi-host ingestion
- no threat-intelligence enrichment
- no dedicated SOC dashboard
- no automatic blocking or remediation

These are deliberate v1.0 boundaries and also define the direction of future work.

## Testing

The project currently passes 71 automated tests covering parsing, normalization, detection, correlation, scoring, investigation, streaming, persistence, lifecycle management, CLI behavior, and integration workflows.

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

```text
config/       detection configuration
data/         sample and controlled lab logs
docs/         release documentation
src/
  parsing/    parsers and normalization
  detection/  detection rules and engine
  correlation/ incident correlation
  streaming/  rolling detection and live correlation
  scoring/    risk assessment
  investigation/ analyst findings
  lifecycle/  incident state management
  storage/    persistent incident records
  reporting/  JSON and Markdown reports
tests/        automated tests
```

## Safe use

Use this project only against systems and logs you are authorized to inspect.

It is designed for defensive analysis and education. It does not perform unauthorized access, exploitation, automatic retaliation, or destructive remediation.

## v1.0.0

The first stable release provides an end-to-end defensive monitoring workflow:

`ingest -> parse -> normalize -> detect -> correlate -> score -> investigate -> persist`

## Contributing

See `CONTRIBUTING.md`.

## Security

See `SECURITY.md`.

## License

MIT License.

Copyright (c) 2026 SamarthSom
