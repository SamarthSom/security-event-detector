# Security Event Detector

A Python-based defensive security project that analyzes authentication logs, detects suspicious activity, assigns severity, and produces investigation reports.

## Features

* Parses structured authentication logs
* Detects repeated SSH authentication failures
* Detects authentication attempts against multiple accounts
* Assigns severity levels
* Displays detections in the terminal
* Generates JSON reports
* Generates Markdown investigation reports
* Includes automated unit tests

## Detection Rules

### AUTH-BRUTE-FORCE

Triggers when an IP address produces at least five failed SSH login attempts within 60 seconds.

### AUTH-MULTI-ACCOUNT

Triggers when an IP address attempts authentication against at least four different accounts within 60 seconds.

These rules are intentionally simple and are designed for educational purposes.

## Project Structure

```text
security-event-detector/
├── data/
│   └── sample_auth.log
├── reports/
├── src/
│   ├── detector.py
│   ├── main.py
│   ├── parser.py
│   └── reporter.py
├── tests/
│   └── test_detector.py
└── README.md
```

## Requirements

* Python 3.10+
* No external Python packages are required

## Running the Detector

From the project root:

```bash
python3 -m src.main data/sample_auth.log
```

Reports will be generated inside:

```text
reports/
```

## Running the Tests

```bash
python3 -m unittest discover -s tests
```

## Example Detections

A detection can look like:

```text
[HIGH] AUTH-BRUTE-FORCE
Source IP: 192.168.1.50
5 failed SSH logins from 192.168.1.50 within 60 seconds.
```

## Security Note

This project uses synthetic log data for educational purposes. It should only be used for authorized defensive analysis and testing.

## Future Development

Potential future improvements include:

* configurable detection rules
* IP reputation integration using an approved threat-intelligence source
* CSV log support
* additional authentication detections
* dashboard visualization
* database storage
* scheduled monitoring
* improved false-positive handling
