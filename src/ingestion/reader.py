from pathlib import Path


def read_log_file(path: str) -> list[str]:
    """Read a text log file and return its non-empty lines."""
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    if not log_path.is_file():
        raise ValueError(f"Path is not a file: {log_path}")

    with log_path.open("r", encoding="utf-8", errors="replace") as file:
        return [line.rstrip("\n") for line in file if line.strip()]
