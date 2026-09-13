import time
from pathlib import Path
from typing import Iterator


def follow_file(
    path: str,
    poll_interval: float = 0.5,
) -> Iterator[str]:
    """
    Follow a growing text file and yield newly appended lines.

    Existing content is processed once. After reaching the current
    end of the file, the function waits for additional data.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Path is not a file: {file_path}"
        )

    with file_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        while True:
            line = file.readline()

            if line:
                if line.strip():
                    yield line.rstrip("\n")
                continue

            time.sleep(poll_interval)
