import json
from pathlib import Path

from src.correlation.models import Incident
from src.reporting.renderer import build_report_data


class IncidentStore:
    """Persist investigation incidents as JSON Lines."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save(self, incident: Incident) -> None:
        """
        Insert or update an incident by incident_id.
        """
        records = self.load_all()

        data = build_report_data(
            [incident]
        )[0]

        replaced = False

        for index, record in enumerate(records):
            if (
                record.get("incident_id")
                == incident.incident_id
            ):
                records[index] = data
                replaced = True
                break

        if not replaced:
            records.append(data)

        self._write_records(records)

    def load_all(self) -> list[dict]:
        """Load all persisted incidents."""
        if not self.path.exists():
            return []

        incidents = []

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line_number, line in enumerate(
                file,
                start=1,
            ):
                if not line.strip():
                    continue

                try:
                    incidents.append(
                        json.loads(line)
                    )
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid JSON at line "
                        f"{line_number} in {self.path}."
                    ) from error

        return incidents

    def _write_records(
        self,
        records: list[dict],
    ) -> None:
        with self.path.open(
            "w",
            encoding="utf-8",
        ) as file:
            for record in records:
                json.dump(
                    record,
                    file,
                    ensure_ascii=False,
                )
                file.write("\n")
