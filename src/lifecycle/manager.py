from datetime import datetime, timezone

from src.lifecycle.models import (
    IncidentStatus,
    IncidentStatusChange,
)


class IncidentLifecycleManager:
    """Manage incident status transitions and history."""

    _allowed = {
        IncidentStatus.NEW: {
            IncidentStatus.OPEN,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.OPEN: {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.INVESTIGATING: {
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.RESOLVED: set(),
        IncidentStatus.FALSE_POSITIVE: set(),
    }

    def __init__(
        self,
        status: IncidentStatus = IncidentStatus.NEW,
        history: tuple[IncidentStatusChange, ...] = (),
    ) -> None:
        self.status = status
        self.history = history

    def transition(
        self,
        new_status: IncidentStatus,
        note: str = "",
    ) -> "IncidentLifecycleManager":
        if new_status == self.status:
            raise ValueError(
                f"Incident is already {self.status.value}."
            )

        if new_status not in self._allowed[self.status]:
            raise ValueError(
                f"Invalid transition: "
                f"{self.status.value} -> {new_status.value}."
            )

        change = IncidentStatusChange(
            status=new_status,
            changed_at=datetime.now(timezone.utc),
            note=note,
        )

        return IncidentLifecycleManager(
            status=new_status,
            history=self.history + (change,),
        )
