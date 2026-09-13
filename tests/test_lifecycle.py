import unittest

from src.lifecycle.manager import IncidentLifecycleManager
from src.lifecycle.models import IncidentStatus


class TestIncidentLifecycle(unittest.TestCase):

    def test_new_to_open(self):
        manager = IncidentLifecycleManager()

        updated = manager.transition(
            IncidentStatus.OPEN,
            "Analyst acknowledged incident.",
        )

        self.assertEqual(
            updated.status,
            IncidentStatus.OPEN,
        )

        self.assertEqual(
            len(updated.history),
            1,
        )

    def test_open_to_investigating(self):
        manager = IncidentLifecycleManager(
            status=IncidentStatus.OPEN,
        )

        updated = manager.transition(
            IncidentStatus.INVESTIGATING,
        )

        self.assertEqual(
            updated.status,
            IncidentStatus.INVESTIGATING,
        )

    def test_investigating_to_resolved(self):
        manager = IncidentLifecycleManager(
            status=IncidentStatus.INVESTIGATING,
        )

        updated = manager.transition(
            IncidentStatus.RESOLVED,
            "Investigation completed.",
        )

        self.assertEqual(
            updated.status,
            IncidentStatus.RESOLVED,
        )

    def test_new_can_be_false_positive(self):
        manager = IncidentLifecycleManager()

        updated = manager.transition(
            IncidentStatus.FALSE_POSITIVE,
            "Authorized security testing.",
        )

        self.assertEqual(
            updated.status,
            IncidentStatus.FALSE_POSITIVE,
        )

    def test_invalid_transition_is_rejected(self):
        manager = IncidentLifecycleManager(
            status=IncidentStatus.RESOLVED,
        )

        with self.assertRaises(ValueError):
            manager.transition(
                IncidentStatus.OPEN,
            )

    def test_same_status_is_rejected(self):
        manager = IncidentLifecycleManager()

        with self.assertRaises(ValueError):
            manager.transition(
                IncidentStatus.NEW,
            )


if __name__ == "__main__":
    unittest.main()
