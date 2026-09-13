from src.config import DetectionConfig, load_detection_config
from src.detection.models import Detection
from src.detection.rules import (
    detect_brute_force,
    detect_password_spray,
    detect_privileged_burst,
    detect_sensitive_sudo,
)
from src.parsing.models import SecurityEvent


def run_detections(
    events: list[SecurityEvent],
    config: DetectionConfig | None = None,
) -> list[Detection]:
    """Run enabled detection rules using supplied configuration."""
    if config is None:
        config = load_detection_config()

    detections = []

    if config.brute_force.enabled:
        detections.extend(
            detect_brute_force(
                events,
                threshold=config.brute_force.threshold,
                window_seconds=config.brute_force.window_seconds,
            )
        )

    if config.password_spray.enabled:
        detections.extend(
            detect_password_spray(
                events,
                account_threshold=(
                    config.password_spray.account_threshold
                ),
                window_seconds=(
                    config.password_spray.window_seconds
                ),
            )
        )

    if config.sensitive_sudo.enabled:
        detections.extend(
            detect_sensitive_sudo(events)
        )

    if config.privileged_burst.enabled:
        detections.extend(
            detect_privileged_burst(
                events,
                threshold=config.privileged_burst.threshold,
                window_seconds=(
                    config.privileged_burst.window_seconds
                ),
            )
        )

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    detections.sort(
        key=lambda detection: (
            severity_order.get(
                detection.severity,
                0,
            ),
            detection.detected_at,
        ),
        reverse=True,
    )

    return detections
