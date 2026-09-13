import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BruteForceConfig:
    enabled: bool
    threshold: int
    window_seconds: int


@dataclass(frozen=True)
class PasswordSprayConfig:
    enabled: bool
    account_threshold: int
    window_seconds: int


@dataclass(frozen=True)
class SensitiveSudoConfig:
    enabled: bool


@dataclass(frozen=True)
class PrivilegedBurstConfig:
    enabled: bool
    threshold: int
    window_seconds: int


@dataclass(frozen=True)
class DetectionConfig:
    brute_force: BruteForceConfig
    password_spray: PasswordSprayConfig
    sensitive_sudo: SensitiveSudoConfig
    privileged_burst: PrivilegedBurstConfig


def _require_positive_integer(
    value: object,
    name: str,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            f"{name} must be an integer."
        )

    if value <= 0:
        raise ValueError(
            f"{name} must be greater than zero."
        )

    return value


def _require_boolean(
    value: object,
    name: str,
) -> bool:
    if not isinstance(value, bool):
        raise ValueError(
            f"{name} must be true or false."
        )

    return value


def load_detection_config(
    path: str = "config/detections.json",
) -> DetectionConfig:
    """Load and validate detection configuration."""
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    try:
        brute_force = data["brute_force"]
        password_spray = data["password_spray"]
        sensitive_sudo = data["sensitive_sudo"]
        privileged_burst = data["privileged_burst"]
    except KeyError as error:
        raise ValueError(
            f"Missing configuration section: {error.args[0]}"
        ) from error

    return DetectionConfig(
        brute_force=BruteForceConfig(
            enabled=_require_boolean(
                brute_force["enabled"],
                "brute_force.enabled",
            ),
            threshold=_require_positive_integer(
                brute_force["threshold"],
                "brute_force.threshold",
            ),
            window_seconds=_require_positive_integer(
                brute_force["window_seconds"],
                "brute_force.window_seconds",
            ),
        ),
        password_spray=PasswordSprayConfig(
            enabled=_require_boolean(
                password_spray["enabled"],
                "password_spray.enabled",
            ),
            account_threshold=_require_positive_integer(
                password_spray["account_threshold"],
                "password_spray.account_threshold",
            ),
            window_seconds=_require_positive_integer(
                password_spray["window_seconds"],
                "password_spray.window_seconds",
            ),
        ),
        sensitive_sudo=SensitiveSudoConfig(
            enabled=_require_boolean(
                sensitive_sudo["enabled"],
                "sensitive_sudo.enabled",
            ),
        ),
        privileged_burst=PrivilegedBurstConfig(
            enabled=_require_boolean(
                privileged_burst["enabled"],
                "privileged_burst.enabled",
            ),
            threshold=_require_positive_integer(
                privileged_burst["threshold"],
                "privileged_burst.threshold",
            ),
            window_seconds=_require_positive_integer(
                privileged_burst["window_seconds"],
                "privileged_burst.window_seconds",
            ),
        ),
    )
