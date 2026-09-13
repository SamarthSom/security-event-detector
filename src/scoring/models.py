from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFactor:
    name: str
    points: int
    explanation: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str
    confidence: str
    factors: tuple[RiskFactor, ...]
