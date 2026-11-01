
from typing import Any


def analyze_brute_force(
    failed_attempts: int,
    threshold: int = 5,
) -> dict[str, Any]:
    """
    Deterministic baseline for repeated failed login attempts.
    This function analyzes an event; it does not execute actions.
    """

    if failed_attempts < 0:
        raise ValueError("failed_attempts cannot be negative")

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if failed_attempts >= threshold:
        return {
            "scenario": "brute_force",
            "classification": "suspicious",
            "severity": "high",
            "proposed_action": "escalate_for_review",
            "risk_score": 85,
            "reason": (
                f"{failed_attempts} failed login attempts "
                f"met or exceeded the threshold of {threshold}."
            ),
        }

    return {
        "scenario": "brute_force",
        "classification": "no_threshold_exceeded",
        "severity": "low",
        "proposed_action": "monitor",
        "risk_score": 15,
        "reason": (
            f"{failed_attempts} failed login attempts; "
            f"threshold is {threshold}."
        ),
    }
