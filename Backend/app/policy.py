
from typing import Any


ALLOWED_ACTIONS = {
    "monitor",
    "investigate",
    "escalate_for_review",
}



def apply_policy(
    event: dict[str, Any],
    proposal: dict[str, Any],
    detector_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Apply deterministic controls to an LLM proposal.
    Security actions are simulated and never executed.
    """
    from app.detector import detect_event

    if detector_result is None:
        detector_result = detect_event(event)

    injection_detected = bool(
        detector_result.get("injection_detected", False)
    )

    assessment = proposal.get("assessment")
    severity = proposal.get("severity")
    proposed_action = proposal.get("recommended_action")

    if (
        assessment not in {
            "malicious", "suspicious", "benign", "uncertain"
        }
        or severity not in {"low", "medium", "high", "critical"}
        or proposed_action not in ALLOWED_ACTIONS
    ):
        return {
            "approved": False,
            "proposed_action": proposed_action,
            "final_action": "escalate_for_review",
            "policy_reason": "Invalid or unsupported LLM proposal.",
            "injection_detected": injection_detected,
            "executed": False,
        }

    detector_classification = detector_result.get("classification")
    detector_severity = detector_result.get("severity")

    if assessment == "malicious":
        final_action = "escalate_for_review"
        reason = (
            "The LLM identified malicious activity; human review is required."
        )

    elif detector_severity in {"high", "critical"}:
        final_action = "escalate_for_review"
        reason = (
            "The deterministic detector reported high or critical severity; "
            "the LLM cannot downgrade this signal to monitoring."
        )

    elif severity in {"high", "critical"}:
        final_action = "escalate_for_review"
        reason = "High or critical LLM severity requires human review."

    elif assessment == "suspicious":
        final_action = "investigate"
        reason = (
            "A credible security concern requires investigation, "
            "but malicious intent is not established."
        )

    elif assessment == "uncertain":
        final_action = "investigate"
        reason = "Insufficient or conflicting evidence requires investigation."

    elif detector_classification == "suspicious":
        final_action = "investigate"
        reason = (
            "The deterministic detector identified suspicious activity; "
            "investigation is required despite the LLM's benign assessment."
        )

    elif detector_classification == "indeterminate":
        final_action = "escalate_for_review"
        reason = (
            "The deterministic detector could not reliably assess the event; "
            "human review is required."
        )

    elif injection_detected:
        final_action = "investigate"
        reason = (
            "Potential prompt injection detected; preserve the event "
            "for review without trusting embedded instructions."
        )

    else:
        final_action = "monitor"
        reason = "No escalation condition was triggered by the policy."

    return {
        "approved": final_action == proposed_action,
        "proposed_action": proposed_action,
        "final_action": final_action,
        "policy_reason": reason,
        "injection_detected": injection_detected,
        "executed": False,
    }


def _contains_injection_indicator(event: dict[str, Any]) -> bool:
    """
    Use the existing detector's injection scan without changing its verdict.
    """
    from app.detector import detect_event

    result = detect_event(event)
    return result["injection_detected"]
