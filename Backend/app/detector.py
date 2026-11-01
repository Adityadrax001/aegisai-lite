import math
import re
import unicodedata
from typing import Any

# Classifications the detector can return.
SUSPICIOUS = "suspicious"
BENIGN = "benign"
INDETERMINATE = "indeterminate"  # malformed / unsupported input, needs review

# Network rule tuning.
VOLUME_SPIKE_RATIO = 5  # bytes_out vs baseline
MIN_SPIKE_BYTES = 100_000_000  # ignore spikes smaller than ~100 MB
OFF_HOURS_START = 22  # 22:00 up to 05:59 local time
OFF_HOURS_END = 6

# Prompt-injection indicators, grouped by what the text is TRYING TO DO.
# Each pattern is matched against normalized (lower-case) text. A string is
# flagged if any pattern in any group matches. The groups exist so each rule
# can be explained, not so the detector reports a reason (the output format
# is unchanged).
#
# Design rule: an override verb alone ("ignore", "disregard") is NOT enough,
# because benign notes say "ignore the earlier ticket" all the time. The thing
# being ignored must be instruction-like (instructions, prompt, rules, ...).
_INJECTION_GROUPS: dict[str, list[re.Pattern]] = {
    # 1. Tell the model to drop what it was told.
    "override_instructions": [
        re.compile(
            r"\b(ignore|disregard|forget)\b "
            r"(all |any |the |your |my |these |those )*"
            r"(previous |prior |above |earlier |preceding )+"
            r"(instructions?|prompts?|rules|guidelines|directions|constraints)\b"
        ),
        re.compile(  # "ignore the instructions above"
            r"\b(ignore|disregard|forget)\b (all |any |the |your )*"
            r"(instructions?|prompts?|rules|guidelines) "
            r"(above|before|earlier|previously)\b"
        ),
        re.compile(  # "forget everything you were told"
            r"\b(forget|ignore|disregard)\b "
            r"(everything|all of that|all that) (you|above|before|i|we|that)\b"
        ),
        # The same idea in Spanish, French and German.
        re.compile(
            r"\b(ignora|ignorar|olvida|descarta)\b "
            r"(todas |todo |las |los |tus |sus )*"
            r"(instrucciones|indicaciones|reglas) (anteriores|previas)\b"
        ),
        re.compile(
            r"\b(ignore[zr]?|oublie[zr]?)\b "
            r"(toutes |tous |les |vos |tes )*"
            r"(instructions|consignes|r[eè]gles) (pr[eé]c[eé]dentes|ant[eé]rieures)\b"
        ),
        re.compile(
            r"\b(ignoriere|ignorieren|vergiss)\b (alle |die |deine |ihre )*"
            r"(vorherigen|früheren|bisherigen) (anweisungen|instruktionen|regeln)\b"
        ),
    ],
    # 2. Dictate the verdict.
    "steer_verdict": [
        re.compile(r"\bclassify this (event |alert |log )?as\b"),
        re.compile(  # "report this event as a critical incident"
            r"\b(classify|mark|label|report|treat|rate|flag|consider|record)\b "
            r"(this|the|that) (event|alert|log|login|activity|incident|record|"
            r"entry|traffic|transfer|request|connection|attempt)\b.{0,10}?"
            r"\b(as|to be|being)\b (a |an )?"
            r"(benign|harmless|false positive|critical|malicious|no threat|low|high)\b"
        ),
        re.compile(  # "the classification for this event must be benign"
            r"\b(classification|verdict|assessment|conclusion)\b.{0,30}"
            r"\b(must|should|has to|needs to|shall) be\b.{0,6}?"
            r"\b(benign|malicious|suspicious|harmless|critical)\b"
        ),
        re.compile(  # output-format spoof: classification=benign
            r'\b(classification|verdict|assessment)"?\s*[=:]\s*"?'
            r"(benign|malicious|suspicious|harmless)\b"
        ),
        re.compile(  # "respond only with ..."
            r"\b(respond|reply|answer|output|return)\b (only |just )?(with|in)\b"
            r".{0,40}\b(classification|verdict|benign|malicious)\b"
        ),
    ],
    # 3. Claim authority to shut the alert down.
    "claim_authority": [
        re.compile(  # note to analyst ... close/ignore/false positive
            r"\bnote to (the )?(analyst|reviewer|assistant|model|ai|llm|soc)\b"
            r".{0,100}\b(false positive|close|ignore|skip|approved|"
            r"whitelisted?|no action)\b"
        ),
        re.compile(r"\b(system|security|developer) override\b ?[:!\-]"),
        re.compile(
            r"\bclose (it|this|the (alert|event|ticket|case)) without "
            r"(any |further )?(review|investigation|analysis)\b"
        ),
    ],
    # 4. Talk to the model directly, or change its role.
    "address_the_model": [
        re.compile(r"\byou are now\b"),
        re.compile(r"\b(developer|god|dan) mode\b"),
        re.compile(
            r"\b(if you are|as) an? "
            r"(ai|llm|language model|large language model|ai assistant|chatbot)\b"
        ),
        re.compile(
            r"\b(attention|dear|hey|hello) "
            r"(ai|llm|assistant|model|chatbot|gpt|claude|deepseek)\b"
        ),
    ],
    # 5. Ask for the prompt or for evaluation data.
    "request_hidden_data": [
        re.compile(
            r"\b(reveal|show|print|output|repeat|leak|display|disclose|"
            r"summari[sz]e|include|tell me)\b.{0,40}"
            r"\b(system|hidden|initial|original|developer|secret) "
            r"(prompt|instructions?|message)\b"
        ),
        re.compile(
            r"\b(reveal|show|print|output|leak|display|disclose|include|"
            r"tell me)\b.{0,50}\b(hidden|secret|internal|confidential)\b"
            r".{0,15}\b(labels?|answers?|truth|keys?)\b"
        ),
        re.compile(
            r"\b(reveal|show|print|include|output|leak|display|disclose)\b"
            r".{0,40}\b(ground[- ]truth|evaluation labels?|"
            r"expected (labels?|answers?|output|classification)|"
            r"correct (labels?|answers?))\b"
        ),
    ],
    # 6. Fake the structure of the prompt: tags, chat tokens, roles.
    "role_or_markup_spoof": [
        re.compile(r"</?\s*(event|instructions?|assistant|prompt)\b[^>]*>"),
        re.compile(r"\[/?(inst|system|assistant)\]"),
        re.compile(r"<\|(im_start|im_end|system|endoftext)\|>"),
        re.compile(r'"role"\s*:\s*"(system|assistant|developer)"'),
    ],
}

# For text written as "i g n o r e  p r e v i o u s ..." we remove the spaces
# and look for this one phrase, since word boundaries are gone.
_SQUASHED_OVERRIDE = re.compile(
    r"(ignore|disregard|forget)(all|any|the|your)*"
    r"(previous|prior|above|earlier|preceding)+"
    r"(instructions?|prompts?|rules|guidelines|directions)"
)

# Common digit/symbol swaps used to dodge keyword filters (1gn0re -> ignore).
_LEET = str.maketrans("013457@$", "oieastas")

_MAX_SCAN_DEPTH = 5
_MAX_SCAN_CHARS = 10_000


class _InvalidEvent(Exception):
    """Raised by a rule when the event is malformed."""


# ---------------------------------------------------------------- validation


def _require(event: dict[str, Any], fields: tuple[str, ...]) -> None:
    missing = [f for f in fields if f not in event]
    if missing:
        raise _InvalidEvent(f"missing required field(s): {', '.join(missing)}")


def _int(event: dict[str, Any], key: str, minimum: int) -> int:
    value = event[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _InvalidEvent(f"{key} must be an integer")
    if value < minimum:
        raise _InvalidEvent(f"{key} must be >= {minimum}")
    return value


def _number(event: dict[str, Any], key: str) -> float:
    value = event[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _InvalidEvent(f"{key} must be a number")
    if not math.isfinite(value) or value < 0:
        raise _InvalidEvent(f"{key} must be a finite, non-negative number")
    return value


def _bool(event: dict[str, Any], key: str) -> bool:
    value = event[key]
    if not isinstance(value, bool):
        raise _InvalidEvent(f"{key} must be a boolean")
    return value


# --------------------------------------------------------------------- rules


def _rule_login(event: dict[str, Any]) -> dict[str, Any]:
    _require(event, ("failed_attempts", "threshold"))
    failed = _int(event, "failed_attempts", 0)
    threshold = _int(event, "threshold", 1)

    details = {"failed_attempts": failed, "threshold": threshold}
    if failed >= threshold:
        return {
            "classification": SUSPICIOUS,
            "severity": "high",
            "indicators": ["failed_logins_at_or_above_threshold"],
            "reason": (
                f"{failed} failed login attempts met or exceeded "
                f"the threshold of {threshold}."
            ),
            "details": details,
        }
    return {
        "classification": BENIGN,
        "severity": "low",
        "indicators": [],
        "reason": (
            f"{failed} failed login attempts were below "
            f"the threshold of {threshold}."
        ),
        "details": details,
    }


def _rule_network(event: dict[str, Any]) -> dict[str, Any]:
    _require(
        event,
        (
            "bytes_out",
            "baseline_bytes_out",
            "destination_known",
            "scheduled",
            "local_hour",
        ),
    )
    bytes_out = _number(event, "bytes_out")
    baseline = _number(event, "baseline_bytes_out")
    destination_known = _bool(event, "destination_known")
    scheduled = _bool(event, "scheduled")
    hour = _int(event, "local_hour", 0)
    if hour > 23:
        raise _InvalidEvent("local_hour must be between 0 and 23")

    # A zero baseline is treated as 1 byte so any real transfer is a spike.
    ratio = bytes_out / max(baseline, 1)
    volume_spike = bytes_out >= MIN_SPIKE_BYTES and ratio >= VOLUME_SPIKE_RATIO
    off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END

    # Weighted indicators. Off-hours only counts when the transfer is not
    # scheduled, since scheduled jobs such as backups normally run at night.
    score = 0
    indicators = []
    if not destination_known:
        score += 2
        indicators.append("unrecognized_destination")
    if volume_spike:
        score += 2
        indicators.append("volume_spike_vs_baseline")
    if not scheduled:
        score += 1
        indicators.append("unscheduled_transfer")
        if off_hours:
            score += 1
            indicators.append("off_hours_unscheduled")

    details = {
        "bytes_out": bytes_out,
        "baseline_bytes_out": baseline,
        "volume_ratio": round(ratio, 2),
        "risk_score": score,
    }
    if score >= 3:
        return {
            "classification": SUSPICIOUS,
            "severity": "high" if score >= 5 else "medium",
            "indicators": indicators,
            "reason": (
                f"Outbound transfer risk score {score} (threshold 3): "
                + ", ".join(indicators)
                + "."
            ),
            "details": details,
        }
    return {
        "classification": BENIGN,
        "severity": "low",
        "indicators": indicators,
        "reason": (
            f"Outbound transfer risk score {score} is below the "
            "threshold of 3."
        ),
        "details": details,
    }


def _rule_admin(event: dict[str, Any]) -> dict[str, Any]:
    _require(
        event,
        ("change_approved", "mfa_verified", "within_maintenance_window"),
    )
    approved = _bool(event, "change_approved")
    mfa = _bool(event, "mfa_verified")
    in_window = _bool(event, "within_maintenance_window")

    # Missing controls are weighted: approval and MFA matter most.
    score = 0
    indicators = []
    if not approved:
        score += 2
        indicators.append("no_approved_change")
    if not mfa:
        score += 2
        indicators.append("mfa_not_verified")
    if not in_window:
        score += 1
        indicators.append("outside_maintenance_window")

    details = {"control_gap_score": score}
    if score >= 2:
        return {
            "classification": SUSPICIOUS,
            "severity": "high" if score >= 4 else "medium",
            "indicators": indicators,
            "reason": (
                f"Administrative action control-gap score {score} "
                "(threshold 2): " + ", ".join(indicators) + "."
            ),
            "details": details,
        }
    return {
        "classification": BENIGN,
        "severity": "low",
        "indicators": indicators,
        "reason": (
            "Administrative action had an approved change, verified "
            "MFA, and ran in the maintenance window."
            if score == 0
            else f"Administrative action control-gap score {score} is "
            "below the threshold of 2."
        ),
        "details": details,
    }


_RULES = {
    "login_activity": _rule_login,
    "network_activity": _rule_network,
    "admin_activity": _rule_admin,
}


# ---------------------------------------------------------- injection scan


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text[:_MAX_SCAN_CHARS])
    # Drop invisible format characters (zero-width spaces and similar).
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return re.sub(r"\s+", " ", text).lower()


def _is_spaced_out(text: str) -> bool:
    """True for text like 'i g n o r e ...' where most tokens are one letter."""
    tokens = text.split()
    if len(tokens) < 8:
        return False
    return sum(len(t) == 1 for t in tokens) / len(tokens) >= 0.7


def _injection_groups(text: str) -> set[str]:
    """Return the indicator groups that match this string (empty if none).

    The text is checked as written, with digit swaps undone (leetspeak),
    and, if it is spaced-out lettering, with the spaces removed.
    """
    normalized = _normalize(text)
    views = [normalized]
    decoded = normalized.translate(_LEET)
    if decoded != normalized:
        views.append(decoded)

    matched = {
        group
        for view in views
        for group, patterns in _INJECTION_GROUPS.items()
        if any(p.search(view) for p in patterns)
    }
    if _is_spaced_out(normalized) and _SQUASHED_OVERRIDE.search(
        normalized.replace(" ", "")
    ):
        matched.add("override_instructions")
    return matched


def _scan_injection(obj: Any, path: str = "", depth: int = 0) -> list[str]:
    """Return key paths of string values that look like hostile instructions.

    This only reports. It never changes the security classification, because
    untrusted text must not influence the verdict.
    """
    if depth > _MAX_SCAN_DEPTH:
        return []
    hits: list[str] = []
    if isinstance(obj, str):
        if _injection_groups(obj):
            hits.append(path or "<root>")
    elif isinstance(obj, dict):
        for key, value in obj.items():
            hits += _scan_injection(value, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            hits += _scan_injection(value, f"{path}[{i}]", depth + 1)
    return hits


# ---------------------------------------------------------------- public API


def detect_event(event: Any) -> dict[str, Any]:
    """Classify a simulated event with event-type-specific deterministic rules.

    Never raises on bad input: malformed or unsupported events return an
    "indeterminate" result. The input is not modified. The detector only sees
    the event, never ground truth.
    """
    if not isinstance(event, dict):
        return _build(None, _indeterminate("event must be a dictionary"), {}, [])

    injection_fields = _scan_injection(event)
    event_type = event.get("event_type")

    rule = _RULES.get(event_type) if isinstance(event_type, str) else None
    if rule is None:
        return _build(
            event_type if isinstance(event_type, str) else None,
            _indeterminate(
                "missing or unsupported event_type"
                if event_type is None or not isinstance(event_type, str)
                else f"unsupported event_type: {event_type[:50]!r}"
            ),
            event,
            injection_fields,
        )

    try:
        outcome = rule(event)
    except _InvalidEvent as exc:
        outcome = _indeterminate(f"invalid {event_type} event: {exc}")

    return _build(event_type, outcome, event, injection_fields)


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "classification": INDETERMINATE,
        "severity": "unknown",
        "indicators": [],
        "reason": reason,
        "details": {},
    }

def _build(
    event_type: str | None,
    outcome: dict[str, Any],
    event: dict[str, Any],
    injection_fields: list[str],
) -> dict[str, Any]:
    """Build a consistent response for API, database, and evaluation use."""

    details = outcome["details"]
    simulated = event.get("simulated")

    result = {
        # Architecture integration
        "scenario_id": event.get("scenario_id"),
        "event_type": event_type,

        # Rule-based detection output
        "classification": outcome["classification"],
        "severity": outcome["severity"],
        "indicators": outcome["indicators"],
        "reason": outcome["reason"],
        "details": details,

        # Separate prompt-injection assessment
        "injection_detected": bool(injection_fields),
        "injection_fields": injection_fields,

        # Simulation metadata
        "simulated": simulated if isinstance(simulated, bool) else None,
    }

    # Preserve compatibility with the earlier login detector's response.
    for field in ("failed_attempts", "threshold"):
        if field in details:
            result[field] = details[field]

    return result