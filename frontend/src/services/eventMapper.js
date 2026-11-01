
function getEventTitle(scenarioId) {
  if (!scenarioId) return "Unknown Security Event";

  return scenarioId
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function normalizeScenarioRun(run) {
  const event = run.event ?? {};
  const result = run.result ?? {};

  return {
    // Unique ID for React routing and rendering.
    id: String(run.id),

    scenarioId: run.scenario_id ?? "unknown",
    title: getEventTitle(run.scenario_id),

    timestamp: run.created_at ?? null,
    category: event.event_type ?? "unknown",

    // Preserve the original detector classification.
    classification:
      result.classification ??
      run.classification ??
      "unknown",

    severity:
      result.severity ??
      run.severity ??
      "unknown",

    riskScore:
      typeof result.details?.risk_score === "number"
        ? result.details.risk_score
        : typeof result.risk_score === "number"
          ? result.risk_score
          : null,

    injectionDetected:
      typeof result.injection_detected === "boolean"
        ? result.injection_detected
        : null,

    // This endpoint does not return an LLM proposal
    // or final policy decision.
    proposedAction: null,
    finalAction: null,

    status: "analysis_recorded",

    // Keep the source data for the investigation page.
    rawEvent: event,
    ruleResult: result,

    source: "stored_simulation",
  };
}

export function normalizeScenarioRuns(response) {
  // Supports an array or an object containing value.
  // PowerShell's ConvertTo-Json can wrap pipeline output.
  const records = Array.isArray(response)
    ? response
    : response?.value ?? [];

  if (!Array.isArray(records)) {
    throw new Error(
      "Unexpected scenario-runs API response format."
    );
  }

  return records.map(normalizeScenarioRun);
}
