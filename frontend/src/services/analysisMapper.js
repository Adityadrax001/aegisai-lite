
export function normalizeLLMAnalysis(record) {
  if (!record || typeof record !== "object") {
    throw new Error("Invalid LLM analysis record.");
  }

  const proposal = record.llm_proposal ?? {};

  return {
    id: String(record.analysis_id),

    scenarioId: record.scenario_id ?? null,

    modelName: record.model_name ?? "Unknown model",

    timestamp: record.created_at ?? null,

    assessment: proposal.assessment ?? null,

    severity: proposal.severity ?? null,

    confidence:
      typeof proposal.confidence === "number"
        ? proposal.confidence
        : null,

    evidence: Array.isArray(proposal.evidence)
      ? proposal.evidence
      : [],

    explanation: proposal.explanation ?? null,

    recommendedAction:
      proposal.recommended_action ?? null,

    executed:
      typeof record.executed === "boolean"
        ? record.executed
        : null,

    source: "stored_llm_analysis",
  };
}

export function normalizeLLMAnalyses(response) {
  const records = Array.isArray(response)
    ? response
    : response?.value ?? [];

  if (!Array.isArray(records)) {
    throw new Error(
      "Unexpected LLM analyses API response format."
    );
  }

  return records.map(normalizeLLMAnalysis);
}
