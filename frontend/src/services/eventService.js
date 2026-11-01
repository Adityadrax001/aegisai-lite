
import { apiRequest } from "./apiClient";

import {
  normalizeScenarioRuns,
} from "./eventMapper";

import {
  normalizeLLMAnalyses,
} from "./analysisMapper";

export const eventService = {
  async getScenarioRuns(signal) {
    const response = await apiRequest(
      "/api/scenarios/runs",
      { signal }
    );

    return normalizeScenarioRuns(response);
  },

  async getLLMAnalyses(signal) {
    const response = await apiRequest(
      "/api/scenarios/llm-analyses",
      { signal }
    );

    return normalizeLLMAnalyses(response);
  },
};
