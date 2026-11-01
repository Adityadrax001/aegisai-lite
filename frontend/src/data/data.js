
import {
  Activity,
  ShieldAlert,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";

// ==========================================
// AEGIS AI — MOCK DATA
// Historical evaluation + illustrative demos
// NOT LIVE BACKEND DATA
// ==========================================

export const dataSource = {
  mode: "demo",
  label: "Demo / Historical Evaluation",
  isLive: false,
};

// ==========================================
// DASHBOARD METRIC CARDS
// Values from the previously reported
// System C evaluation.
// ==========================================

export const dashboardMetrics = [
  {
    id: "total-events",
    title: "Total Scenarios",
    value: 146,
    description: "Evaluation dataset size",
    icon: Activity,
    status: "neutral",
    color: "white",
  },
  {
    id: "malicious-events",
    title: "Malicious Scenarios",
    value: 53,
    description: "Ground-truth malicious cases",
    icon: ShieldAlert,
    status: "danger",
    color: "coral",
  },
  {
    id: "injection-events",
    title: "Injection Detections",
    value: 17,
    description: "Latest System C evaluation",
    icon: ScanSearch,
    status: "warning",
    color: "lime",
  },
  {
    id: "execution-violations",
    title: "Execution Violations",
    value: 0,
    description: "Latest System C evaluation",
    icon: ShieldCheck,
    status: "success",
    color: "blue",
  },
];

// ==========================================
// SECURITY EVENTS
// Illustrative records using known
// scenario types; not actual saved runs.
// ==========================================

export const securityEvents = [
  {
    id: "demo-001",
    scenarioId: "brute_force",
    timestamp: "2026-10-27T09:10:00+05:30",
    category: "authentication",
    title: "Repeated Failed Login Attempts",
    classification: "malicious",
    severity: "high",
    riskScore: 85,
    injectionDetected: false,
    status: "needs_review",
    proposedAction: "monitor",
    finalAction: "escalate_for_review",
  },
  {
    id: "demo-002",
    scenarioId: "normal_login",
    timestamp: "2026-10-27T09:15:00+05:30",
    category: "authentication",
    title: "Normal User Login",
    classification: "benign",
    severity: "low",
    riskScore: 15,
    injectionDetected: false,
    status: "monitored",
    proposedAction: "monitor",
    finalAction: "monitor",
  },
  {
    id: "demo-003",
    scenarioId: "suspicious_outbound",
    timestamp: "2026-10-27T09:25:00+05:30",
    category: "network",
    title: "Suspicious Outbound Connection",
    classification: "malicious",
    severity: "high",
    riskScore: 90,
    injectionDetected: false,
    status: "needs_review",
    proposedAction: "escalate_for_review",
    finalAction: "escalate_for_review",
  },
  {
    id: "demo-004",
    scenarioId: "benign_admin",
    timestamp: "2026-10-27T09:35:00+05:30",
    category: "administration",
    title: "Authorized Administrator Activity",
    classification: "benign",
    severity: "low",
    riskScore: 10,
    injectionDetected: false,
    status: "monitored",
    proposedAction: "monitor",
    finalAction: "monitor",
  },
  {
    id: "demo-005",
    scenarioId: "prompt_injection",
    timestamp: "2026-10-27T09:45:00+05:30",
    category: "prompt_injection",
    title: "Embedded Instruction Attempt",
    classification: "benign",
    severity: "medium",
    riskScore: 45,
    injectionDetected: true,
    status: "investigating",
    proposedAction: "monitor",
    finalAction: "investigate",
  },
  {
    id: "demo-006",
    scenarioId: "benign_backup",
    timestamp: "2026-10-27T09:55:00+05:30",
    category: "system",
    title: "Scheduled Backup Activity",
    classification: "benign",
    severity: "low",
    riskScore: 10,
    injectionDetected: false,
    status: "monitored",
    proposedAction: "monitor",
    finalAction: "monitor",
  },
];

// ==========================================
// EVENT SEVERITY DISTRIBUTION
// Illustrative chart data, not measured.
// ==========================================

export const severityDistribution = [
  { name: "Critical", value: 5, color: "#D73838" },
  { name: "High", value: 21, color: "#FF8A70" },
  { name: "Medium", value: 38, color: "#FFDA66" },
  { name: "Low", value: 82, color: "#91B9FF" },
];

// ==========================================
// EVENT TREND
// Illustrative seven-day sample.
// ==========================================

export const threatTrend = [
  { date: "Oct 21", malicious: 4, benign: 12 },
  { date: "Oct 22", malicious: 6, benign: 10 },
  { date: "Oct 23", malicious: 3, benign: 15 },
  { date: "Oct 24", malicious: 8, benign: 11 },
  { date: "Oct 25", malicious: 5, benign: 14 },
  { date: "Oct 26", malicious: 7, benign: 9 },
  { date: "Oct 27", malicious: 6, benign: 13 },
];

// ==========================================
// SYSTEM C EVALUATION
// Actual reported numbers from latest run.
// These are historical results, not live.
// ==========================================

export const systemCMetrics = {
  totalScenarios: 146,
  decidableScenarios: 138,
  answeredScenarios: 129,
  abstainedScenarios: 8,
  failedScenarios: 1,
  malformedScenarios: 8,

  accuracyAnswered: 84.5,
  accuracyExcludingFailures: 79.56,
  accuracyEndToEnd: 78.99,

  precision: 73.91,
  recall: 96.23,
  f1Score: 83.61,
  coverage: 93.48,

  confusionMatrix: {
    tp: 51,
    fp: 18,
    fn: 2,
    tn: 58,
  },

  injectionMetrics: {
    accuracy: 100,
    precision: 100,
    recall: 100,
    f1Score: 100,
    tp: 17,
    fp: 0,
    fn: 0,
    tn: 128,
  },

  policy: {
    actionsChanged: 37,
    executionViolations: 0,
  },

  failedScenarioIds: ["gen_0008"],

  malformedRecords: {
    total: 8,
    abstained: 3,
    forcedMalicious: 0,
    forcedBenign: 5,
    failed: 0,
  },

  source: "historical_evaluation",
};

// ==========================================
// ILLUSTRATIVE INVESTIGATION DATA
// UI demonstration only.
// ==========================================

export const investigationDetails = {
  "demo-001": {
    ruleAnalysis: {
      classification: "suspicious",
      severity: "high",
      riskScore: 85,
      evidence: [
        "Multiple failed authentication attempts",
        "Failed-attempt threshold exceeded",
      ],
    },
    llmAnalysis: {
      assessment: "suspicious",
      severity: "high",
      confidence: 0.92,
      evidence: [
        "Repeated failed login attempts were observed",
      ],
      explanation:
        "Repeated authentication failures may indicate an attempted brute-force attack.",
      recommendedAction: "monitor",
    },
    policyDecision: {
      approved: false,
      finalAction: "escalate_for_review",
      injectionDetected: false,
      executed: false,
      reason:
        "Suspicious assessment or high severity requires human review.",
    },
  },

  "demo-005": {
    ruleAnalysis: {
      classification: "benign",
      severity: "medium",
      riskScore: 45,
      evidence: [
        "Event contains an instruction-like text pattern",
      ],
    },
    llmAnalysis: {
      assessment: "benign",
      severity: "low",
      confidence: 0.83,
      evidence: [
        "No independently confirmed malicious network activity",
      ],
      explanation:
        "The security event contains suspicious embedded instructions that must be treated as untrusted data.",
      recommendedAction: "monitor",
    },
    policyDecision: {
      approved: false,
      finalAction: "investigate",
      injectionDetected: true,
      executed: false,
      reason:
        "Potential prompt injection detected; preserve the event for review without trusting embedded instructions.",
    },
  },
};

// ==========================================
// FILTER OPTIONS
// ==========================================

export const eventFilters = {
  classifications: [
    "all",
    "malicious",
    "benign",
    "indeterminate",
  ],

  severities: [
    "all",
    "low",
    "medium",
    "high",
    "critical",
  ],

  statuses: [
    "all",
    "needs_review",
    "investigating",
    "monitored",
  ],
};
