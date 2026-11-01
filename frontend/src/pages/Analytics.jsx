
import AnalyticsMetric from "../components/analytics/AnalyticsMetric";
import ConfusionMatrix from "../components/analytics/ConfusionMatrix";

import { systemCMetrics } from "../data/data";

function percentage(value) {
  return typeof value === "number"
    ? `${value.toFixed(2)}%`
    : "N/A";
}

export default function Analytics() {
  const m = systemCMetrics;

  return (
    <main className="min-w-0 space-y-6">
      {/* Header */}
      <header className="nb-card p-5">
        <p className="nb-label">
          AEGIS AI / PERFORMANCE LAB
        </p>

        <h1 className="mt-2 text-3xl font-black uppercase text-text">
          System Analytics.
        </h1>

        <p className="mt-2 text-sm text-muted">
          Evaluation results for the AI-assisted
          cyber-defense prototype.
        </p>

        <span className="mt-4 inline-flex border-2 border-[#171717] bg-yellow px-3 py-1 font-mono text-xs font-black text-[#171717]">
          HISTORICAL EVALUATION — NOT LIVE DATA
        </span>
      </header>

      {/* System comparison */}
      <section className="nb-card p-5">
        <h2 className="text-lg font-black uppercase text-text">
          Architecture Comparison
        </h2>

        <div className="mt-4 grid gap-3 md:grid-cols-3">
          {[
            {
              name: "System A",
              detail: "Deterministic rules",
            },
            {
              name: "System B",
              detail: "DeepSeek LLM-only",
            },
            {
              name: "System C",
              detail: "LLM + deterministic policy",
            },
          ].map((system) => (
            <article
              key={system.name}
              className="border-2 border-border bg-surface p-4"
            >
              <h3 className="text-lg font-black uppercase text-text">
                {system.name}
              </h3>
              <p className="mt-2 text-sm text-muted">
                {system.detail}
              </p>
              <p className="mt-4 font-mono text-xs font-bold uppercase text-muted">
                {system.name === "System C"
                  ? "Metrics available below"
                  : "Comparable metrics not loaded"}
              </p>
            </article>
          ))}
        </div>
      </section>

      {/* Classification metrics */}
      <section aria-labelledby="classification-heading">
        <h2
          id="classification-heading"
          className="mb-4 text-xl font-black uppercase text-text"
        >
          System C / Classification
        </h2>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <AnalyticsMetric
            label="End-to-End Accuracy"
            value={percentage(m.accuracyEndToEnd)}
            description="Correct / all decidable scenarios"
            color="lime"
          />

          <AnalyticsMetric
            label="Malicious Precision"
            value={percentage(m.precision)}
            description="TP / (TP + FP)"
            color="coral"
          />

          <AnalyticsMetric
            label="Malicious Recall"
            value={percentage(m.recall)}
            description="TP / all malicious scenarios"
            color="blue"
          />

          <AnalyticsMetric
            label="Malicious F1"
            value={percentage(m.f1Score)}
            description="Harmonic mean of precision and recall"
            color="yellow"
          />
        </div>
      </section>

      {/* Additional accuracy definitions */}
      <section className="nb-card p-5">
        <h2 className="text-lg font-black uppercase text-text">
          Accuracy and Coverage
        </h2>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            {
              label: "Answered Only",
              value: m.accuracyAnswered,
            },
            {
              label: "Excluding Failures",
              value: m.accuracyExcludingFailures,
            },
            {
              label: "End to End",
              value: m.accuracyEndToEnd,
            },
            {
              label: "Answer Coverage",
              value: m.coverage,
            },
          ].map((item) => (
            <div
              key={item.label}
              className="border-2 border-border bg-surface p-4"
            >
              <p className="text-xs font-black uppercase text-muted">
                {item.label}
              </p>
              <p className="mt-3 text-2xl font-black tabular-nums text-text">
                {percentage(item.value)}
              </p>
            </div>
          ))}
        </div>

        <p className="mt-4 text-xs text-muted">
          Answered-only accuracy excludes abstentions
          and failures. End-to-end accuracy includes
          both in the decidable-scenario denominator.
        </p>
      </section>

      {/* Confusion matrix */}
      <ConfusionMatrix matrix={m.confusionMatrix} />

      {/* Scenario accounting */}
      <section className="nb-card p-5">
        <h2 className="text-lg font-black uppercase text-text">
          Scenario Accounting
        </h2>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
          {[
            ["Total", m.totalScenarios],
            ["Decidable", m.decidableScenarios],
            ["Answered", m.answeredScenarios],
            ["Abstained", m.abstainedScenarios],
            ["Failed", m.failedScenarios],
            ["Malformed", m.malformedScenarios],
          ].map(([label, value]) => (
            <div
              key={label}
              className="border-2 border-border bg-surface p-4"
            >
              <p className="text-xs font-black uppercase text-muted">
                {label}
              </p>
              <p className="mt-2 text-3xl font-black tabular-nums text-text">
                {value}
              </p>
            </div>
          ))}
        </div>

        <p className="mt-4 text-sm text-muted">
          Malformed ground-truth records are evaluated
          separately. In the latest run,{" "}
          {m.malformedRecords.abstained} of{" "}
          {m.malformedRecords.total} were correctly
          handled by abstention.
        </p>
      </section>

      {/* Injection detection */}
      <section aria-labelledby="injection-heading">
        <h2
          id="injection-heading"
          className="mb-4 text-xl font-black uppercase text-text"
        >
          Prompt-Injection Detection
        </h2>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <AnalyticsMetric
            label="Precision"
            value={percentage(m.injectionMetrics.precision)}
            color="lime"
          />
          <AnalyticsMetric
            label="Recall"
            value={percentage(m.injectionMetrics.recall)}
            color="blue"
          />
          <AnalyticsMetric
            label="F1 Score"
            value={percentage(m.injectionMetrics.f1Score)}
            color="yellow"
          />
          <AnalyticsMetric
            label="Accuracy"
            value={percentage(m.injectionMetrics.accuracy)}
            color="white"
          />
        </div>

        <p className="mt-3 text-sm text-muted">
          These scores reflect the evaluated simulation
          dataset. They do not establish performance
          on unseen real-world prompt injections.
        </p>

        <div className="mt-5">
          <ConfusionMatrix
            title="Injection Detection Confusion Matrix"
            matrix={m.injectionMetrics}
          />
        </div>
      </section>

      {/* Policy safety */}
      <section className="nb-card p-5">
        <h2 className="text-lg font-black uppercase text-text">
          Policy and Execution Safety
        </h2>

        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <AnalyticsMetric
            label="Recommendations Changed"
            value={m.policy.actionsChanged}
            description="Policy action differed from LLM proposal"
            color="yellow"
          />

          <AnalyticsMetric
            label="Execution Violations"
            value={m.policy.executionViolations}
            description="Reported violations in the evaluated simulation"
            color="lime"
          />
        </div>

        <p className="mt-4 text-sm text-muted">
          All defensive actions remain simulated.
          Zero reported execution violations is an
          evaluation result, not proof of complete
          system security.
        </p>
      </section>
    </main>
  );
}
