
import { BrainCircuit, MessageSquareText } from "lucide-react";
import EventStatusBadge from "../events/EventStatusBadge";

export default function LLMAnalysis({ analysis }) {
  if (!analysis) {
    return (
      <section className="nb-card p-5">
        <h2 className="font-black uppercase text-text">
          DeepSeek Analysis
        </h2>
        <p className="mt-2 text-sm text-muted">
          LLM analysis is unavailable.
        </p>
      </section>
    );
  }

  const {
    assessment,
    severity,
    confidence,
    evidence = [],
    explanation,
    recommendedAction,
  } = analysis;

  const confidencePercent =
    typeof confidence === "number" &&
    Number.isFinite(confidence) &&
    confidence >= 0 &&
    confidence <= 1
      ? Math.round(confidence * 100)
      : null;

  return (
    <section
      aria-labelledby="llm-analysis-title"
      className="nb-card min-w-0 p-5 sm:p-6"
    >
      <div className="mb-6 flex items-start justify-between gap-3">
        <div>
          <p className="nb-label">03 / SYSTEM B OUTPUT</p>
          <h2
            id="llm-analysis-title"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            DeepSeek Analysis
          </h2>
        </div>

        <BrainCircuit
          size={25}
          className="shrink-0 text-text"
          aria-hidden="true"
        />
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            AI Assessment
          </p>
          <EventStatusBadge value={assessment} />
        </div>

        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            AI Severity
          </p>
          <EventStatusBadge value={severity} />
        </div>
      </div>

      <div className="mt-4 border-2 border-border bg-blue p-4 text-[#171717]">
        <p className="text-xs font-black uppercase">
          Model-Reported Confidence
        </p>

        <p className="mt-2 text-3xl font-black tabular-nums">
          {confidencePercent === null
            ? "Unavailable"
            : `${confidencePercent}%`}
        </p>

        <p className="mt-2 text-xs font-medium">
          Self-reported by the LLM; not a calibrated probability
          of correctness.
        </p>
      </div>

      <div className="mt-5">
        <div className="mb-3 flex items-center gap-2">
          <MessageSquareText size={18} aria-hidden="true" />
          <h3 className="text-sm font-black uppercase text-text">
            AI Explanation
          </h3>
        </div>

        <div className="border-2 border-border bg-surface p-4">
          <p className="break-words whitespace-pre-wrap text-sm leading-6 text-text">
            {explanation || "No explanation provided."}
          </p>
        </div>
      </div>

      <div className="mt-5">
        <h3 className="mb-3 text-sm font-black uppercase text-text">
          Evidence Identified by LLM
        </h3>

        {evidence.length > 0 ? (
          <ul className="list-inside list-square space-y-2 border-2 border-border bg-surface p-4 text-sm text-text">
            {evidence.map((item, index) => (
              <li key={index} className="break-words">
                {item}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">
            No supporting evidence supplied.
          </p>
        )}
      </div>

      <div className="mt-5 border-t-2 border-border pt-4">
        <p className="mb-3 text-xs font-black uppercase text-muted">
          LLM Proposed Action
        </p>

        <EventStatusBadge value={recommendedAction} />
      </div>
    </section>
  );
}
