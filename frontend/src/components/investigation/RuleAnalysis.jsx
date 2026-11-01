
import { ShieldAlert, Activity, ListChecks } from "lucide-react";
import EventStatusBadge from "../events/EventStatusBadge";

export default function RuleAnalysis({ analysis }) {
  if (!analysis) {
    return (
      <section className="nb-card p-5">
        <h2 className="font-black uppercase text-text">
          Rule-Based Analysis
        </h2>
        <p className="mt-2 text-sm text-muted">
          Rule-based analysis is unavailable.
        </p>
      </section>
    );
  }

  const { classification, severity, riskScore, evidence = [] } = analysis;

  return (
    <section
      aria-labelledby="rule-analysis-title"
      className="nb-card min-w-0 p-5 sm:p-6"
    >
      <div className="mb-6 flex items-start justify-between gap-3">
        <div>
          <p className="nb-label">02 / SYSTEM A</p>
          <h2
            id="rule-analysis-title"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            Rule-Based Detector
          </h2>
        </div>

        <ShieldAlert
          size={25}
          className="shrink-0 text-text"
          aria-hidden="true"
        />
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            Classification
          </p>
          <EventStatusBadge value={classification} />
        </div>

        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            Severity
          </p>
          <EventStatusBadge value={severity} />
        </div>
      </div>

      <div className="mt-4 border-2 border-border bg-lime p-4 text-[#171717]">
        <div className="flex items-center gap-2">
          <Activity size={18} aria-hidden="true" />
          <p className="text-xs font-black uppercase">
            Risk Score
          </p>
        </div>

        {typeof riskScore === "number" ? (
          <>
            <p className="mt-3 text-4xl font-black tabular-nums">
              {riskScore}
              <span className="text-lg"> / 100</span>
            </p>

            <div
              role="progressbar"
              aria-label="Risk score"
              aria-valuenow={riskScore}
              aria-valuemin={0}
              aria-valuemax={100}
              className="mt-3 h-4 overflow-hidden border-2 border-[#171717] bg-white"
            >
              <div
                className="h-full bg-[#171717]"
                style={{
                  width: `${Math.max(0, Math.min(100, riskScore))}%`,
                }}
              />
            </div>
          </>
        ) : (
          <p className="mt-3 text-sm font-bold">
            Risk score unavailable
          </p>
        )}
      </div>

      <div className="mt-5">
        <div className="mb-3 flex items-center gap-2">
          <ListChecks size={18} aria-hidden="true" />
          <h3 className="text-sm font-black uppercase text-text">
            Observed Evidence
          </h3>
        </div>

        {evidence.length > 0 ? (
          <ul className="space-y-2">
            {evidence.map((item, index) => (
              <li
                key={index}
                className="flex gap-3 border-2 border-border bg-surface p-3 text-sm text-text"
              >
                <span aria-hidden="true" className="font-black">
                  {String(index + 1).padStart(2, "0")}.
                </span>
                <span className="min-w-0 break-words">{item}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">
            No evidence details were provided.
          </p>
        )}
      </div>
    </section>
  );
}
