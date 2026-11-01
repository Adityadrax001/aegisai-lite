
import {
  ShieldCheck,
  ShieldX,
  LockKeyhole,
  ArrowRight,
} from "lucide-react";

import EventStatusBadge from "../events/EventStatusBadge";

export default function PolicyDecision({
  decision,
  proposedAction,
}) {
  if (!decision) {
    return (
      <section className="nb-card p-5">
        <h2 className="font-black uppercase text-text">
          Policy Decision
        </h2>

        <p className="mt-2 text-sm text-muted">
          No policy result is available.
        </p>
      </section>
    );
  }

  const {
    approved,
    finalAction,
    injectionDetected,
    executed,
    reason,
  } = decision;

  return (
    <section
      aria-labelledby="policy-decision-title"
      className="nb-card min-w-0 p-5 sm:p-6"
    >
      <div className="mb-6 flex items-start justify-between gap-3">
        <div>
          <p className="nb-label">04 / SYSTEM C POLICY</p>
          <h2
            id="policy-decision-title"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            Deterministic Policy
          </h2>
        </div>

        <ShieldCheck size={25} className="shrink-0 text-text" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto_1fr] lg:items-center">
        <div className="min-w-0 border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            LLM Proposed
          </p>
          <EventStatusBadge value={proposedAction} />
        </div>

        <ArrowRight
          size={25}
          aria-hidden="true"
          className="rotate-90 text-text lg:rotate-0"
        />

        <div className="min-w-0 border-2 border-border bg-lime p-4">
          <p className="mb-3 text-xs font-black uppercase text-[#171717]">
            Final Policy Action
          </p>
          <EventStatusBadge value={finalAction} />
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            Recommendation Status
          </p>
          <p className="flex items-center gap-2 font-black uppercase text-text">
            {approved === true ? (
              <>
                <ShieldCheck size={19} />
                Approved
              </>
            ) : approved === false ? (
              <>
                <ShieldX size={19} />
                Overridden
              </>
            ) : (
              "Unknown"
            )}
          </p>
        </div>

        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            Injection Indicator
          </p>
          <p className="font-black uppercase text-text">
            {injectionDetected === true
              ? "Detected"
              : injectionDetected === false
                ? "Not Detected"
                : "Unknown"}
          </p>
        </div>
      </div>

      <div className="mt-5 border-2 border-border bg-surface p-4">
        <h3 className="mb-2 text-sm font-black uppercase text-text">
          Policy Explanation
        </h3>
        <p className="break-words whitespace-pre-wrap text-sm leading-6 text-text">
          {reason || "No policy explanation provided."}
        </p>
      </div>

      <div
        className={`mt-5 flex items-start gap-3 border-2 border-border p-4 ${
          executed === false ? "bg-lime" : "bg-yellow"
        } text-[#171717]`}
      >
        <LockKeyhole size={22} className="shrink-0" />

        <div>
          <p className="font-black uppercase">
            {executed === false
              ? "Simulation Only — No Action Executed"
              : "Execution Status Requires Verification"}
          </p>

          <p className="mt-1 text-xs">
            {executed === false
              ? "This result confirms that the reported policy outcome is non-executing."
              : "The supplied data does not confirm a non-executing policy outcome."}
          </p>
        </div>
      </div>
    </section>
  );
}
