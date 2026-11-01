
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, AlertTriangle } from "lucide-react";

import EventDetails from "../components/events/EventDetails";
import RuleAnalysis from "../components/investigation/RuleAnalysis";
import LLMAnalysis from "../components/investigation/LLMAnalysis";
import PolicyDecision from "../components/investigation/PolicyDecision";

import {
  securityEvents,
  investigationDetails,
} from "../data/data";

export default function Investigation() {
  const { eventId } = useParams();

  const event = securityEvents.find(
    (item) => item.id === eventId
  );

  const analysis = event
    ? investigationDetails[event.id] ?? null
    : null;

  if (!event) {
    return (
      <main className="space-y-5">
        <Link
          to="/events"
          className="inline-flex items-center gap-2 font-bold text-text underline"
        >
          <ArrowLeft size={18} />
          Back to Security Events
        </Link>

        <section className="nb-card p-6">
          <h1 className="text-2xl font-black uppercase text-text">
            Event Not Found
          </h1>

          <p className="mt-2 text-sm text-muted">
            No demonstration event matches this ID.
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="min-w-0 space-y-6">
      {/* Back navigation */}
      <Link
        to="/events"
        className="inline-flex items-center gap-2 text-sm font-bold text-text underline underline-offset-4"
      >
        <ArrowLeft size={17} aria-hidden="true" />
        Back to Security Events
      </Link>

      {/* Page header */}
      <header className="nb-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="nb-label">
              AEGIS AI / SECURITY OPERATIONS
            </p>

            <h1 className="mt-2 text-2xl font-black uppercase text-text sm:text-3xl">
              Event Investigation.
            </h1>

            <p className="mt-2 text-sm text-muted">
              Inspect rule-based findings, DeepSeek analysis,
              and deterministic policy outcomes.
            </p>
          </div>

          <span className="border-2 border-[#171717] bg-yellow px-3 py-2 font-mono text-xs font-black text-[#171717]">
            DEMO DATA
          </span>
        </div>
      </header>

      {/* Event metadata */}
      <EventDetails event={event} />

      {/* Security analysis */}
      {analysis ? (
        <div className="space-y-6">
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
            <RuleAnalysis
              analysis={analysis.ruleAnalysis}
            />

            <LLMAnalysis
              analysis={analysis.llmAnalysis}
            />
          </div>

          {/* Final policy result */}
          <PolicyDecision
            decision={analysis.policyDecision}
            proposedAction={
              analysis.llmAnalysis?.recommendedAction
            }
          />
        </div>
      ) : (
        <section
          role="status"
          className="nb-card p-6"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle
              size={24}
              className="shrink-0 text-warning"
            />

            <div>
              <h2 className="font-black uppercase text-text">
                Analysis Unavailable
              </h2>

              <p className="mt-2 text-sm text-muted">
                No investigation record exists for this
                demonstration event. No analysis has been
                generated or inferred.
              </p>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
