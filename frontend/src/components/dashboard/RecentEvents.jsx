
import { useNavigate } from "react-router-dom";
import {
  ArrowUpRight,
  ShieldAlert,
  Activity,
} from "lucide-react";

const severityStyles = {
  critical: "bg-red-300",
  high: "bg-coral",
  medium: "bg-yellow",
  low: "bg-blue",
};

const classificationStyles = {
  malicious: "bg-coral",
  benign: "bg-lime",
  indeterminate: "bg-yellow",
};

const actionLabels = {
  monitor: "Monitor",
  investigate: "Investigate",
  escalate_for_review: "Review Required",
};

function formatDate(timestamp) {
  if (!timestamp) return "Unknown";

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return "Invalid date";
  }

  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "Asia/Kolkata",
  }).format(date);
}

export default function RecentEvents({ events = [] }) {
  const navigate = useNavigate();

  const recentEvents = [...events]
    .sort(
      (a, b) =>
        new Date(b.timestamp).getTime() -
        new Date(a.timestamp).getTime()
    )
    .slice(0, 5);

  return (
    <section
      aria-labelledby="recent-events-heading"
      className="nb-card min-w-0 overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b-2 border-border p-5">
        <div>
          <p className="nb-label">EVENT MONITOR</p>

          <h2
            id="recent-events-heading"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            Recent Security Events
          </h2>

          <p className="mt-2 text-xs text-muted">
            Demonstration events — not live security monitoring.
          </p>
        </div>

        <button
          type="button"
          onClick={() => navigate("/events")}
          className="inline-flex items-center gap-2 border-2 border-border bg-lime px-3 py-2 text-xs font-black uppercase text-[#171717] shadow-[3px_3px_0_#171717] transition-transform hover:-translate-y-0.5 active:translate-y-0"
        >
          View All
          <ArrowUpRight size={15} aria-hidden="true" />
        </button>
      </div>

      {/* Events */}
      {recentEvents.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 p-12 text-center">
          <Activity size={30} className="text-muted" />

          <p className="font-bold text-text">
            No security events available
          </p>

          <p className="text-sm text-muted">
            Events will appear here when data is available.
          </p>
        </div>
      ) : (
        <div className="divide-y-2 divide-border">
          {recentEvents.map((event) => {
            const severity =
              severityStyles[event.severity] ?? "bg-surface";

            const classification =
              classificationStyles[event.classification] ??
              "bg-surface";

            return (
              <button
                key={event.id}
                type="button"
                onClick={() =>
                  navigate(`/events/${encodeURIComponent(event.id)}`)
                }
                className="flex w-full flex-col gap-3 p-4 text-left transition-colors hover:bg-accent/20 focus-visible:bg-accent/20 sm:flex-row sm:items-center sm:justify-between sm:p-5"
              >
                <div className="flex min-w-0 flex-1 items-start gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center border-2 border-border bg-surface">
                    <ShieldAlert
                      size={20}
                      className="text-text"
                      aria-hidden="true"
                    />
                  </div>

                  <div className="min-w-0">
                    <p className="break-words text-sm font-black uppercase text-text">
                      {event.title}
                    </p>

                    <p className="mt-1 font-mono text-xs text-muted">
                      {event.scenarioId} · {formatDate(event.timestamp)}
                    </p>

                    <p className="mt-1 text-xs text-muted">
                      Policy:{" "}
                      {actionLabels[event.finalAction] ??
                        event.finalAction ??
                        "Unknown"}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 sm:justify-end">
                  <span
                    className={`border-2 border-[#171717] px-2 py-1 text-[10px] font-black uppercase text-[#171717] ${severity}`}
                  >
                    {event.severity ?? "Unknown"}
                  </span>

                  <span
                    className={`border-2 border-[#171717] px-2 py-1 text-[10px] font-black uppercase text-[#171717] ${classification}`}
                  >
                    {event.classification ?? "Unknown"}
                  </span>

                  <ArrowUpRight
                    size={18}
                    className="ml-1 text-text"
                    aria-hidden="true"
                  />
                </div>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
