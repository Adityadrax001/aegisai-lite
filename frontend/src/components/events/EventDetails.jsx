
import {
  Activity,
  CalendarClock,
  Fingerprint,
  Layers,
  ShieldAlert,
} from "lucide-react";

import EventStatusBadge from "./EventStatusBadge";

function formatTimestamp(value) {
  if (!value) return "Unavailable";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }

  return new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Kolkata",
  }).format(date);
}

function DetailItem({ icon: Icon, label, value }) {
  return (
    <div className="min-w-0 border-2 border-border bg-surface p-4">
      <div className="mb-3 flex items-center gap-2 text-muted">
        <Icon size={16} aria-hidden="true" />

        <span className="text-xs font-black uppercase">
          {label}
        </span>
      </div>

      <p className="break-words font-mono text-sm font-bold text-text">
        {value ?? "Unavailable"}
      </p>
    </div>
  );
}

export default function EventDetails({ event }) {
  if (!event) {
    return (
      <section className="nb-card p-6">
        <p className="font-black uppercase text-text">
          Event details unavailable
        </p>
      </section>
    );
  }

  return (
    <section
      aria-labelledby="event-details-heading"
      className="nb-card p-4 sm:p-6"
    >
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="nb-label">01 / EVENT INFORMATION</p>

          <h2
            id="event-details-heading"
            className="mt-3 text-xl font-black uppercase text-text sm:text-2xl"
          >
            {event.title}
          </h2>

          <p className="mt-2 font-mono text-xs text-muted">
            Event ID: {event.id}
          </p>
        </div>

        <EventStatusBadge value={event.severity} />
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <DetailItem
          icon={Fingerprint}
          label="Scenario ID"
          value={event.scenarioId}
        />

        <DetailItem
          icon={CalendarClock}
          label="Timestamp"
          value={formatTimestamp(event.timestamp)}
        />

        <DetailItem
          icon={Layers}
          label="Category"
          value={event.category}
        />

        <DetailItem
          icon={ShieldAlert}
          label="Classification"
          value={event.classification}
        />

        <DetailItem
          icon={Activity}
          label="Risk Score"
          value={
            event.riskScore != null
              ? `${event.riskScore} / 100`
              : "Not available"
          }
        />

        <div className="border-2 border-border bg-surface p-4">
          <p className="mb-3 text-xs font-black uppercase text-muted">
            Prompt Injection
          </p>

          {typeof event.injectionDetected === "boolean" ? (
            <span
              className={`inline-block border-2 border-[#171717] px-3 py-1 text-xs font-black uppercase text-[#171717] ${
                event.injectionDetected ? "bg-coral" : "bg-lime"
              }`}
            >
              {event.injectionDetected ? "Detected" : "Not detected"}
            </span>
          ) : (
            <span className="text-sm text-muted">
              Not evaluated
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
