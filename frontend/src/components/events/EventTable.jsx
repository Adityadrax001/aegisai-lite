
import { Link } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import EventStatusBadge from "./EventStatusBadge";

function formatDate(value) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "Unknown";

  return new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Kolkata",
  }).format(date);
}

export default function EventTable({
  events,
  sortOrder,
  onSortChange,
}) {
  return (
    <section className="nb-card min-w-0 overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b-2 border-border bg-lime p-4 text-[#171717]">
        <h2 className="text-sm font-black uppercase">
          Security Event Queue
        </h2>

        <span className="font-mono text-xs font-bold">
          {events.length} records on this page
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[850px] border-collapse text-left text-sm">
          <thead className="border-b-2 border-border bg-sidebar text-text">
            <tr>
              <th scope="col" className="p-4">Event</th>
              <th scope="col" className="p-4">Severity</th>
              <th scope="col" className="p-4">Classification</th>
              <th scope="col" className="p-4">Policy Action</th>

              <th scope="col" className="p-4">
                <button
                  type="button"
                  onClick={onSortChange}
                  className="font-bold underline underline-offset-4"
                >
                  Timestamp {sortOrder === "desc" ? "↓" : "↑"}
                </button>
              </th>

              <th scope="col" className="p-4">Details</th>
            </tr>
          </thead>

          <tbody>
            {events.map((event) => (
              <tr
                key={event.id}
                className="border-b border-border last:border-b-0 hover:bg-accent/15"
              >
                <td className="p-4">
                  <p className="font-black text-text">
                    {event.title}
                  </p>
                  <p className="mt-1 font-mono text-xs text-muted">
                    {event.scenarioId}
                  </p>
                </td>

                <td className="p-4">
                  <EventStatusBadge value={event.severity} />
                </td>

                <td className="p-4">
                  <EventStatusBadge value={event.classification} />
                </td>

                <td className="p-4">
                  <EventStatusBadge value={event.finalAction} />
                </td>

                <td className="p-4 whitespace-nowrap text-muted">
                  {formatDate(event.timestamp)}
                </td>

                <td className="p-4">
                  <Link
                    to={`/events/${encodeURIComponent(event.id)}`}
                    aria-label={`View details for ${event.title}`}
                    className="inline-flex items-center gap-1 border-2 border-border bg-surface px-3 py-2 text-xs font-black text-text hover:bg-accent hover:text-[#171717]"
                  >
                    Open
                    <ArrowUpRight size={14} aria-hidden="true" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {events.length === 0 && (
        <div className="p-10 text-center">
          <p className="font-black uppercase text-text">
            No Matching Events
          </p>
          <p className="mt-2 text-sm text-muted">
            Try changing the search or filters.
          </p>
        </div>
      )}
    </section>
  );
}
