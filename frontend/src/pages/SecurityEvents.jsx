
import EventFilters from "../components/events/EventFilters";
import EventTable from "../components/events/EventTable";
import useStoredScenarioRuns from "../hooks/useStoredScenarioRuns";
import useSecurityEvents from "../hooks/useSecurityEvents";
import { securityEvents } from "../data/data";

export default function SecurityEvents() {
const {
  events,
  loading,
  error,
  refresh,
} = useStoredScenarioRuns();

const {
  search,
  severity,
  classification,
  sortOrder,
  filteredEvents,
  visibleEvents,
  currentPage,
  pageCount,
  updateSearch,
  updateSeverity,
  updateClassification,
  toggleSortOrder,
  resetFilters,
  nextPage,
  previousPage,
} = useSecurityEvents(events);

  return (
    <div className="space-y-6">
      {/* Page heading */}
      <header className="nb-card p-5">
        <p className="nb-label">
          AEGIS AI / EVENT EXPLORER
        </p>

        <h1 className="mt-2 text-3xl font-black uppercase text-text">
          Security Events.
        </h1>

        <p className="mt-2 text-sm text-muted">
          Search, filter and investigate simulated security events.
        </p>

        <p className="mt-2 font-mono text-xs font-bold text-muted">
          DEMO DATA — NOT LIVE SECURITY MONITORING
        </p>
      </header>

      {/* Filters */}
      <EventFilters
        search={search}
        onSearchChange={updateSearch}
        severity={severity}
        onSeverityChange={updateSeverity}
        classification={classification}
        onClassificationChange={updateClassification}
        onReset={resetFilters}
      />
      
      {loading && (
  <div role="status" className="nb-card p-5 text-sm text-muted">
    Loading stored security events...
  </div>
)}

{error && (
  <div role="alert" className="nb-card p-5">
    <p className="font-bold text-critical">
      {error}
    </p>

    <button
      type="button"
      onClick={refresh}
      className="mt-3 brutal-button"
    >
      Retry
    </button>
  </div>
)}

{!loading && !error && (
  <EventTable
    events={visibleEvents}
    sortOrder={sortOrder}
    onSortChange={toggleSortOrder}
  />
)}
      {/* Event table */}
      <EventTable
        events={visibleEvents}
        sortOrder={sortOrder}
        onSortChange={toggleSortOrder}
      />

      {/* Pagination */}
      <nav
        aria-label="Event pagination"
        className="flex flex-wrap items-center justify-between gap-3"
      >
        <p className="font-mono text-xs text-muted">
          Showing {visibleEvents.length} of{" "}
          {filteredEvents.length} matching events
        </p>

        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={currentPage === 1}
            onClick={previousPage}
            className="border-2 border-border bg-surface px-3 py-2 text-sm font-bold text-text disabled:cursor-not-allowed disabled:opacity-40"
          >
            Previous
          </button>

          <span className="font-mono text-xs font-bold text-text">
            {currentPage} / {pageCount}
          </span>

          <button
            type="button"
            disabled={currentPage === pageCount}
            onClick={nextPage}
            className="border-2 border-border bg-lime px-3 py-2 text-sm font-bold text-[#171717] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </nav>
    </div>
  );
}
