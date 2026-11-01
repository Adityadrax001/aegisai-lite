
import { Search, RotateCcw } from "lucide-react";

export default function EventFilters({
  search,
  onSearchChange,
  severity,
  onSeverityChange,
  classification,
  onClassificationChange,
  onReset,
}) {
  const inputStyle =
    "w-full min-w-0 border-2 border-border bg-surface px-3 py-2.5 text-sm text-text outline-offset-2";

  return (
    <section
      aria-label="Event filters"
      className="nb-card p-4 sm:p-5"
    >
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
        <div className="lg:col-span-6">
          <label
            htmlFor="event-search"
            className="mb-2 block text-xs font-black uppercase"
          >
            Search Events
          </label>

          <div className="relative">
            <Search
              size={18}
              aria-hidden="true"
              className="absolute top-1/2 left-3 -translate-y-1/2 text-muted"
            />

            <input
              id="event-search"
              type="search"
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search title, ID, category..."
              className={`${inputStyle} pl-10`}
            />
          </div>
        </div>

        <div className="lg:col-span-3">
          <label
            htmlFor="severity-filter"
            className="mb-2 block text-xs font-black uppercase"
          >
            Severity
          </label>

          <select
            id="severity-filter"
            value={severity}
            onChange={(e) => onSeverityChange(e.target.value)}
            className={inputStyle}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="lg:col-span-3">
          <label
            htmlFor="classification-filter"
            className="mb-2 block text-xs font-black uppercase"
          >
            Classification
          </label>

          <select
            id="classification-filter"
            value={classification}
            onChange={(e) => onClassificationChange(e.target.value)}
            className={inputStyle}
          >
            <option value="all">All Classifications</option>
            <option value="malicious">Malicious</option>
            <option value="benign">Benign</option>
            <option value="indeterminate">Indeterminate</option>
          </select>
        </div>
      </div>

      <div className="mt-4 flex justify-end">
        <button
          type="button"
          onClick={onReset}
          className="inline-flex items-center gap-2 border-2 border-border bg-lime px-4 py-2 text-xs font-black uppercase text-[#171717] shadow-[3px_3px_0_#171717] hover:translate-y-[-1px] active:translate-y-0"
        >
          <RotateCcw size={15} aria-hidden="true" />
          Reset Filters
        </button>
      </div>
    </section>
  );
}
