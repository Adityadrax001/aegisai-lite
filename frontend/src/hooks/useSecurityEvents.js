
import { useMemo, useState } from "react";

const DEFAULT_PAGE_SIZE = 5;

export default function useSecurityEvents(
  events = [],
  pageSize = DEFAULT_PAGE_SIZE
) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [classification, setClassification] = useState("all");
  const [sortOrder, setSortOrder] = useState("desc");
  const [page, setPage] = useState(1);

  // Search, filter, and sort security events.
  // This is UI logic, not cybersecurity classification.
  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();

    return events
      .filter((event) => {
        const searchableText = [
          event.title,
          event.id,
          event.scenarioId,
          event.category,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        const matchesSearch =
          !query || searchableText.includes(query);

        const matchesSeverity =
          severity === "all" ||
          event.severity === severity;

        const matchesClassification =
          classification === "all" ||
          event.classification === classification;

        return (
          matchesSearch &&
          matchesSeverity &&
          matchesClassification
        );
      })
      .sort((a, b) => {
        const difference =
          new Date(a.timestamp).getTime() -
          new Date(b.timestamp).getTime();

        return sortOrder === "asc"
          ? difference
          : -difference;
      });
  }, [events, search, severity, classification, sortOrder]);

  // Pagination
  const pageCount = Math.max(
    1,
    Math.ceil(filteredEvents.length / pageSize)
  );

  const currentPage = Math.min(page, pageCount);

  const visibleEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;

    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, currentPage, pageSize]);

  // Reset pagination whenever a filter changes.
  function updateSearch(value) {
    setSearch(value);
    setPage(1);
  }

  function updateSeverity(value) {
    setSeverity(value);
    setPage(1);
  }

  function updateClassification(value) {
    setClassification(value);
    setPage(1);
  }

  function toggleSortOrder() {
    setSortOrder((current) =>
      current === "desc" ? "asc" : "desc"
    );
    setPage(1);
  }

  function resetFilters() {
    setSearch("");
    setSeverity("all");
    setClassification("all");
    setPage(1);
  }

  function nextPage() {
    setPage((current) =>
      Math.min(current + 1, pageCount)
    );
  }

  function previousPage() {
    setPage((current) =>
      Math.max(current - 1, 1)
    );
  }

  return {
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
  };
}
