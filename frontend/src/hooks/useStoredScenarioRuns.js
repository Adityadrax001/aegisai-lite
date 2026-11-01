
import { useEffect, useState, useCallback } from "react";
import { eventService } from "../services/eventService";

export default function useStoredScenarioRuns() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = useCallback(() => {
    setRefreshKey((current) => current + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();

    async function loadEvents() {
      setLoading(true);
      setError(null);

      try {
        const records = await eventService.getScenarioRuns(
          controller.signal
        );

        if (!controller.signal.aborted) {
          setEvents(records);
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err.message || "Failed to load scenario runs.");
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }

    loadEvents();

    return () => controller.abort();
  }, [refreshKey]);

  return {
    events,
    loading,
    error,
    refresh,
  };
}
