
import ThreatChart from "../components/dashboard/ThreatChart";
import MetricCard from "../components/dashboard/MetricCard";
import SeverityChart from "../components/dashboard/SeverityChart";
import RecentEvents from "../components/dashboard/RecentEvents";

import {
  dashboardMetrics,
  threatTrend,
  severityDistribution,
  securityEvents
} from "../data/data";

export default function Dashboard() {
  return (
    <div className="space-y-6">

      {/* Dashboard Header */}
      <section className="nb-card p-5">
        <p className="nb-label">Overview</p>

        <h1 className="mt-1 text-2xl font-black uppercase">
          Dashboard
        </h1>

        <p className="mt-2 text-sm text-muted">
          Security operations and simulated threat analysis.
        </p>
      </section>

      {/* Metric Cards */}
      <section
        aria-label="Security metrics"
        className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4"
      >
        {dashboardMetrics.map((metric) => (
          <MetricCard
            key={metric.id}
            {...metric}
          />
        ))}
      </section>

      {/* Threat Activity Chart */}
      <section
        aria-label="Threat activity trends"
        className="min-w-0"
      >
        <ThreatChart data={threatTrend} />
      </section>

      
{/* Analytics charts */}
<section
  aria-label="Security analytics"
  className="grid grid-cols-1 items-stretch gap-5 xl:grid-cols-2"
>
  <div className="min-w-0">
    <ThreatChart data={threatTrend} />
  </div>

  <div className="min-w-0">
    <SeverityChart data={severityDistribution} />
  </div>
</section>
{/* Recent Security Events */}
<section aria-label="Recent security events">
  <RecentEvents events={securityEvents} />
</section>

    </div>
  );
}
