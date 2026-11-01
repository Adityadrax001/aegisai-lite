
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

function ThreatTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;

  return (
    <div className="border-2 border-[#171717] bg-white p-3 shadow-[4px_4px_0_#171717]">
      <p className="mb-2 text-xs font-black uppercase text-[#171717]">
        {label}
      </p>

      {payload.map((entry) => (
        <div
          key={entry.dataKey}
          className="flex items-center justify-between gap-6 text-xs"
        >
          <span className="font-semibold text-[#353535]">
            {entry.name}
          </span>
          <span className="font-black text-[#171717]">
            {entry.value}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function ThreatChart({ data = [] }) {
  return (
    <section
      aria-labelledby="threat-chart-heading"
      className="brutal-card min-w-0 p-4 sm:p-6"
    >
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs font-bold uppercase text-muted">
            / EVENT ANALYTICS
          </p>
          <h2
            id="threat-chart-heading"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            Threat Activity
          </h2>
          <p className="mt-1 text-xs text-muted">
            Illustrative security-event activity over seven days
          </p>
        </div>

        <span className="brutal-label bg-yellow text-[#171717]">
          Demo data
        </span>
      </div>

      {data.length === 0 ? (
        <div className="flex h-64 items-center justify-center border-2 border-dashed border-border">
          <p className="text-sm text-muted">
            No threat activity data available.
          </p>
        </div>
      ) : (
        <>
          <div
            role="img"
            aria-label="Area chart showing malicious and benign event trends"
            className="h-64 w-full sm:h-80"
          >
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={data}
                margin={{ top: 10, right: 10, left: -22, bottom: 5 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#8A8A8A"
                  strokeOpacity={0.3}
                  vertical={false}
                />

                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11, fill: "#888888" }}
                  axisLine={false}
                  tickLine={false}
                />

                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "#888888" }}
                  axisLine={false}
                  tickLine={false}
                />

                <Tooltip content={<ThreatTooltip />} />

                <Legend
                  verticalAlign="bottom"
                  wrapperStyle={{ fontSize: 12, paddingTop: 12 }}
                />

                <Area
                  type="monotone"
                  dataKey="malicious"
                  name="Malicious"
                  stroke="#D73838"
                  strokeWidth={3}
                  fill="#FF8A70"
                  fillOpacity={0.45}
                  activeDot={{ r: 5 }}
                />

                <Area
                  type="monotone"
                  dataKey="benign"
                  name="Benign"
                  stroke="#17683B"
                  strokeWidth={3}
                  fill="#DFFF65"
                  fillOpacity={0.3}
                  activeDot={{ r: 5 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <p className="sr-only">
            {data.map(
              (item) =>
                `${item.date}: ${item.malicious} malicious events and ${item.benign} benign events.`
            ).join(" ")}
          </p>
        </>
      )}
    </section>
  );
}
