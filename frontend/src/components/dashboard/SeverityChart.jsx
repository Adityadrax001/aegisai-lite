
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";

function SeverityTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;

  const item = payload[0].payload;

  return (
    <div className="border-2 border-[#171717] bg-white p-3 shadow-[4px_4px_0_#171717]">
      <p className="text-xs font-black uppercase text-[#171717]">
        {item.name}
      </p>

      <p className="mt-1 text-sm font-semibold text-[#353535]">
        {item.value} events
      </p>
    </div>
  );
}

export default function SeverityChart({ data = [] }) {
  const total = data.reduce(
    (sum, item) => sum + item.value,
    0
  );

  return (
    <section
      aria-labelledby="severity-chart-title"
      className="nb-card min-w-0 p-4 sm:p-6"
    >
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="nb-label">EVENT CLASSIFICATION</p>

          <h2
            id="severity-chart-title"
            className="mt-2 text-xl font-black uppercase text-text"
          >
            Severity Distribution
          </h2>

          <p className="mt-2 text-xs text-muted">
            Illustrative distribution across severity levels.
          </p>
        </div>

        <span className="border-2 border-border bg-yellow px-3 py-1 font-mono text-xs font-bold text-[#171717]">
          DEMO DATA
        </span>
      </div>

      {data.length === 0 ? (
        <div className="flex h-64 items-center justify-center border-2 border-dashed border-border">
          <p className="text-sm text-muted">
            No severity information available.
          </p>
        </div>
      ) : (
        <>
          <div
            className="h-64 w-full sm:h-72"
            role="img"
            aria-label="Bar chart showing the severity distribution of demo security events"
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={data}
                layout="vertical"
                margin={{
                  top: 5,
                  right: 15,
                  bottom: 5,
                  left: 5,
                }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  horizontal={false}
                  stroke="#888888"
                  strokeOpacity={0.25}
                />

                <XAxis
                  type="number"
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "#888888" }}
                  axisLine={false}
                  tickLine={false}
                />

                <YAxis
                  type="category"
                  dataKey="name"
                  width={65}
                  tick={{ fontSize: 11, fill: "#888888" }}
                  axisLine={false}
                  tickLine={false}
                />

                <Tooltip
                  content={<SeverityTooltip />}
                  cursor={{ fill: "#888888", fillOpacity: 0.08 }}
                />

                <Bar
                  dataKey="value"
                  barSize={24}
                  radius={0}
                >
                  {data.map((item) => (
                    <Cell
                      key={item.name}
                      fill={item.color}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t-2 border-border pt-4">
            <span className="font-mono text-xs font-bold uppercase text-muted">
              Total represented
            </span>

            <span className="text-xl font-black text-text">
              {total}
            </span>
          </div>

          <p className="sr-only">
            {data.map(
              (item) => `${item.name}: ${item.value} events.`
            ).join(" ")}
          </p>
        </>
      )}
    </section>
  );
}
