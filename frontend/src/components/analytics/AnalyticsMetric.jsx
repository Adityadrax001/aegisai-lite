
const colors = {
  white: "bg-surface text-text",
  lime: "bg-lime text-[#171717]",
  coral: "bg-coral text-[#171717]",
  blue: "bg-blue text-[#171717]",
  yellow: "bg-yellow text-[#171717]",
};

export default function AnalyticsMetric({
  label,
  value,
  description,
  color = "white",
}) {
  return (
    <article
      className={`nb-card min-w-0 p-4 sm:p-5 ${
        colors[color] ?? colors.white
      }`}
    >
      <p className="text-xs font-black uppercase tracking-wide">
        {label}
      </p>

      <p className="mt-4 wrap-break-word text-3xl font-black tabular-nums sm:text-4xl">
        {value ?? "N/A"}
      </p>

      {description && (
        <p className="mt-3 text-xs font-medium opacity-80">
          {description}
        </p>
      )}
    </article>
  );
}
