
const styles = {
  malicious: "bg-coral",
  benign: "bg-lime",
  indeterminate: "bg-yellow",
  critical: "bg-red-300",
  high: "bg-coral",
  medium: "bg-yellow",
  low: "bg-blue",
  needs_review: "bg-coral",
  investigating: "bg-yellow",
  monitored: "bg-lime",
  monitor: "bg-lime",
  investigate: "bg-yellow",
  escalate_for_review: "bg-coral",
  suspicious: "bg-yellow",
};

export default function EventStatusBadge({ value }) {
  const color = styles[value] ?? "bg-surface text-text";
  const label = String(value ?? "unknown")
    .replaceAll("_", " ")
    .toUpperCase();

  return (
    <span
      className={`inline-flex max-w-full items-center border-2 border-[#171717] px-2 py-1 text-[10px] font-black tracking-wide ${color} ${
        styles[value] ? "text-[#171717]" : ""
      }`}
    >
      {label}
    </span>
  );
}
