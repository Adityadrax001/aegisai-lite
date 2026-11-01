
import { ArrowUpRight } from "lucide-react";

export default function MetricCard({
  title,
  value,
  description,
  icon: Icon,
  status = "neutral",
}) {
  const statusStyles = {
    neutral: "text-slate-400 bg-slate-400/10",
    success: "text-emerald-400 bg-emerald-400/10",
    warning: "text-amber-400 bg-amber-400/10",
    danger: "text-red-400 bg-red-400/10",
  };

  const currentStyle = statusStyles[status] ?? statusStyles.neutral;

  return (
    <article className="rounded-xl border border-white/10 bg-[#141820] p-5 transition-colors hover:border-white/20">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-slate-400">
          {title}
        </p>

        {Icon && (
          <span className={`rounded-lg p-2 ${currentStyle}`}>
            <Icon size={18} aria-hidden="true" />
          </span>
        )}
      </div>

      <div className="mt-5">
        <p className="text-3xl font-semibold tracking-tight text-slate-100">
          {value}
        </p>

        {description && (
          <p className="mt-2 flex items-center gap-1 text-xs text-slate-500">
            <ArrowUpRight size={13} aria-hidden="true" />
            {description}
          </p>
        )}
      </div>
    </article>
  );
}
