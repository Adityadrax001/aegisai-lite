import { NavLink } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { NAV_ITEMS } from '../../utils/constants.js'
import LogoutButton from "../auth/LogoutButton.jsx";
export default function Sidebar({ onNavigate }) {
  
  return (
    
<div className="flex h-full flex-col gap-6 p-4">
  <div className="nb-card flex items-center gap-2 bg-accent px-3 py-2 !shadow-[4px_4px_0_0_var(--shadow-color)]">
    <ShieldCheck className="h-5 w-5 text-black" aria-hidden="true" />
    <span className="text-sm font-bold uppercase tracking-tight text-black">
      AegisAI-Lite
    </span>
  </div>

  <nav aria-label="Primary" className="flex flex-col gap-3">
    {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
      <NavLink
        key={to}
        to={to}
        end={end}
        onClick={onNavigate}
        className={({ isActive }) =>
          `flex items-center gap-3 border-[3px] border-border px-3 py-2 text-sm font-bold uppercase transition-transform ${
            isActive
              ? "bg-accent text-black nb-shadow-sm"
              : "bg-surface text-text hover:-translate-x-0.5 hover:-translate-y-0.5 hover:bg-info hover:text-black hover:nb-shadow-sm"
          }`
        }
      >
        <Icon className="h-4 w-4" aria-hidden="true" />
        {label}
      </NavLink>
    ))}
  </nav>

<div className="mt-auto space-y-4">
  <p className="nb-card bg-pink p-3 text-xs font-bold text-black !shadow-[4px_4px_0_0_var(--shadow-color)]">
    The LLM recommends. The deterministic policy decides.
    All actions are simulated.
  </p>

  <LogoutButton />
</div>
</div>

  )
}