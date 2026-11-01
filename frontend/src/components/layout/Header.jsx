import { Menu, Moon, Sun, FlaskConical } from 'lucide-react'

export default function Header({ onOpenMenu, theme, onToggleTheme }) {
  const isDark = theme === 'dark'
  return (
    <header className="sticky top-0 z-30 flex min-h-16 items-center gap-3 border-b-[3px] border-border bg-surface px-4">
      <button
        type="button"
        onClick={onOpenMenu}
        aria-label="Open menu"
        className="nb-btn !p-2 lg:hidden"
      >
        <Menu className="h-5 w-5" aria-hidden="true" />
      </button>

      <div className="nb-badge !bg-warning !px-3 !py-1.5 !text-xs">
        <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
        <span>Simulation mode · no action executed</span>
      </div>

      <button
        type="button"
        onClick={onToggleTheme}
        aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
        className="nb-btn ml-auto !p-2"
      >
        {isDark ? (
          <Sun className="h-4 w-4" aria-hidden="true" />
        ) : (
          <Moon className="h-4 w-4" aria-hidden="true" />
        )}
      </button>
    </header>
  )
}