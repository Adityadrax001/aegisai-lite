import { Suspense, useCallback, useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import Header from './Header.jsx'
import MobileNavigation from './MobileNavigation.jsx'
import LogoutButton from "../auth/LogoutButton.jsx";
function readStoredTheme() {
  try {
    return localStorage.getItem('aegis-theme') === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export default function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setTheme] = useState(readStoredTheme)
  const closeMenu = useCallback(() => setMenuOpen(false), [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('aegis-theme', theme)
    } catch {
      /* storage unavailable: theme still applies for this session */
    }
  }, [theme])

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r-[3px] border-border bg-sidebar lg:block">
        <Sidebar />
        <LogoutButton />
      </aside>
      <MobileNavigation open={menuOpen} onClose={closeMenu} />

      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          onOpenMenu={() => setMenuOpen(true)}
          theme={theme}
          onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        />
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 md:px-6">
          <Suspense
            fallback={<p className="nb-label">Loading…</p>}
          >
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  )
}