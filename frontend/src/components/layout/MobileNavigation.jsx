import { useEffect } from 'react'
import { X } from 'lucide-react'
import Sidebar from './Sidebar.jsx'

export default function MobileNavigation({ open, onClose }) {
  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-40 lg:hidden">
      <button
        type="button"
        aria-label="Close menu"
        onClick={onClose}
        className="absolute inset-0 bg-black/70"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Navigation menu"
        className="absolute inset-y-0 left-0 w-72 border-r-[3px] border-border bg-sidebar"
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close menu"
          className="nb-btn absolute right-3 top-3 !p-1.5"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
        <div className="pt-12">
          <Sidebar onNavigate={onClose} />
        </div>
      </div>
    </div>
  )
}