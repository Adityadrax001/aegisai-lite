import { LayoutDashboard, ListChecks, BarChart3, UsersRound} from 'lucide-react'

export const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/events', label: 'Security Events', icon: ListChecks, end: false },
  { to: '/analytics', label: 'Evaluation', icon: BarChart3, end: false },
  { to: "/admins", label: "Admin Management", icon: UsersRound },
]