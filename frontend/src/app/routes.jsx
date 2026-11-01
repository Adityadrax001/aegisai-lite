
import AppShell from "../components/layout/AppShell.jsx";

import Dashboard from "../pages/Dashboard.jsx";
import SecurityEvents from "../pages/SecurityEvents.jsx";
import Investigation from "../pages/Investigation.jsx";
import Analytics from "../pages/Analytics.jsx";
import NotFound from "../pages/NotFound.jsx";

import Login from "../pages/Login.jsx";
import ProtectedRoute from "../components/auth/ProtectedRoute.jsx";
import AdminManagement from "../pages/AdminManagement.jsx";
export const routes = [
  {
    path: "/login",
    element: <Login />,
  },
  {
    element: <ProtectedRoute />,
    children: [
      {
        path: "/",
        element: <AppShell />,
        children: [
          { index: true, element: <Dashboard /> },
          { path: "events", element: <SecurityEvents /> },
          {
            path: "events/:eventId",
            element: <Investigation />,
          },
          { path: "analytics", element: <Analytics /> },
          {
  path: "admins",
  element: <AdminManagement />,
},
        ],
      },
    ],
  },
  {
    path: "*",
    element: <NotFound />,
  },
];
