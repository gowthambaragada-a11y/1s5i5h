import { useCallback, useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { apiBaseUrl, isReadOnly, onDemoModeChange } from "../api/client";
import { logout } from "../api/auth";
import type { Session } from "../api/auth";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/findings", label: "Findings", end: false },
  { to: "/devices", label: "Devices", end: false },
  { to: "/remediation", label: "Remediation Queue", end: false },
];

interface LayoutProps {
  /**
   * Passed in rather than read from `useSession` here.
   *
   * The hook verifies the stored token against `/auth/me` on mount, so calling it
   * a second time would send that request twice per page load. On a free backend
   * that sleeps after 15 minutes, a duplicate round-trip is a duplicate
   * cold-start wait.
   *
   * Null in static-demo mode, where there is no session to show.
   */
  session: Session | null;
}

/** App shell: fixed sidebar navigation plus the routed page body. */
export function Layout({ session }: LayoutProps) {
  const target = apiBaseUrl || window.location.origin;
  // Demo mode is decided by the first request, which settles after the initial
  // render, so the banner subscribes rather than reading a flag during render.
  const [readOnly, setReadOnly] = useState(isReadOnly());
  useEffect(() => onDemoModeChange(() => setReadOnly(true)), []);

  const signOut = useCallback(() => {
    // Cleared locally; the JWT remains valid until it expires, so the next
    // request is what proves it is actually gone.
    void logout();
  }, []);

  return (
    <div className="app-shell">
      <nav className="app-nav">
        <div className="brand">
          <span className="brand-mark">NETGUARD-AI</span>
          <span className="brand-sub">Config compliance SOC</span>
        </div>

        <div className="nav-links">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              {item.label}
            </NavLink>
          ))}
        </div>

        <div className="nav-footer">
          <div className="row" style={{ gap: 6 }}>
            <span className={readOnly ? "status-dot" : "status-dot live"} aria-hidden="true" />
            <span>{readOnly ? "Static snapshot" : `API: ${target}`}</span>
          </div>
          {session && (
            <div className="row" style={{ gap: 6, justifyContent: "space-between" }}>
              <span className="small">
                {session.username} ({session.role})
              </span>
              <button type="button" className="btn sm ghost" onClick={signOut}>
                Sign out
              </button>
            </div>
          )}
          <div>SIH 2026 - team Anvaya</div>
        </div>
      </nav>

      <div className="app-main">
        {readOnly && (
          <div className="alert" role="status" style={{ marginBottom: 16 }}>
            <strong>Static demo.</strong> No backend is reachable, so these are real
            analysis results for the bundled sample configurations, captured by running
            the pipeline once. Uploading and remediation review are disabled.
          </div>
        )}
        <Outlet />
      </div>
    </div>
  );
}

export default Layout;