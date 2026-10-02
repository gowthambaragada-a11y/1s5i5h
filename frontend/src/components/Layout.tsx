import { NavLink, Outlet } from "react-router-dom";
import { apiBaseUrl } from "../api/client";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/findings", label: "Findings", end: false },
  { to: "/devices", label: "Devices", end: false },
  { to: "/remediation", label: "Remediation Queue", end: false },
];

/** App shell: fixed sidebar navigation plus the routed page body. */
export function Layout() {
  const target = apiBaseUrl || window.location.origin;

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
            <span className="status-dot live" aria-hidden="true" />
            <span>API: {target}</span>
          </div>
          <div>SIH 2026 - team Anvaya</div>
        </div>
      </nav>

      <div className="app-main">
        <Outlet />
      </div>
    </div>
  );
}

export default Layout;