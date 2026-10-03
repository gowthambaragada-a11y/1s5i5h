import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import LoginForm from "./components/LoginForm";
import { isBackendReachable } from "./api/client";
import type { Session } from "./api/auth";
import DashboardPage from "./pages/DashboardPage";
import DevicesPage from "./pages/DevicesPage";
import FindingsPage from "./pages/FindingsPage";
import RemediationPage from "./pages/RemediationPage";
import { useSession } from "./hooks/useSession";

/** The four pages, wrapped in the shell. `session` is null in static-demo mode. */
function Shell({ session }: { session: Session | null }) {
  return (
    <Routes>
      <Route element={<Layout session={session} />}>
        <Route index element={<DashboardPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="remediation" element={<RemediationPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

/** Blank frame while the backend probe and stored token settle. */
function Pending() {
  return <div className="login-shell" />;
}

/**
 * The backend authenticates every endpoint except liveness and login, so an
 * unauthenticated visitor would get a 401 from all four pages.
 *
 * The gate sits above the shell rather than inside each route: showing the
 * sidebar to someone who cannot open any of its links is worse than showing a
 * login form alone.
 */
export function App() {
  const session = useSession();
  // `undefined` until the probe settles. The choice between "sign in" and "serve
  // the snapshot" cannot wait for the first data request: on a static deployment
  // there is nothing to authenticate against, so gating on the session alone
  // would leave the demo permanently unreachable behind a login form.
  const [backendKnown, setBackendKnown] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    let active = true;
    void isBackendReachable().then((reachable) => {
      if (active) setBackendKnown(reachable);
    });
    return () => {
      active = false;
    };
  }, []);

  if (backendKnown === undefined) return <Pending />;

  if (backendKnown) {
    // Live backend. `undefined` is "still verifying the stored token" -- render
    // nothing rather than the login form, which would flash on every reload.
    if (session === undefined) return <Pending />;
    if (session === null) return <LoginForm />;
    return <Shell session={session} />;
  }

  return <Shell session={null} />;
}

export default App;