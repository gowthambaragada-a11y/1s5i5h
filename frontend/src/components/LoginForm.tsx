import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { AuthStatus } from "../api/auth";
import { login } from "../api/auth";
import { describeError, getAuthStatus } from "../api/client";

/**
 * Operator sign-in.
 *
 * No callback prop: `login()` announces the new session through
 * `onSessionChange`, which is what `useSession` and therefore the router already
 * subscribe to. Passing an `onSignedIn` as well would just be a second, no-op
 * path to the same re-render.
 */
export function LoginForm() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);

  // Tells the operator up front whether the well-known demo passwords will work,
  // rather than letting them fail a login and guess.
  useEffect(() => {
    let active = true;
    getAuthStatus()
      .then((status) => {
        if (active) setAuthStatus(status);
      })
      .catch(() => {
        /* The login attempt itself will report an unreachable backend. */
      });
    return () => {
      active = false;
    };
  }, []);

  const submit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      setError(null);
      if (!username.trim() || !password) {
        setError("Enter a username and password.");
        return;
      }
      setBusy(true);
      try {
        await login(username.trim(), password);
        // The session listener re-renders the shell; this only makes sure a
        // stale deep link does not survive the transition.
        navigate("/", { replace: true });
      } catch (cause) {
        setError(describeError(cause));
      } finally {
        setBusy(false);
      }
    },
    [navigate, password, username],
  );

  return (
    <div className="login-shell">
      <form className="card login-card" onSubmit={submit}>
        <div className="card-head">
          <span className="card-title">Sign in</span>
          {busy && <span className="chip accent">authenticating</span>}
        </div>
        <div className="card-body stack">
          <p className="muted small">
            NETGUARD-AI is a security tool, so every request is authenticated. Scanning a
            configuration or approving a remediation requires an operator account.
          </p>

          <div className="field">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              value={username}
              autoComplete="username"
              onChange={(event) => setUsername(event.target.value)}
              disabled={busy}
            />
          </div>

          <div className="field">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(event) => setPassword(event.target.value)}
              disabled={busy}
            />
          </div>

          {error && <div className="alert">{error}</div>}

          <div className="btn-row">
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? "Signing in..." : "Sign in"}
            </button>
          </div>

          {authStatus?.demo_accounts && (
            <div className="alert warn">
              <div className="stack sm">
                <strong>Demo accounts are enabled on this deployment</strong>
                <span className="small">
                  Local/demo builds accept <code>admin</code> / <code>admin123!</code>. Public
                  deployments must set <code>ALLOW_DEMO_ACCOUNTS=false</code>, so if this is a
                  shared instance, use the credentials you were given.
                </span>
              </div>
            </div>
          )}
        </div>
      </form>
    </div>
  );
}

export default LoginForm;