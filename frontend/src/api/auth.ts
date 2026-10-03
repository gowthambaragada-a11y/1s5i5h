/**
 * Bearer token storage and the login call.
 *
 * Where the token lives is the whole security question here, so it is worth being
 * explicit about the trade-off:
 *
 * - **sessionStorage** (chosen): a token in `localStorage` survives the browser
 *   being closed and is readable by any script on the origin, so one bad XSS
 *   becomes permanent credential theft. sessionStorage is scoped to the tab and
 *   is gone when it closes.
 * - The cost is re-login after closing the tab. For a security tool that is the
 *   right trade.
 * - **A real production deployment should move to httpOnly cookies** with CSRF
 *   protection. That requires server-side session state, so it is not something
 *   to fake in the client.
 */

const STORAGE_KEY = "netguard:token";

export interface Session {
  accessToken: string;
  username: string;
  role: string;
  /** Epoch millis when the token stops being usable. */
  expiresAt: number;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  username: string;
  role: string;
}

/** What the backend reports about which accounts exist. */
export interface AuthStatus {
  users_table_available: boolean;
  demo_accounts: boolean;
}

let cached: Session | null | undefined;

/**
 * Current session, or null when signed out.
 *
 * Cached because every request needs the token and re-parsing JSON per request
 * is wasteful; `undefined` means "not read yet", `null` means "known signed out".
 */
export function getSession(): Session | null {
  if (cached !== undefined) return cached;
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) {
      cached = null;
      return null;
    }
    const parsed = JSON.parse(raw) as Session;
    // Drop an expired token on sight rather than sending it and reading a 401.
    if (typeof parsed?.expiresAt !== "number" || parsed.expiresAt <= Date.now()) {
      window.sessionStorage.removeItem(STORAGE_KEY);
      cached = null;
      return null;
    }
    cached = parsed;
    return parsed;
  } catch {
    // Corrupt or unreadable storage is treated as signed out, never as a crash.
    cached = null;
    return null;
  }
}

export function setSession(session: Session): void {
  cached = session;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    /* Private mode with storage disabled: stay in memory for this page load. */
  }
}

export function clearSession(): void {
  cached = null;
  try {
    window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* nothing to do */
  }
}

/** Listeners fired when the session changes, so the shell can re-render. */
const listeners = new Set<(session: Session | null) => void>();

export function onSessionChange(listener: (session: Session | null) => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function announce(session: Session | null): void {
  for (const listener of listeners) listener(session);
}

/**
 * Exchanges credentials for a token.
 *
 * Imported lazily to avoid a cycle: client.ts imports this module for the
 * Authorization header, and the login call needs client.ts's fetch and error
 * handling.
 */
export async function login(username: string, password: string): Promise<Session> {
  const { request } = await import("./client");
  const body = await request<LoginResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  const session: Session = {
    accessToken: body.access_token,
    username: body.username,
    role: body.role,
    expiresAt: Date.now() + body.expires_in * 1000,
  };
  setSession(session);
  announce(session);
  return session;
}

export async function logout(): Promise<void> {
  clearSession();
  announce(null);
}

/** True when an error means "this token is not accepted", not "the call failed". */
function isAuthRejection(error: unknown): boolean {
  const status = (error as { status?: unknown }).status;
  return status === 401 || status === 403;
}

/**
 * Verifies the stored token is still accepted, e.g. after a backend restart.
 *
 * Only an actual rejection logs the user out. A network failure must not: on a
 * free Render instance the first request after a sleep period fails to connect
 * while the instance wakes, and treating that as "your session ended" would sign
 * the operator out of a perfectly valid token every time the service idles.
 */
export async function verifySession(): Promise<Session | null> {
  const session = getSession();
  if (!session) return null;
  try {
    const { request } = await import("./client");
    await request("/auth/me");
    return session;
  } catch (error) {
    if (isAuthRejection(error)) {
      // An invalid or expired token must not linger and produce 401s forever.
      await logout();
      return null;
    }
    return session;
  }
}

/**
 * Drops the session after the server rejects a token mid-session.
 *
 * Called from the request layer so an expiry surfaces as the login form instead
 * of every page showing an error the user cannot clear.
 */
export function handleUnauthorized(): void {
  if (getSession() !== null) {
    clearSession();
    announce(null);
  }
}