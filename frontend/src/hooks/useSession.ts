import { useEffect, useState } from "react";
import type { Session } from "../api/auth";
import { getSession, onSessionChange, verifySession } from "../api/auth";

/**
 * The current session, or `undefined` while it is still being established.
 *
 * `undefined` and `null` mean different things and the router depends on it:
 * `undefined` is "not known yet", so rendering a login form would flash on every
 * reload; `null` is "known signed out".
 */
export function useSession(): Session | null | undefined {
  // Read storage synchronously rather than waiting on the network. The stored
  // token carries its own expiry, so it is already enough to render with, and
  // waiting would mean a blank frame on every reload -- which on a free-tier
  // backend that is asleep for 15 minutes means a blank frame for half a minute.
  const [session, setSession] = useState<Session | null | undefined>(() => getSession() ?? undefined);

  useEffect(() => {
    let active = true;
    // Runs for a stored token too, not just when storage is empty. The initial
    // state is a guess from a previous session; only the server knows whether it
    // is still accepted, and a guess that survives to the first request would put
    // a dead token on every page.
    void verifySession().then((verified) => {
      if (active) setSession(verified);
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => onSessionChange(setSession), []);

  return session;
}