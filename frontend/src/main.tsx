import React, { useEffect, useRef } from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, useNavigate } from "react-router-dom";
import App from "./App";
import "./styles.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("Root element #root is missing from index.html");
}

/**
 * Vite's `base` already accounts for the GitHub Pages subpath
 * ("/1s5i5h/"). BrowserRouter needs that same prefix so a hard refresh on
 * /1s5i5h/findings does not 404 -- GitHub Pages has no server-side rewrite, so
 * the app must own routing for every path under the project.
 *
 * In dev `base` is still the Pages path, which is harmless: the Vite dev server
 * serves the SPA at "/".
 */
const basename = import.meta.env.BASE_URL.replace(/\/+$/, "");

/**
 * Replay a deep link that GitHub Pages answered with 404.html.
 *
 * Pages has no rewrite rules, so /1s5i5h/findings serves 404.html, which stashes
 * the original URL here and boots us at the root. Recovering the path is what
 * makes a refresh or a shared link work instead of silently landing on the
 * dashboard.
 */
function consumeRedirect(): string | null {
  const key = "netguard:redirect";
  try {
    const stored = window.sessionStorage.getItem(key);
    if (!stored) return null;
    window.sessionStorage.removeItem(key);
    const url = new URL(stored);
    // Only replay same-origin paths; an absolute external URL is not ours to follow.
    if (url.origin !== window.location.origin) return null;
    return url.pathname + url.search + url.hash;
  } catch {
    return null;
  }
}

const redirectPath = consumeRedirect();

/**
 * Redirects once on mount, then renders the app. Doing this in an effect rather
 * than swapping the tree keeps <App /> mounted so the router state stays
 * consistent instead of remounting on every deep link.
 */
function Root(): React.ReactElement {
  const navigate = useNavigate();
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    if (redirectPath) navigate(redirectPath, { replace: true });
  }, [navigate]);

  return <App />;
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <BrowserRouter basename={basename || undefined}>
      <Root />
    </BrowserRouter>
  </React.StrictMode>,
);