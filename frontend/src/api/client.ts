import { getSession, handleUnauthorized } from "./auth";
import type { AuthStatus } from "./auth";
import type {
  AnalysisSummary,
  DashboardSummary,
  DeviceCompliance,
  Finding,
  FindingQuery,
  Paged,
  RejectRequest,
  Remediation,
  RemediationQuery,
  VendorDetection,
} from "../types/api";

/** Base URL of the backend. Empty string means "same origin", which the dev server proxies. */
const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

/** Resolved against Vite's `base` so the subpath deploy fetches correctly. */
const DEMO_DATA_URL = `${import.meta.env.BASE_URL}demo-data.json`;

const configuredTimeout = Number(import.meta.env.VITE_API_TIMEOUT_MS);
const DEFAULT_TIMEOUT_MS =
  Number.isFinite(configuredTimeout) && configuredTimeout > 0 ? configuredTimeout : 30_000;

const API_PREFIX = "/api/v1";

/** FastAPI validation errors arrive as a list of {loc, msg, type} objects. */
interface FastApiValidationItem {
  loc?: (string | number)[];
  msg?: string;
  type?: string;
}

/**
 * Error carrying the server's own explanation. `detail` is what FastAPI puts in
 * the body for both `HTTPException(detail=...)` and request-validation failures,
 * so we surface it verbatim instead of a generic "request failed" string.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly url: string;
  readonly body: unknown;

  constructor(params: { status: number; detail: string; url: string; body?: unknown }) {
    super(params.detail);
    this.name = "ApiError";
    this.status = params.status;
    this.detail = params.detail;
    this.url = params.url;
    this.body = params.body;
  }

  /** True when the failure is the browser/network layer rather than the server. */
  get isNetworkError(): boolean {
    return this.status === 0;
  }
}

/* -------------------------------------------------------------------------- */
/* Static-demo fallback                                                        */
/* -------------------------------------------------------------------------- */

interface DemoDataset {
  dashboard: DashboardSummary;
  devices: DeviceCompliance[];
  findings: Finding[];
  remediations: Remediation[];
}

let demoCache: DemoDataset | null = null;
let demoUnavailable = false;

/**
 * True once any read has fallen back to the bundled snapshot. Drives the banner
 * so a static deployment cannot be mistaken for a live one.
 */
let usingDemoData = false;

/** True when the app is serving the static snapshot, so writes must be refused. */
export function isReadOnly(): boolean {
  return usingDemoData;
}

const demoModeListeners = new Set<() => void>();

/**
 * Notifies when the app drops into demo mode.
 *
 * The first successful read decides this, which happens after the initial
 * render, so a component cannot read the flag synchronously. Subscribing avoids
 * polling on a timer and re-renders only the components that care.
 */
export function onDemoModeChange(listener: () => void): () => void {
  demoModeListeners.add(listener);
  return () => {
    demoModeListeners.delete(listener);
  };
}

/**
 * Whether the bundled snapshot may be shown when no backend answers.
 *
 * On for the hackathon demo, off for a live deployment: a snapshot generated
 * from sample configs is stale the moment real data starts arriving, so serving
 * it after an outage would quietly show last week's findings as current.
 */
const DEMO_FALLBACK_ENABLED = import.meta.env.VITE_ENABLE_DEMO_FALLBACK !== "false";

async function loadDemoData(): Promise<DemoDataset | null> {
  if (!DEMO_FALLBACK_ENABLED) return null;
  if (demoCache !== null || demoUnavailable) return demoCache;
  try {
    const response = await fetch(DEMO_DATA_URL, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`demo snapshot returned ${response.status}`);
    demoCache = (await response.json()) as DemoDataset;
  } catch {
    // The snapshot is itself optional; without it the real error stands.
    demoUnavailable = true;
    return null;
  }
  return demoCache;
}

/**
 * Decides once, up front, whether a real backend is serving this origin.
 *
 * Inferring this from a failed data request is unreliable: on GitHub Pages an
 * `/api/v1/...` path is answered by our own 404.html with status 404 and an HTML
 * body, which is indistinguishable from a genuine "not found" unless you inspect
 * the body. So we ask the one endpoint that must answer if a backend is really
 * there -- `/healthz`, which touches no dependency -- and commit to the answer
 * for the session.
 *
 * Any outcome other than a well-formed health response means "no backend":
 * unreachable, HTML instead of JSON, an auth challenge, a 404 from the static
 * host. In that case reads are served from the snapshot and writes are refused.
 */
async function detectBackend(): Promise<boolean> {
  try {
    const response = await fetch(`${BASE_URL}${API_PREFIX}/healthz`, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return false;
    const contentType = response.headers.get("content-type") ?? "";
    // A static host answering 404.html with 200-ish behaviour still lands here;
    // requiring JSON keeps an HTML body from being read as a healthy API.
    if (!contentType.includes("application/json")) return false;
    const body = (await response.json()) as { status?: string; service?: string };
    return body?.status === "ok" && body?.service === "netguard-ai";
  } catch {
    return false;
  }
}

let backendAvailable: Promise<boolean> | null = null;

function backendIsAvailable(): Promise<boolean> {
  // Memoised so concurrent first-load requests trigger a single probe.
  backendAvailable ??= detectBackend();
  return backendAvailable;
}

/**
 * Whether a live backend answers, resolved once.
 *
 * Exposed because the choice of "show a login form or serve the snapshot" cannot
 * be deferred to the first data request: on a static deployment there is nothing
 * to log in to, so gating on the session would leave the demo unreachable.
 */
export async function isBackendReachable(): Promise<boolean> {
  const reachable = await backendIsAvailable();
  if (!reachable) enterDemoMode();
  return reachable;
}

function enterDemoMode(): void {
  if (usingDemoData) return;
  usingDemoData = true;
  for (const listener of demoModeListeners) listener();
}

/**
 * Runs the real request when a backend is present, otherwise serves the bundled
 * snapshot.
 *
 * The snapshot is real pipeline output over the sample configs, produced by
 * `backend/scripts/export_demo_data.py` -- not hand-written numbers. Once a
 * backend has been detected, genuine failures (401/403/404 from a real server)
 * propagate as errors instead of being masked with sample data.
 */
async function withDemoFallback<T>(run: () => Promise<T>, demo: (data: DemoDataset) => T): Promise<T> {
  if (await backendIsAvailable()) return run();

  const data = await loadDemoData();
  if (!data) {
    throw new ApiError({
      status: 0,
      detail: `No NETGUARD-AI backend is reachable at ${BASE_URL || window.location.origin}.`,
      url: `${BASE_URL}${API_PREFIX}/healthz`,
    });
  }
  enterDemoMode();
  return demo(data);
}

/** Aborts the underlying fetch when the server takes too long to answer. */
export class TimeoutError extends Error {
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    super(`Request timed out after ${timeoutMs} ms`);
    this.name = "TimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

function stringifyDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item: FastApiValidationItem) => {
        const where = Array.isArray(item?.loc) ? item.loc.join(".") : "";
        return where ? `${where}: ${item?.msg ?? "invalid"}` : (item?.msg ?? "invalid");
      })
      .join("; ");
  }
  if (detail && typeof detail === "object") {
    try {
      return JSON.stringify(detail);
    } catch {
      return "Unserializable error detail";
    }
  }
  return "Request failed";
}

function buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.append(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Already-stringified body; sent as-is (used for multipart uploads). */
  body?: BodyInit | null;
  headers?: Record<string, string>;
  timeoutMs?: number;
  signal?: AbortSignal;
}

async function parseErrorBody(response: Response): Promise<unknown> {
  const text = await response.text().catch(() => "");
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * Single entry point for every backend call: applies the base URL, JSON headers,
 * a timeout, and turns non-2xx responses into {@link ApiError}.
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const {
    method = "GET",
    body = null,
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    signal,
  } = options;

  const url = `${BASE_URL}${API_PREFIX}${path}`;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(new DOMException("timeout", "TimeoutError")), timeoutMs);

  // Forward an externally supplied abort (e.g. component unmount) into ours.
  const onExternalAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) onExternalAbort();
    else signal.addEventListener("abort", onExternalAbort, { once: true });
  }

  const isFormData = typeof FormData !== "undefined" && body instanceof FormData;
  const session = getSession();
  const finalHeaders: Record<string, string> = {
    Accept: "application/json",
    // Every endpoint except /healthz, /readyz and /auth/login requires this, so
    // it is attached centrally rather than per call site. The login call itself
    // runs while `cached` is still null, so it stays unauthenticated.
    ...(session ? { Authorization: `Bearer ${session.accessToken}` } : {}),
    ...(isFormData || body === null ? {} : { "Content-Type": "application/json" }),
    ...headers,
  };

  let response: Response;
  try {
    response = await fetch(url, { method, headers: finalHeaders, body, signal: controller.signal });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "TimeoutError") {
      throw new TimeoutError(timeoutMs);
    }
    if (cause instanceof DOMException && cause.name === "AbortError") {
      throw cause;
    }
    throw new ApiError({
      status: 0,
      detail: `Cannot reach the NETGUARD-AI API at ${BASE_URL || window.location.origin}. Is the backend running?`,
      url,
    });
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener("abort", onExternalAbort);
  }

  if (!response.ok) {
    // A token can expire mid-session, well after the initial verification. Clear
    // it so the shell falls back to the login form instead of leaving every page
    // showing an error the operator has no way to clear. Excluded for /auth/login
    // itself: a mistyped password is not a reason to discard a working session.
    if (response.status === 401 && !path.startsWith("/auth/login")) {
      handleUnauthorized();
    }
    const payload = await parseErrorBody(response);
    const detail =
      payload && typeof payload === "object" && "detail" in (payload as Record<string, unknown>)
        ? stringifyDetail((payload as Record<string, unknown>).detail)
        : stringifyDetail(payload);
    throw new ApiError({
      status: response.status,
      detail: detail || `${response.status} ${response.statusText}`,
      url,
      body: payload,
    });
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function post<T>(path: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: JSON.stringify(payload),
    signal,
  });
}

/* -------------------------------------------------------------------------- */
/* Analyses                                                                    */
/* -------------------------------------------------------------------------- */

/** Scanning is synchronous on the server: the summary comes back in one response. */
export function uploadConfig(file: File, signal?: AbortSignal): Promise<AnalysisSummary> {
  if (usingDemoData) return Promise.reject(uploadUnavailable());
  const form = new FormData();
  form.append("file", file);
  return request<AnalysisSummary>("/analyze", {
    method: "POST",
    body: form,
    // Uploads can be several megabytes; give them a longer budget than reads.
    timeoutMs: 120_000,
    signal,
  });
}

/** The API returns every supported adapter, each already normalised. */
export function listSupportedVendors(signal?: AbortSignal): Promise<VendorDetection[]> {
  return withDemoFallback(
    () => request<VendorDetection[]>("/vendors", { signal }),
    // Demo mode has no adapter catalogue to report, so derive it from the
    // vendors actually present in the snapshot.
    (data) =>
      [...new Set(data.devices.map((device) => device.vendor))].map((vendor) => ({
        vendor: vendor as VendorDetection["vendor"],
        confidence: 1,
        rule_pack: null,
        candidates: [],
        evidence_precision: "block" as const,
      })),
  );
}

function uploadUnavailable(): ApiError {
  return new ApiError({
    status: 0,
    detail:
      "Scanning a configuration needs a running NETGUARD-AI backend. This page is showing a static snapshot of the bundled sample configurations.",
    url: "(demo-mode)",
  });
}

export function getAnalysis(analysisId: string, signal?: AbortSignal): Promise<AnalysisSummary> {
  return request<AnalysisSummary>(`/analyses/${encodeURIComponent(analysisId)}`, { signal });
}

/* -------------------------------------------------------------------------- */
/* Dashboard / findings / devices                                              */
/* -------------------------------------------------------------------------- */

/** Which accounts this deployment accepts. Used to warn before a demo login. */
export function getAuthStatus(signal?: AbortSignal): Promise<AuthStatus> {
  return request<AuthStatus>("/auth/auth-status", { signal, timeoutMs: 8_000 });
}

/**
 * Single-page test hook: uploads a config and returns the findings it produced.
 * Kept in the client so the deployment smoke test exercises the same code path
 * the UI uses, rather than a separate script that can drift from it.
 */
export function healthz(signal?: AbortSignal): Promise<{ status: string; service: string }> {
  return request<{ status: string; service: string }>("/healthz", { signal });
}

export function getDashboardSummary(signal?: AbortSignal): Promise<DashboardSummary> {
  return withDemoFallback(
    () => request<DashboardSummary>("/dashboard", { signal }),
    (data) => data.dashboard,
  );
}

export function listFindings(query: FindingQuery = {}, signal?: AbortSignal): Promise<Paged<Finding>> {
  return withDemoFallback(
    () => request<Paged<Finding>>(`/findings${buildQuery({ ...query })}`, { signal }),
    (data) => filterDemoFindings(data, query),
  );
}

/** Applies the same filters the API would, so demo mode honours the query UI. */
function filterDemoFindings(data: DemoDataset, query: FindingQuery): Paged<Finding> {
  const { severity, framework, device_id, status, limit = 50, offset = 0 } = query;
  let items = data.findings;
  if (severity) items = items.filter((f) => f.severity === severity);
  if (status) items = items.filter((f) => f.status === status);
  if (device_id) items = items.filter((f) => f.device_id === device_id);
  if (framework) {
    items = items.filter((f) => f.controls.some((c) => c.framework === framework));
  }
  return { items: items.slice(offset, offset + limit), total: items.length, limit, offset };
}

export function listDevices(signal?: AbortSignal): Promise<{ items: DeviceCompliance[]; total: number }> {
  return withDemoFallback(
    // The API answers with a bare array; normalise to the paged shape the UI uses.
    async () => {
      const devices = await request<DeviceCompliance[]>("/devices", { signal });
      return { items: devices, total: devices.length };
    },
    (data) => ({ items: data.devices, total: data.devices.length }),
  );
}

export function getDevice(deviceId: string, signal?: AbortSignal): Promise<DeviceCompliance> {
  return withDemoFallback(
    () => request<DeviceCompliance>(`/devices/${encodeURIComponent(deviceId)}`, { signal }),
    (data) => {
      const found = data.devices.find((d) => d.device_id === deviceId);
      if (!found) throw new ApiError({ status: 404, detail: `device ${deviceId} not found`, url: deviceId });
      return found;
    },
  );
}

/* -------------------------------------------------------------------------- */
/* Remediation review queue                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The API nests the plan under `plan` and repeats finding metadata alongside
 * it, because the queue view needs the severity without a second request. The
 * UI wants one flat row, so flatten on the way in.
 */
interface RemediationDetail {
  plan: Omit<Remediation, "finding_id" | "reviewed_by" | "reviewed_at" | "review_note"> & {
    finding_id: string;
    reviewed_by?: string | null;
    reviewed_at?: string | null;
    review_note?: string | null;
  };
  finding_id: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
}

function flattenRemediation(detail: RemediationDetail): Remediation {
  return {
    ...detail.plan,
    finding_id: detail.finding_id,
    reviewed_by: detail.reviewed_by,
    reviewed_at: detail.reviewed_at,
    review_note: detail.review_note,
  };
}

export function listRemediations(
  query: RemediationQuery = {},
  signal?: AbortSignal,
): Promise<{ items: Remediation[]; total: number }> {
  return withDemoFallback(
    async () => {
      // The API filters by status server-side but has no finding_id filter, so
      // that one is applied here to keep both paths behaving the same.
      const rows = await request<RemediationDetail[]>(
        `/remediations${buildQuery({ status: query.status })}`,
        { signal },
      );
      const items = rows
        .map(flattenRemediation)
        .filter((item) => !query.finding_id || item.finding_id === query.finding_id);
      return { items, total: items.length };
    },
    (data) => {
      const { status, finding_id } = query;
      let items = data.remediations;
      if (status) items = items.filter((r) => r.status === status);
      if (finding_id) items = items.filter((r) => r.finding_id === finding_id);
      return { items, total: items.length };
    },
  );
}

/**
 * Review actions are unavailable in demo mode.
 *
 * Approving a proposal against a static snapshot would be a lie: there is no
 * server holding the decision, so the UI must not pretend one was recorded.
 */
export async function approveRemediation(
  remediationId: string,
  signal?: AbortSignal,
): Promise<Remediation> {
  if (!(await backendIsAvailable())) return Promise.reject(reviewUnavailable("Approving"));
  const detail = await post<RemediationDetail>(
    `/remediations/${encodeURIComponent(remediationId)}/review`,
    { decision: "approved" },
    signal,
  );
  return flattenRemediation(detail);
}

export async function rejectRemediation(
  remediationId: string,
  payload: RejectRequest,
  signal?: AbortSignal,
): Promise<Remediation> {
  if (!(await backendIsAvailable())) return Promise.reject(reviewUnavailable("Rejecting"));
  const detail = await post<RemediationDetail>(
    `/remediations/${encodeURIComponent(remediationId)}/review`,
    { decision: "rejected", note: payload.reason },
    signal,
  );
  return flattenRemediation(detail);
}

function reviewUnavailable(action: string): ApiError {
  return new ApiError({
    status: 0,
    detail: `${action} a remediation needs a running NETGUARD-AI backend. This page is showing a static snapshot of real analysis results.`,
    url: "(demo-mode)",
  });
}

/** Human-facing message for any thrown value, safe to render directly. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.detail;
  if (error instanceof TimeoutError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}

export const apiBaseUrl = BASE_URL;