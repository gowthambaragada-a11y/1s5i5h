import type {
  AnalysisAccepted,
  AnalysisRequest,
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
  VendorDetectRequest,
} from "../types/api";

/** Base URL of the backend. Empty string means "same origin", which the dev server proxies. */
const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

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
  const finalHeaders: Record<string, string> = {
    Accept: "application/json",
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

export function uploadConfig(file: File, signal?: AbortSignal): Promise<AnalysisSummary> {
  const form = new FormData();
  form.append("file", file);
  return request<AnalysisSummary>("/analyses/upload", {
    method: "POST",
    body: form,
    // Uploads can be several megabytes; give them a longer budget than reads.
    timeoutMs: 120_000,
    signal,
  });
}

export function detectVendor(payload: VendorDetectRequest, signal?: AbortSignal): Promise<VendorDetection> {
  return post<VendorDetection>("/analyses/detect-vendor", payload, signal);
}

export function startAnalysis(payload: AnalysisRequest, signal?: AbortSignal): Promise<AnalysisAccepted> {
  return post<AnalysisAccepted>("/analyses", payload, signal);
}

export function getAnalysis(analysisId: string, signal?: AbortSignal): Promise<AnalysisSummary> {
  return request<AnalysisSummary>(`/analyses/${encodeURIComponent(analysisId)}`, { signal });
}

/* -------------------------------------------------------------------------- */
/* Dashboard / findings / devices                                              */
/* -------------------------------------------------------------------------- */

export function getDashboardSummary(signal?: AbortSignal): Promise<DashboardSummary> {
  return request<DashboardSummary>("/dashboard/summary", { signal });
}

export function listFindings(query: FindingQuery = {}, signal?: AbortSignal): Promise<Paged<Finding>> {
  return request<Paged<Finding>>(`/findings${buildQuery({ ...query })}`, { signal });
}

export function listDevices(signal?: AbortSignal): Promise<{ items: DeviceCompliance[]; total: number }> {
  return request<{ items: DeviceCompliance[]; total: number }>("/devices", { signal });
}

export function getDevice(deviceId: string, signal?: AbortSignal): Promise<DeviceCompliance> {
  return request<DeviceCompliance>(`/devices/${encodeURIComponent(deviceId)}`, { signal });
}

/* -------------------------------------------------------------------------- */
/* Remediation review queue                                                    */
/* -------------------------------------------------------------------------- */

export function listRemediations(
  query: RemediationQuery = {},
  signal?: AbortSignal,
): Promise<{ items: Remediation[]; total: number }> {
  return request<{ items: Remediation[]; total: number }>(
    `/remediations${buildQuery({ ...query })}`,
    { signal },
  );
}

export function approveRemediation(remediationId: string, signal?: AbortSignal): Promise<Remediation> {
  return post<Remediation>(
    `/remediations/${encodeURIComponent(remediationId)}/approve`,
    {},
    signal,
  );
}

export function rejectRemediation(
  remediationId: string,
  payload: RejectRequest,
  signal?: AbortSignal,
): Promise<Remediation> {
  return post<Remediation>(
    `/remediations/${encodeURIComponent(remediationId)}/reject`,
    payload,
    signal,
  );
}

/** Human-facing message for any thrown value, safe to render directly. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.detail;
  if (error instanceof TimeoutError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}

export const apiBaseUrl = BASE_URL;