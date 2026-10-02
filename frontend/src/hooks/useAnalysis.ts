import { useCallback, useEffect, useRef, useState } from "react";
import {
  approveRemediation,
  describeError,
  detectVendor,
  getAnalysis,
  getDashboardSummary,
  getDevice,
  listDevices,
  listFindings,
  listRemediations,
  rejectRemediation,
  startAnalysis,
  uploadConfig,
} from "../api/client";
import type {
  AnalysisAccepted,
  AnalysisRequest,
  AnalysisSummary,
  DashboardSummary,
  DeviceCompliance,
  Finding,
  FindingQuery,
  Paged,
  Remediation,
  RemediationQuery,
  VendorDetection,
} from "../types/api";

export interface ResourceState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs an async loader whenever `deps` change and cancels the previous request
 * when a new one starts or the component unmounts, so a slow response can never
 * overwrite fresher state.
 */
function useResource<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
  options: { enabled?: boolean } = {},
): ResourceState<T> {
  const enabled = options.enabled ?? true;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [nonce, setNonce] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError(null);

    loaderRef
      .current(controller.signal)
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((cause: unknown) => {
        if (!active || controller.signal.aborted) return;
        setError(describeError(cause));
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
      controller.abort();
    };
    // `deps` is spread on purpose: callers pass primitives, and this keeps the
    // effect keyed to exact values instead of a new array identity each render.
  }, [...deps, enabled, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  return { data, error, loading, reload };
}

/* -------------------------------------------------------------------------- */
/* Read hooks                                                                  */
/* -------------------------------------------------------------------------- */

export function useDashboardSummary(): ResourceState<DashboardSummary> {
  return useResource<DashboardSummary>((signal) => getDashboardSummary(signal), []);
}

export function useFindings(query: FindingQuery): ResourceState<Paged<Finding>> {
  const { severity, framework, device_id, status, limit = 50, offset = 0 } = query;
  return useResource<Paged<Finding>>(
    (signal) => listFindings({ severity, framework, device_id, status, limit, offset }, signal),
    [severity, framework, device_id, status, limit, offset],
  );
}

export function useDevices(): ResourceState<{ items: DeviceCompliance[]; total: number }> {
  return useResource<{ items: DeviceCompliance[]; total: number }>(
    (signal) => listDevices(signal),
    [],
  );
}

export function useDevice(deviceId: string | null): ResourceState<DeviceCompliance> {
  return useResource<DeviceCompliance>((signal) => getDevice(deviceId as string, signal), [deviceId], {
    enabled: Boolean(deviceId),
  });
}

export function useRemediations(
  query: RemediationQuery = {},
  options: { enabled?: boolean } = {},
): ResourceState<{ items: Remediation[]; total: number }> {
  const { status, finding_id } = query;
  return useResource<{ items: Remediation[]; total: number }>(
    (signal) => listRemediations({ status, finding_id }, signal),
    [status, finding_id],
    options,
  );
}

/**
 * Resolves the remediation attached to a finding. The contract exposes no
 * GET /remediations/{id}, so the queue endpoint is filtered by finding_id and
 * matched against the finding's remediation_id. Nothing is fetched until a row
 * is actually expanded.
 */
export function useRemediationForFinding(
  findingId: string | null,
  remediationId: string | null,
): ResourceState<Remediation | null> {
  const state = useRemediations(findingId ? { finding_id: findingId } : {}, { enabled: Boolean(findingId) });

  const data =
    state.data === null
      ? null
      : remediationId
        ? state.data.items.find((item) => item.id === remediationId) ?? state.data.items[0] ?? null
        : state.data.items[0] ?? null;

  return { data, error: state.error, loading: state.loading, reload: state.reload };
}

/* -------------------------------------------------------------------------- */
/* Mutations                                                                   */
/* -------------------------------------------------------------------------- */

interface MutationState {
  pending: boolean;
  error: string | null;
  /** Id of the row currently being mutated, for per-row button state. */
  activeId: string | null;
}

export function useApproveRemediation(
  onApproved?: (remediation: Remediation) => void,
): MutationState & { approve: (id: string) => Promise<Remediation | null> } {
  const [state, setState] = useState<MutationState>({ pending: false, error: null, activeId: null });

  const approve = useCallback(
    async (id: string) => {
      setState({ pending: true, error: null, activeId: id });
      try {
        const remediation = await approveRemediation(id);
        onApproved?.(remediation);
        return remediation;
      } catch (cause) {
        setState({ pending: false, error: describeError(cause), activeId: id });
        return null;
      } finally {
        setState((current) => ({ ...current, pending: false, activeId: null }));
      }
    },
    [onApproved],
  );

  return { ...state, approve };
}

export function useRejectRemediation(
  onRejected?: (remediation: Remediation) => void,
): MutationState & { reject: (id: string, reason: string) => Promise<Remediation | null> } {
  const [state, setState] = useState<MutationState>({ pending: false, error: null, activeId: null });

  const reject = useCallback(
    async (id: string, reason: string) => {
      setState({ pending: true, error: null, activeId: id });
      try {
        const remediation = await rejectRemediation(id, { reason });
        onRejected?.(remediation);
        return remediation;
      } catch (cause) {
        setState({ pending: false, error: describeError(cause), activeId: id });
        return null;
      } finally {
        setState((current) => ({ ...current, pending: false, activeId: null }));
      }
    },
    [onRejected],
  );

  return { ...state, reject };
}

/* -------------------------------------------------------------------------- */
/* Analysis triggering                                                         */
/* -------------------------------------------------------------------------- */

const POLL_INTERVAL_MS = 1_500;
const POLL_TIMEOUT_MS = 120_000;

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timer);
        reject(new DOMException("aborted", "AbortError"));
      },
      { once: true },
    );
  });
}

/**
 * Follows an accepted analysis to completion. `poll_url` comes back as an
 * absolute API path ("/api/v1/analyses/{id}"), which the client would
 * double-prefix, so polling is driven by the analysis id instead.
 */
async function pollUntilDone(
  accepted: AnalysisAccepted,
  signal: AbortSignal,
): Promise<AnalysisSummary> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    const summary = await getAnalysis(accepted.analysis_id, signal);
    if (summary.status === "completed" || summary.status === "failed") return summary;
    if (Date.now() > deadline) {
      throw new Error(
        `Analysis ${accepted.analysis_id} did not finish within ${POLL_TIMEOUT_MS / 1000}s. It is still running; check the dashboard.`,
      );
    }
    await sleep(POLL_INTERVAL_MS, signal);
  }
}

export interface RunAnalysisState {
  running: boolean;
  error: string | null;
  summary: AnalysisSummary | null;
  deviceId: string | null;
  clear: () => void;
  /** Re-scores an already-read configuration file end to end. */
  runUpload: (file: File) => Promise<AnalysisSummary | null>;
  /** Submits raw config text asynchronously (202 + polling). */
  runText: (payload: AnalysisRequest) => Promise<AnalysisSummary | null>;
  /** Vendor fingerprint only, without a full rule-pack run. */
  detect: (text: string) => Promise<VendorDetection | null>;
  detection: VendorDetection | null;
}

export function useRunAnalysis(): RunAnalysisState {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<AnalysisSummary | null>(null);
  const [detection, setDetection] = useState<VendorDetection | null>(null);
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const runUpload = useCallback(async (file: File) => {
    setRunning(true);
    setError(null);
    try {
      const result = await uploadConfig(file);
      if (!mounted.current) return null;
      setSummary(result);
      setDeviceId(result.device_id);
      setDetection({
        vendor: result.vendor,
        confidence: result.vendor_confidence,
        rule_pack: null,
        candidates: [],
        evidence_precision: result.evidence_precision,
      });
      return result;
    } catch (cause) {
      if (mounted.current) setError(describeError(cause));
      return null;
    } finally {
      if (mounted.current) setRunning(false);
    }
  }, []);

  const runText = useCallback(async (payload: AnalysisRequest) => {
    setRunning(true);
    setError(null);
    setDeviceId(payload.device_id);
    try {
      const accepted = await startAnalysis(payload);
      const result = await pollUntilDone(accepted, new AbortController().signal);
      if (!mounted.current) return null;
      setSummary(result);
      setDetection({
        vendor: result.vendor,
        confidence: result.vendor_confidence,
        rule_pack: null,
        candidates: [],
        evidence_precision: result.evidence_precision,
      });
      return result;
    } catch (cause) {
      if (mounted.current) setError(describeError(cause));
      return null;
    } finally {
      if (mounted.current) setRunning(false);
    }
  }, []);

  const detect = useCallback(async (text: string) => {
    setError(null);
    try {
      const result = await detectVendor({ text });
      if (mounted.current) setDetection(result);
      return result;
    } catch (cause) {
      if (mounted.current) setError(describeError(cause));
      return null;
    }
  }, []);

  const clear = useCallback(() => {
    setSummary(null);
    setDetection(null);
    setError(null);
    setDeviceId(null);
  }, []);

  return { running, error, summary, deviceId, clear, runUpload, runText, detect, detection };
}