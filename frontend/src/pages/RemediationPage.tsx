import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { Remediation, RemediationQuery, RemediationStatus } from "../types/api";
import { isReadOnly, onDemoModeChange } from "../api/client";
import { useApproveRemediation, useRejectRemediation, useRemediations } from "../hooks/useAnalysis";
import {
  REMEDIATION_STATUSES,
  REMEDIATION_STATUS_LABELS,
  RISK_LABELS,
  VENDOR_LABELS,
  formatRelative,
} from "../lib/labels";
import { RemediationCard } from "../components/RemediationCard";

const STATUS_TONES: Record<RemediationStatus, string> = {
  pending_review: "warn",
  approved: "ok",
  rejected: "critical",
  applied: "accent",
  failed: "critical",
};

interface Toast {
  id: number;
  tone: "ok" | "error";
  text: string;
}

export function RemediationPage() {
  const [status, setStatus] = useState<RemediationStatus | "">("pending_review");
  const [toasts, setToasts] = useState<Toast[]>([]);
  // A decision only exists if a server records it, so the approve/reject
  // controls are withdrawn entirely on the static snapshot.
  const [readOnly, setReadOnly] = useState(isReadOnly());
  useEffect(() => onDemoModeChange(() => setReadOnly(true)), []);

  const queue = useRemediations(useMemo<RemediationQuery>(() => (status ? { status } : {}), [status]));

  const pushToast = (tone: Toast["tone"], text: string) => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((current) => [...current, { id, tone, text }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 4000);
  };

  const approve = useApproveRemediation((remediation: Remediation) => {
    pushToast("ok", `Approved: ${remediation.title}`);
    queue.reload();
  });

  const reject = useRejectRemediation((remediation: Remediation) => {
    pushToast("ok", `Rejected: ${remediation.title}`);
    queue.reload();
  });

  const mutationError = approve.error ?? reject.error;
  const busyId = approve.activeId ?? reject.activeId;
  const items = queue.data?.items ?? [];
  const pendingCount = items.filter((item) => item.status === "pending_review").length;

  return (
    <>
      <header className="app-header">
        <div className="page-title">
          <h1>Remediation queue</h1>
          <span className="page-subtitle">
            {queue.loading && items.length === 0
              ? "Loading generated CLI..."
              : `${items.length} remediation(s) - ${pendingCount} awaiting human approval`}
          </span>
        </div>
        <div className="btn-row">
          <div className="field">
            <label htmlFor="remediation-status">Status</label>
            <select
              id="remediation-status"
              value={status}
              onChange={(event) => setStatus(event.target.value as RemediationStatus | "")}
            >
              <option value="">All statuses</option>
              {REMEDIATION_STATUSES.map((item) => (
                <option key={item} value={item}>
                  {REMEDIATION_STATUS_LABELS[item]}
                </option>
              ))}
            </select>
          </div>
          <button type="button" className="btn" onClick={queue.reload} disabled={queue.loading}>
            Refresh
          </button>
        </div>
      </header>

      <div className="page-body">
        <div className="alert info">
          <span>
            Nothing here touches a live device. Approving a remediation records that a human signed
            off on the generated CLI; it does not push configuration to the fleet.
          </span>
        </div>

        {queue.error && <div className="alert">{queue.error}</div>}
        {mutationError && <div className="alert">Review failed: {mutationError}</div>}

        {queue.loading && items.length === 0 && (
          <div className="card">
            <div className="card-body stack sm">
              <div className="skeleton" style={{ height: 90 }} />
              <div className="skeleton" style={{ height: 90 }} />
            </div>
          </div>
        )}

        {!queue.loading && items.length === 0 && !queue.error && (
          <div className="card">
            <div className="empty">
              {status
                ? `No ${REMEDIATION_STATUS_LABELS[status].toLowerCase()} remediations in the queue.`
                : "No remediations generated yet. Run an analysis from the dashboard to produce vendor-specific CLI."}
            </div>
          </div>
        )}

        {items.map((remediation) => (
          <div className="card" key={remediation.id}>
            <div className="card-head">
              <div className="meta-row">
                <span className={`chip ${STATUS_TONES[remediation.status]}`}>
                  {REMEDIATION_STATUS_LABELS[remediation.status]}
                </span>
                <span className="chip">{RISK_LABELS[remediation.risk]}</span>
                <span className="chip dim mono">{remediation.device_id}</span>
                <span className="small dim">{formatRelative(remediation.created_at)}</span>
              </div>
              <Link className="btn sm ghost" to={`/findings?device_id=${encodeURIComponent(remediation.device_id)}`}>
                {VENDOR_LABELS[remediation.vendor]} device findings
              </Link>
            </div>
            <div className="card-body">
              <RemediationCard
                remediation={remediation}
                onApprove={readOnly ? undefined : approve.approve}
                onReject={readOnly ? undefined : reject.reject}
                busyId={busyId}
              />
            </div>
          </div>
        ))}
      </div>

      {toasts.length > 0 && (
        <div className="toast-stack">
          {toasts.map((toast) => (
            <div className={`toast ${toast.tone}`} key={toast.id}>
              {toast.text}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

export default RemediationPage;