import { useState } from "react";
import { Link } from "react-router-dom";
import type { DeviceCompliance } from "../types/api";
import { useDevice, useDevices } from "../hooks/useAnalysis";
import {
  FRAMEWORK_LABELS,
  SEVERITIES,
  VENDOR_LABELS,
  formatPercent,
  formatRelative,
  formatScore,
  scoreColor,
  scoreTone,
} from "../lib/labels";
import { ComplianceGauge } from "../components/ComplianceGauge";
import { SeverityBadge } from "../components/SeverityBadge";

function DeviceCard({ device, expanded, onToggle }: { device: DeviceCompliance; expanded: boolean; onToggle: () => void }) {
  const detail = useDevice(expanded ? device.device_id : null);
  const shown = detail.data ?? device;

  return (
    <div className="card">
      <div className="card-head">
        <div className="stack sm">
          <div className="row">
            <h2>{shown.hostname ?? shown.device_id}</h2>
            <span className="chip accent">{VENDOR_LABELS[shown.vendor]}</span>
            <span className="chip dim">{shown.role}</span>
          </div>
          <span className="small dim mono">
            {shown.device_id} - last analysed {formatRelative(shown.last_analyzed_at)}
          </span>
        </div>
        <div className="meta-row">
          <span
            className="chip"
            style={{ color: scoreColor(shown.overall_score), borderColor: scoreColor(shown.overall_score) }}
          >
            {formatScore(shown.overall_score)}
          </span>
          <Link className="btn sm" to={`/findings?device_id=${encodeURIComponent(shown.device_id)}`}>
            Findings
          </Link>
          <button type="button" className="btn sm ghost" onClick={onToggle}>
            {expanded ? "Hide frameworks" : "Framework breakdown"}
          </button>
        </div>
      </div>

      <div className="card-body stack">
        <div className="meta-row">
          {SEVERITIES.filter((severity) => (shown.severity_counts[severity] ?? 0) > 0).map((severity) => (
            <SeverityBadge key={severity} severity={severity} count={shown.severity_counts[severity]} />
          ))}
          {shown.total_findings === 0 && <span className="chip ok">no findings</span>}
          <span className="chip dim">{shown.open_findings} open</span>
        </div>

        <div className="spread small dim">
          <span>
            parser coverage {formatPercent(shown.parser_coverage)} -{" "}
            {shown.evidence_precision === "line"
              ? "findings cite exact config lines"
              : "evidence anchored to config blocks"}
          </span>
          <span>{shown.total_findings} findings evaluated</span>
        </div>

        {expanded && (
          <div className="stack">
            {detail.loading && <div className="skeleton" style={{ height: 60 }} />}
            {detail.error && <div className="alert">{detail.error}</div>}
            {shown.framework_scores.length === 0 && !detail.loading && (
              <div className="empty">No framework control results recorded for this device.</div>
            )}
            <div className="grid-2">
              <ComplianceGauge score={shown.overall_score} label="Device score" size={190} />
              <div className="framework-list">
                {shown.framework_scores.map((score) => (
                  <div className="framework-row" key={score.framework}>
                    <span className="label">{FRAMEWORK_LABELS[score.framework]}</span>
                    <div className="progress-track">
                      <div
                        className="progress-fill"
                        style={{
                          width: `${Math.max(0, Math.min(100, score.score))}%`,
                          background: scoreColor(score.score),
                        }}
                      />
                    </div>
                    <div className="counts">
                      <strong style={{ color: scoreColor(score.score) }}>{Math.round(score.score)}%</strong> -{" "}
                      {score.passed}/{score.total_controls} passed
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function DevicesPage() {
  const { data, error, loading, reload } = useDevices();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const devices = data?.items ?? [];
  const worst = devices.reduce<DeviceCompliance | null>(
    (lowest, device) => (lowest === null || device.overall_score < lowest.overall_score ? device : lowest),
    null,
  );
  const averageScore =
    devices.length > 0 ? devices.reduce((sum, device) => sum + device.overall_score, 0) / devices.length : null;
  const openTotal = devices.reduce((sum, device) => sum + device.open_findings, 0);

  return (
    <>
      <header className="app-header">
        <div className="page-title">
          <h1>Devices</h1>
          <span className="page-subtitle">
            {loading && devices.length === 0
              ? "Loading audited devices..."
              : `${devices.length} of ${data?.total ?? devices.length} device(s) in the inventory`}
          </span>
        </div>
        <button type="button" className="btn" onClick={reload} disabled={loading}>
          Refresh
        </button>
      </header>

      <div className="page-body">
        {error && <div className="alert">{error}</div>}

        <div className="stat-grid">
          <div className="stat-card">
            <span className="stat-label">Fleet average</span>
            <span className={`stat-value ${averageScore === null ? "neutral" : scoreTone(averageScore)}`}>
              {formatScore(averageScore)}
            </span>
            <span className="stat-hint">Mean device compliance score</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Lowest scoring</span>
            <span className={`stat-value ${worst ? scoreTone(worst.overall_score) : "neutral"}`}>
              {worst ? formatScore(worst.overall_score) : "--"}
            </span>
            <span className="stat-hint">{worst ? (worst.hostname ?? worst.device_id) : "No devices yet"}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Open findings</span>
            <span className="stat-value high">{openTotal}</span>
            <span className="stat-hint">Across every audited device</span>
          </div>
        </div>

        {!loading && devices.length === 0 && !error && (
          <div className="card">
            <div className="empty">
              No devices in the inventory yet. Upload a configuration from the dashboard to create the
              first device record.
            </div>
          </div>
        )}

        {devices.map((device) => (
          <DeviceCard
            key={device.device_id}
            device={device}
            expanded={expandedId === device.device_id}
            onToggle={() => setExpandedId((current) => (current === device.device_id ? null : device.device_id))}
          />
        ))}
      </div>
    </>
  );
}

export default DevicesPage;