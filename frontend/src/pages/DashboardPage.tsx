import { useNavigate } from "react-router-dom";
import type { Framework, Severity } from "../types/api";
import { isReadOnly } from "../api/client";
import { useDashboardSummary } from "../hooks/useAnalysis";
import {
  SEVERITIES,
  VENDOR_LABELS,
  formatRelative,
  formatScore,
  formatTimestamp,
  scoreColor,
  scoreTone,
} from "../lib/labels";
import { ComplianceGauge } from "../components/ComplianceGauge";
import { FrameworkTabs } from "../components/FrameworkTabs";
import { SeverityBadge } from "../components/SeverityBadge";
import { SeverityChart } from "../components/SeverityChart";
import { StatCard } from "../components/StatCard";
import { UploadPanel } from "../components/UploadPanel";

export function DashboardPage() {
  const navigate = useNavigate();
  const { data, error, loading, reload } = useDashboardSummary();
  const summary = data;

  const openFindings = summary
    ? summary.devices.reduce((total, device) => total + device.open_findings, 0)
    : 0;

  return (
    <>
      <header className="app-header">
        <div className="page-title">
          <h1>Security posture</h1>
          <span className="page-subtitle">
            {summary
              ? `Generated ${formatTimestamp(summary.generated_at)} - ${summary.total_devices} device(s) under audit`
              : "Loading fleet compliance summary..."}
          </span>
        </div>
        <button type="button" className="btn" onClick={reload} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </header>

      <div className="page-body">
        {error && <div className="alert">{error}</div>}

        <div className="stat-grid">
          <StatCard
            label="Overall score"
            value={summary ? formatScore(summary.overall_score) : loading ? "..." : "--"}
            tone={summary ? scoreTone(summary.overall_score) : "neutral"}
            trendUpIsGood
            hint="Weighted CIS / NIST / STIG / ISO control pass rate"
          />
          <StatCard
            label="Devices audited"
            value={summary ? summary.total_devices : loading ? "..." : "--"}
            hint={summary ? `${summary.devices.filter((d) => d.vendor !== "unknown").length} vendor identified` : undefined}
            onClick={() => navigate("/devices")}
          />
          <StatCard
            label="Open findings"
            value={summary ? summary.total_findings : loading ? "..." : "--"}
            trend={summary?.critical_delta ?? null}
            trendLabel="critical vs previous period"
            tone={summary && summary.total_findings > 0 ? "high" : "ok"}
            hint={summary ? `${openFindings} still open across the fleet` : undefined}
            onClick={() => navigate("/findings?status=open")}
          />
          <StatCard
            label="Pending remediations"
            value={summary ? summary.pending_remediations : loading ? "..." : "--"}
            tone={summary && summary.pending_remediations > 0 ? "warn" : "ok"}
            hint="Awaiting human approval before any CLI is applied"
            onClick={() => navigate("/remediation")}
          />
        </div>

        {/* Scanning needs a live backend, so the panel is hidden in static demo
            mode rather than left as a control that cannot work. */}
        {!isReadOnly() && <UploadPanel onAnalyzed={reload} />}

        <div className="grid-2">
          <div className="card">
            <div className="card-head">
              <span className="card-title">Compliance score</span>
              <span className="chip dim">0 - 100</span>
            </div>
            <div className="card-body">
              <ComplianceGauge
                score={summary?.overall_score ?? null}
                label="Fleet compliance"
                caption={summary ? `${summary.total_findings} findings evaluated` : undefined}
              />
            </div>
          </div>

          <div className="card">
            <div className="card-head">
              <span className="card-title">Findings by severity</span>
              <span className="small dim">click a bar to filter</span>
            </div>
            <div className="card-body">
              {summary ? (
                <SeverityChart
                  counts={summary.severity_counts}
                  onSelect={(severity: Severity) => navigate(`/findings?severity=${severity}`)}
                />
              ) : (
                <div className="skeleton" style={{ height: 240 }} />
              )}
              {summary && (
                <div className="meta-row" style={{ marginTop: 10 }}>
                  {SEVERITIES.map((severity) => (
                    <SeverityBadge
                      key={severity}
                      severity={severity}
                      count={summary.severity_counts[severity] ?? 0}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <FrameworkTabs
          scores={summary?.framework_scores ?? []}
          onSelectFramework={(framework: Framework) => navigate(`/findings?framework=${framework}`)}
        />

        <div className="grid-2">
          <div className="card">
            <div className="card-head">
              <span className="card-title">Top risky rules</span>
              <span className="small dim">fleet-wide frequency</span>
            </div>
            <div className="card-body stack sm">
              {!summary && <div className="skeleton" style={{ height: 120 }} />}
              {summary && summary.top_risky_rules.length === 0 && (
                <div className="empty">No rule has fired across the fleet yet.</div>
              )}
              {summary?.top_risky_rules.map((rule) => (
                <div className="spread" key={rule.rule_id}>
                  <div className="stack sm">
                    <span className="strong small">{rule.title}</span>
                    <span className="mono small dim">{rule.rule_id}</span>
                  </div>
                  <div className="meta-row">
                    <SeverityBadge severity={rule.severity} />
                    <span className="chip">{rule.count}x</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-head">
              <span className="card-title">Device compliance</span>
              <button type="button" className="btn sm ghost" onClick={() => navigate("/devices")}>
                View all
              </button>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Vendor</th>
                    <th className="num">Score</th>
                    <th>Severity mix</th>
                    <th>Last analysed</th>
                  </tr>
                </thead>
                <tbody>
                  {!summary &&
                    [0, 1, 2].map((row) => (
                      <tr key={row}>
                        <td colSpan={5}>
                          <div className="skeleton" />
                        </td>
                      </tr>
                    ))}
                  {summary?.devices.slice(0, 8).map((device) => (
                    <tr key={device.device_id}>
                      <td>
                        <div className="finding-title">{device.hostname ?? device.device_id}</div>
                        <div className="finding-sub mono">{device.device_id}</div>
                      </td>
                      <td className="small">{VENDOR_LABELS[device.vendor]}</td>
                      <td className="num strong" style={{ color: scoreColor(device.overall_score) }}>
                        {formatScore(device.overall_score)}
                      </td>
                      <td>
                        <div className="meta-row">
                          {SEVERITIES.filter(
                            (severity) => (device.severity_counts[severity] ?? 0) > 0,
                          ).map((severity) => (
                            <SeverityBadge
                              key={severity}
                              severity={severity}
                              count={device.severity_counts[severity]}
                            />
                          ))}
                          {device.total_findings === 0 && <span className="chip ok">clean</span>}
                        </div>
                      </td>
                      <td className="small dim nowrap">{formatRelative(device.last_analyzed_at)}</td>
                    </tr>
                  ))}
                  {summary && summary.devices.length === 0 && (
                    <tr>
                      <td colSpan={5}>
                        <div className="empty">
                          No devices analysed yet. Upload a configuration to get started.
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default DashboardPage;