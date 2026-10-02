import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { FindingQuery, FindingStatus, Framework, Severity } from "../types/api";
import { useDevices, useFindings } from "../hooks/useAnalysis";
import {
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  FRAMEWORKS,
  FRAMEWORK_LABELS,
  SEVERITIES,
  VENDOR_LABELS,
} from "../lib/labels";
import { FindingTable } from "../components/FindingTable";

/** Guards against hand-edited or stale query strings producing invalid filter values. */
function parseOne<T extends string>(raw: string | null, allowed: readonly T[]): T | undefined {
  return raw && (allowed as readonly string[]).includes(raw) ? (raw as T) : undefined;
}

const PAGE_SIZES = [25, 50, 100, 200];

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const severity = parseOne<Severity>(searchParams.get("severity"), SEVERITIES);
  const framework = parseOne<Framework>(searchParams.get("framework"), FRAMEWORKS);
  const status = parseOne<FindingStatus>(searchParams.get("status"), FINDING_STATUSES);
  const deviceId = searchParams.get("device_id") ?? undefined;
  const offset = Math.max(0, Number(searchParams.get("offset") ?? 0) || 0);
  const limitRaw = Number(searchParams.get("limit") ?? 50) || 50;
  const limit = PAGE_SIZES.includes(limitRaw) ? limitRaw : 50;

  const query: FindingQuery = useMemo(
    () => ({ severity, framework, status, device_id: deviceId, limit, offset }),
    [severity, framework, status, deviceId, limit, offset],
  );

  const findings = useFindings(query);
  const devices = useDevices();

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    // Any filter change invalidates the current page position.
    if (key !== "offset") next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  const activeFilterCount = [severity, framework, status, deviceId].filter(Boolean).length;
  const total = findings.data?.total ?? 0;

  return (
    <>
      <header className="app-header">
        <div className="page-title">
          <h1>Findings</h1>
          <span className="page-subtitle">
            {findings.loading && total === 0
              ? "Loading findings..."
              : `${total} finding(s) match the current filters`}
          </span>
        </div>
        <div className="btn-row">
          <button type="button" className="btn" onClick={findings.reload} disabled={findings.loading}>
            Refresh
          </button>
          {activeFilterCount > 0 && (
            <button
              type="button"
              className="btn ghost"
              onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
            >
              Clear {activeFilterCount} filter(s)
            </button>
          )}
        </div>
      </header>

      <div className="page-body">
        <div className="card">
          <div className="table-toolbar">
            <div className="field">
              <label htmlFor="filter-severity">Severity</label>
              <select
                id="filter-severity"
                value={severity ?? ""}
                onChange={(event) => setFilter("severity", event.target.value)}
              >
                <option value="">All severities</option>
                {SEVERITIES.map((item) => (
                  <option key={item} value={item}>
                    {item.charAt(0).toUpperCase() + item.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label htmlFor="filter-status">Status</label>
              <select
                id="filter-status"
                value={status ?? ""}
                onChange={(event) => setFilter("status", event.target.value)}
              >
                <option value="">All statuses</option>
                {FINDING_STATUSES.map((item) => (
                  <option key={item} value={item}>
                    {FINDING_STATUS_LABELS[item]}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label htmlFor="filter-framework">Framework</label>
              <select
                id="filter-framework"
                value={framework ?? ""}
                onChange={(event) => setFilter("framework", event.target.value)}
              >
                <option value="">All frameworks</option>
                {FRAMEWORKS.map((item) => (
                  <option key={item} value={item}>
                    {FRAMEWORK_LABELS[item]}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label htmlFor="filter-device">Device</label>
              <select
                id="filter-device"
                value={deviceId ?? ""}
                onChange={(event) => setFilter("device_id", event.target.value)}
              >
                <option value="">All devices</option>
                {devices.data?.items.map((device) => (
                  <option key={device.device_id} value={device.device_id}>
                    {device.hostname ?? device.device_id} ({VENDOR_LABELS[device.vendor]})
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <FindingTable
          page={findings.data}
          loading={findings.loading}
          error={findings.error}
          onPageChange={(nextOffset) => setFilter("offset", String(nextOffset))}
          onPageSizeChange={(nextLimit) => setFilter("limit", String(nextLimit))}
          emptyHint={
            activeFilterCount > 0
              ? "No findings match these filters. Widen the severity or framework selection."
              : "No findings recorded. Upload a device configuration from the dashboard to start an audit."
          }
        />
      </div>
    </>
  );
}

export default FindingsPage;