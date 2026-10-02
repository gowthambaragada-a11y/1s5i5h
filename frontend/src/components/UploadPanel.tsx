import { useCallback, useRef, useState } from "react";
import type { DragEvent } from "react";
import type { AnalysisSummary, Framework } from "../types/api";
import { useRunAnalysis } from "../hooks/useAnalysis";
import { FRAMEWORKS, FRAMEWORK_LABELS, SEVERITIES, VENDOR_LABELS, formatPercent, formatScore } from "../lib/labels";
import { SeverityBadge } from "./SeverityBadge";

interface UploadPanelProps {
  onAnalyzed?: (summary: AnalysisSummary) => void;
}

const ACCEPTED_SUFFIXES = [".cfg", ".conf", ".config", ".txt", ".running", ".saved", ".json", ".xml"];

const DEFAULT_FRAMEWORKS: Framework[] = ["CIS_CISCO_IOS", "CIS_FORTINET", "NIST_800_53"];

function hasAcceptedSuffix(name: string): boolean {
  const lower = name.toLowerCase();
  return ACCEPTED_SUFFIXES.some((suffix) => lower.endsWith(suffix)) || !lower.includes(".");
}

export function UploadPanel({ onAnalyzed }: UploadPanelProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [showTextForm, setShowTextForm] = useState(false);
  const [deviceId, setDeviceId] = useState("dev-1");
  const [configText, setConfigText] = useState("");
  const [frameworks, setFrameworks] = useState<Framework[]>(DEFAULT_FRAMEWORKS);
  const [runMl, setRunMl] = useState(true);
  const [persistGraph, setPersistGraph] = useState(true);
  const { runUpload, runText, detection, summary, running, error, clear } = useRunAnalysis();

  const handleFile = useCallback(
    async (file: File) => {
      setLocalError(null);
      if (!hasAcceptedSuffix(file.name)) {
        setLocalError(`Unsupported file type: ${file.name}. Expected a running-config text export.`);
        return;
      }
      setFileName(file.name);
      // POST /analyze is synchronous and reports which adapter it chose, so the
      // vendor fingerprint arrives with the results rather than from a probe.
      const result = await runUpload(file);
      if (result) onAnalyzed?.(result);
    },
    [onAnalyzed, runUpload],
  );

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) void handleFile(file);
  };

  // Pasted text is submitted through the same endpoint as a file upload, so
  // this is an alternative way to supply the input, not a second scan path.
  const submitText = async () => {
    setLocalError(null);
    if (configText.trim().length === 0) {
      setLocalError("Paste a configuration first.");
      return;
    }
    const result = await runText({
      device_id: deviceId.trim() || "dev-1",
      text: configText,
      frameworks,
      run_ml: runMl,
      persist_graph: persistGraph,
    });
    if (result) onAnalyzed?.(result);
  };

  const toggleFramework = (framework: Framework) => {
    setFrameworks((current) =>
      current.includes(framework)
        ? current.filter((item) => item !== framework)
        : [...current, framework],
    );
  };

  const severityCounts = summary
    ? SEVERITIES.map((severity) => ({
        severity,
        count: summary.findings.filter((finding) => finding.severity === severity).length,
      }))
    : [];

  return (
    <div className="card">
      <div className="card-head">
        <span className="card-title">Audit a device configuration</span>
        {running && <span className="chip accent">running analysis</span>}
      </div>
      <div className="card-body stack">
        <div
          className={`dropzone${dragging ? " dragging" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <div className="dropzone-title">Drop a running-config export here</div>
          <div className="dropzone-hint">
            Cisco IOS / NX-OS, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS - .cfg .conf .txt .xml
            up to 10 MB
          </div>
          {fileName && <div className="chip">{fileName}</div>}
          <input
            ref={inputRef}
            className="file-input"
            type="file"
            accept=".cfg,.conf,.config,.txt,.running,.saved,.json,.xml,text/plain"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void handleFile(file);
              event.target.value = "";
            }}
          />
        </div>

        {running && (
          <div className="stack sm">
            <div className="progress-bar">
              <div />
            </div>
            <span className="small dim">
              Parsing, matching rule packs and generating remediations. Large configs can take a
              minute.
            </span>
          </div>
        )}

        {(localError ?? error) && <div className="alert">{localError ?? error}</div>}

        {detection && !running && (
          <div className="detect-box">
            <span className="chip accent">{VENDOR_LABELS[detection.vendor]}</span>
            <div className="confidence-bar">
              <div className="spread small dim" style={{ marginBottom: 4 }}>
                <span>detection confidence</span>
                <span className="num">{formatPercent(detection.confidence)}</span>
              </div>
              <div className="confidence-track">
                <div className="confidence-fill" style={{ width: `${detection.confidence * 100}%` }} />
              </div>
            </div>
            {detection.rule_pack && <span className="chip">rule pack: {detection.rule_pack}</span>}
            {detection.candidates.length > 0 && (
              <div className="candidate-list">
                {detection.candidates.slice(0, 3).map((candidate) => (
                  <span className="chip dim" key={candidate.adapter}>
                    {candidate.adapter} {formatPercent(candidate.score)}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {summary && !running && (
          <div className="stack">
            <div className="spread">
              <div className="meta-row">
                <span className="chip">{summary.device_id}</span>
                <span className="chip">{VENDOR_LABELS[summary.vendor]}</span>
                <span className="chip">{summary.status}</span>
                <span className="chip dim">parser coverage {formatPercent(summary.parser_coverage)}</span>
              </div>
              <div className="meta-row">
                <span className="chip accent">score {formatScore(summary.overall_score)}</span>
                <span className="chip">{summary.total_findings} findings</span>
                <span className="chip">{summary.remediations.length} remediations</span>
              </div>
            </div>

            <div className="meta-row">
              {severityCounts
                .filter((row) => row.count > 0)
                .map((row) => (
                  <SeverityBadge key={row.severity} severity={row.severity} count={row.count} />
                ))}
            </div>

            {summary.parse_warnings.length > 0 && (
              <div className="alert warn">
                <div className="stack sm">
                  <strong>{summary.parse_warnings.length} parser warning(s)</strong>
                  <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                    {summary.parse_warnings.slice(0, 5).map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            <div className="row">
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setFileName(null);
                  setConfigText("");
                  clear();
                }}
              >
                Analyse another config
              </button>
              <button type="button" className="btn ghost" onClick={() => setShowTextForm((open) => !open)}>
                {showTextForm ? "Hide text mode" : "Paste config instead"}
              </button>
            </div>
          </div>
        )}

        {!summary && (
          <div className="row">
            <button type="button" className="btn ghost sm" onClick={() => setShowTextForm((open) => !open)}>
              {showTextForm ? "Hide text mode" : "Paste config text instead"}
            </button>
          </div>
        )}

        {showTextForm && (
          <div className="stack">
            <div className="row" style={{ alignItems: "flex-end" }}>
              <div className="field">
                <label htmlFor="analysis-device">Device id</label>
                <input
                  id="analysis-device"
                  value={deviceId}
                  onChange={(event) => setDeviceId(event.target.value)}
                  placeholder="dev-1"
                />
              </div>
              <label className="row small muted" style={{ gap: 6 }}>
                <input type="checkbox" checked={runMl} onChange={(event) => setRunMl(event.target.checked)} />
                run ML anomaly detection
              </label>
              <label className="row small muted" style={{ gap: 6 }}>
                <input
                  type="checkbox"
                  checked={persistGraph}
                  onChange={(event) => setPersistGraph(event.target.checked)}
                />
                persist knowledge graph
              </label>
            </div>

            <div className="field">
              <label>Frameworks to evaluate</label>
              <div className="meta-row">
                {FRAMEWORKS.map((framework) => (
                  <button
                    key={framework}
                    type="button"
                    className={`chip${frameworks.includes(framework) ? " accent" : " dim"}`}
                    style={{ cursor: "pointer" }}
                    onClick={() => toggleFramework(framework)}
                    aria-pressed={frameworks.includes(framework)}
                  >
                    {FRAMEWORK_LABELS[framework]}
                  </button>
                ))}
              </div>
            </div>

            <div className="field">
              <label htmlFor="analysis-text">Configuration text</label>
              <textarea
                id="analysis-text"
                rows={8}
                value={configText}
                spellCheck={false}
                placeholder="hostname core-rtr-1&#10;ip ssh version 2&#10;line vty 0 4&#10; transport input telnet"
                onChange={(event) => setConfigText(event.target.value)}
              />
            </div>

            <div className="btn-row">
              <button type="button" className="btn primary" disabled={running} onClick={() => void submitText()}>
                {running ? "Analysis in progress..." : "Scan config text"}
              </button>
              <span className="small dim">
                Submitted to POST /api/v1/analyze, which scans synchronously.
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default UploadPanel;