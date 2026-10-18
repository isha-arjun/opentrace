import { useEffect, useMemo, useState } from 'react';
import { sampleReport } from './sampleReport';
import { buildJsonReport, buildMarkdownReport, compareReports, filterFindings, sortFindings, severityLabels } from './utils/report';
import type { ScanReport } from './types';

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const emptyState: ScanReport = {
  target: 'https://example.com',
  scan_timestamp: new Date().toISOString(),
  data_source: 'No scan yet',
  summary: { total: 0, passed: 0, failed: 0, informational: 0, unavailable: 0, unknown: 0 },
  findings: [],
  hostname: 'example.com',
  scope: 'No report has been generated yet.',
  limitations: 'This workspace does not include a real scan until you submit a target URL.',
};

const validateTarget = (input: string) => {
  const value = input.trim();
  if (!value) return 'Target URL is required.';
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return 'Only HTTP and HTTPS URLs are supported for public scans.';
    }
    const host = parsed.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost')) {
      return 'localhost targets are not allowed for public scans.';
    }
    if (host === '127.0.0.1' || host.startsWith('127.')) {
      return 'Private, reserved, or local IP addresses are not allowed.';
    }
    return null;
  } catch {
    return 'Only HTTP and HTTPS URLs are supported for public scans.';
  }
};

const pickSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'unknown';
  }
};

function App() {
  const [target, setTarget] = useState('https://example.com');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [demoMode, setDemoMode] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const saved = window.localStorage.getItem('opentrace:last-report');
    if (saved) {
      try {
        const parsed = JSON.parse(saved) as ScanReport;
        if (parsed?.findings) {
          setReport(parsed);
        }
      } catch {
        window.localStorage.removeItem('opentrace:last-report');
      }
    }
  }, []);

  const categories = useMemo(() => {
    const source = report?.findings ?? [];
    return Array.from(new Set(source.map((finding) => finding.category)));
  }, [report]);

  const visibleFindings = useMemo(() => {
    const source = report?.findings ?? [];
    const filtered = filterFindings(source, severityFilter, categoryFilter);
    return sortFindings(filtered, 'desc');
  }, [categoryFilter, report, severityFilter]);

  const saveReportLocally = (nextReport: ScanReport) => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('opentrace:last-report', JSON.stringify(nextReport));
    }
  };

  const downloadFile = (filename: string, content: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    window.URL.revokeObjectURL(url);
  };

  const handleDemoLoad = () => {
    setDemoMode(true);
    setError(null);
    setReport(sampleReport);
    setExpandedId(sampleReport.findings[0]?.id ?? null);
    saveReportLocally(sampleReport);
  };

  const handleScan = async () => {
    const validationError = validateTarget(target);
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError(null);
    setDemoMode(false);

    try {
      const response = await fetch(`${apiBaseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        const message = payload?.detail || payload?.error || 'The scan could not complete.';
        throw new Error(message);
      }

      const payload = (await response.json()) as { report?: ScanReport; error?: string };
      if (!payload.report) {
        throw new Error(payload.error || 'No report was returned.');
      }
      setReport(payload.report);
      setExpandedId(payload.report.findings[0]?.id ?? null);
      saveReportLocally(payload.report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed unexpectedly.');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const currentReport = report ?? emptyState;
  const previousReport = (() => {
    if (typeof window === 'undefined') return null;
    try {
      const stored = window.localStorage.getItem('opentrace:last-report');
      return stored ? (JSON.parse(stored) as ScanReport) : null;
    } catch {
      return null;
    }
  })();

  const delta = previousReport && report ? compareReports(report, previousReport) : [];

  return (
    <div className="page-shell">
      <header className="topbar">
        <div className="brand-wrap">
          <div className="brand-mark">OT</div>
          <div>
            <div className="brand-name">OpenTrace</div>
            <div className="brand-subtitle">Website transparency analyzer</div>
          </div>
        </div>
        <nav className="topnav" aria-label="Main navigation">
          <a href="#overview">Overview</a>
          <a href="#scan">Scan</a>
          <a href="#report">Report</a>
          <button type="button" className="small-button" onClick={handleDemoLoad}>Load sample report</button>
        </nav>
      </header>

      <main className="page-content">
        <section className="hero" id="overview">
          <div className="hero-copy">
            <span className="eyebrow">Evidence-first transparency</span>
            <h1>OpenTrace</h1>
            <p>
              Understand what a site is visibly exposing: headers, privacy signals, transparency gaps, and the evidence behind each conclusion.
            </p>
            <div className="cta-row">
              <a href="#scan" className="primary-button">Scan a target</a>
              <button type="button" className="secondary-button" onClick={handleDemoLoad}>View demo report</button>
            </div>
          </div>

          <div className="mini-report" aria-label="Sample report card">
            <div className="mini-report-header">
              <span>Example report</span>
              <span className="demo-tag">Synthetic data</span>
            </div>
            <div className="mini-stat-grid">
              <div>
                <strong>3</strong>
                <span>passed</span>
              </div>
              <div>
                <strong>1</strong>
                <span>failed</span>
              </div>
              <div>
                <strong>1</strong>
                <span>info</span>
              </div>
            </div>
            <ul className="mini-list">
              <li>Content-Security-Policy: missing</li>
              <li>HSTS: configured</li>
              <li>Referrer-Policy: present</li>
            </ul>
          </div>
        </section>

        <section className="scan-panel" id="scan">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Target scan</span>
              <h2>Check a public website</h2>
            </div>
            {demoMode ? <span className="demo-tag">Demo mode</span> : <span className="status-pill">Live URL input</span>}
          </div>

          <label className="input-label" htmlFor="target-url">Target URL</label>
          <div className="scan-form">
            <input
              id="target-url"
              type="url"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="https://example.com"
              aria-label="Target URL"
            />
            <button type="button" onClick={handleScan} disabled={loading} className="primary-button" aria-live="polite">
              {loading ? 'Scanning…' : 'Scan target'}
            </button>
          </div>

          <div className="helper-row">
            <span>Examples: https://example.com, https://www.mozilla.org</span>
          </div>

          {error ? <div className="alert error">{error}</div> : null}

          {loading ? (
            <div className="loading-block" aria-live="polite">
              <div className="loading-skeleton heading" />
              <div className="loading-skeleton line" />
              <div className="loading-skeleton line short" />
            </div>
          ) : null}
        </section>

        <section className="report-panel" id="report">
          <div className="report-header">
            <div>
              <span className="eyebrow">Transparency report</span>
              <h2>{demoMode ? 'Synthetic example report' : currentReport.hostname}</h2>
            </div>
            <div className="report-actions">
              <button type="button" className="secondary-button" onClick={() => downloadFile('opentrace-report.json', buildJsonReport(currentReport), 'application/json')}>
                Export JSON
              </button>
              <button type="button" className="secondary-button" onClick={() => downloadFile('opentrace-report.md', buildMarkdownReport(currentReport), 'text/markdown')}>
                Export Markdown
              </button>
              <button type="button" className="secondary-button" onClick={() => window.print()}>
                Print/PDF
              </button>
            </div>
          </div>

          <div className="summary-grid">
            <article className="summary-card">
              <span>Target</span>
              <strong>{currentReport.target}</strong>
            </article>
            <article className="summary-card">
              <span>Timestamp</span>
              <strong>{new Date(currentReport.scan_timestamp).toLocaleString()}</strong>
            </article>
            <article className="summary-card">
              <span>Data source</span>
              <strong>{currentReport.data_source}</strong>
            </article>
            <article className="summary-card">
              <span>Findings</span>
              <strong>{currentReport.summary.total}</strong>
            </article>
          </div>

          <div className="finding-toolbar">
            <label>
              Severity
              <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Informational</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
            <label>
              Category
              <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
                <option value="all">All categories</option>
                {categories.map((category) => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </label>
          </div>

          {visibleFindings.length === 0 ? (
            <div className="empty-state">
              <h3>No findings match the current filters.</h3>
              <p>Try a different severity or category, or submit a new scan target.</p>
            </div>
          ) : (
            <div className="findings-shell">
              <div className="findings-list">
                {visibleFindings.map((finding) => (
                  <article className="finding-card" key={finding.id}>
                    <button className="finding-button" type="button" onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}>
                      <div className="finding-topline">
                        <span className={`badge ${pickSeverityColor(finding.severity)}`}>{severityLabels[finding.severity] ?? finding.severity}</span>
                        <span className="finding-category">{finding.category}</span>
                      </div>
                      <h3>{finding.title}</h3>
                      <p>{finding.observed_value ?? 'No direct observation provided.'}</p>
                    </button>

                    {expandedId === finding.id ? (
                      <div className="finding-detail">
                        <div className="detail-grid">
                          <div>
                            <h4>Evidence</h4>
                            <ul>
                              {finding.evidence.map((item) => (
                                <li key={`${finding.id}-${item.check_id}`}>
                                  <strong>{item.check_id}</strong>: {item.observed_value ?? 'No value'}
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <h4>Interpretation</h4>
                            <p>{finding.explanation}</p>
                          </div>
                        </div>
                        <div className="detail-grid">
                          <div>
                            <h4>Why it matters</h4>
                            <p>{finding.explanation}</p>
                          </div>
                          <div>
                            <h4>Remediation</h4>
                            <p>{finding.remediation}</p>
                          </div>
                        </div>
                        <div className="detail-grid">
                          <div>
                            <h4>Confidence</h4>
                            <p>{finding.confidence}</p>
                          </div>
                          <div>
                            <h4>Authoritative documentation</h4>
                            <a href={finding.documentation} target="_blank" rel="noreferrer">Open reference</a>
                          </div>
                        </div>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>

              <aside className="report-aside">
                <h3>Scope and limitations</h3>
                <p>{currentReport.scope}</p>
                <p>{currentReport.limitations}</p>
                {delta.length > 0 ? (
                  <div>
                    <h4>Local comparison</h4>
                    <ul>
                      {delta.map((item) => (
                        <li key={item.id}>
                          {item.title}: {item.previous ?? 'missing'} → {item.current ?? 'missing'}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </aside>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
