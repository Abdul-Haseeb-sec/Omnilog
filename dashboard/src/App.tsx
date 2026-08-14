import { useState, useRef, useEffect, useCallback } from 'react'
import { ShieldAlert, Activity, Upload, Download, FileJson, Globe, Beaker, Database, History, Trash2, Filter, X } from 'lucide-react'
import './index.css'

interface Alert {
  source_ip: string
  dest_ip?: string
  classification: string
  classification_source?: string
  detection_type?: string
  detection_label?: string
  detection_confidence?: string
  window_start: string
  window_end: string
  event_count: number
  raw_logs?: Record<string, unknown>[]
  intel_details?: Record<string, unknown>
}

interface Report {
  timestamp: string
  mode: string
  rule_id: string
  rule_name: string
  threshold: number
  alerts: Alert[]
  pcap_stats?: Record<string, number>
  request_id?: string
}

interface RunSummary {
  id: string
  timestamp: string
  mode: string
  alert_count: number
  rule_name: string
}

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const getAuthHeaders = (): Record<string, string> => {
  const key = localStorage.getItem('OMNILOG_API_KEY') || import.meta.env.VITE_API_KEY
  return key ? { 'X-API-Key': key } : {}
}


function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [showIntel, setShowIntel] = useState(false)
  const [intelData, setIntelData] = useState<Record<string, unknown>>({})
  const [showHistory, setShowHistory] = useState(false)
  const [runs, setRuns] = useState<RunSummary[]>([])
  const [activeFilter, setActiveFilter] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>
    if (loading) {
      setProgress(0)
      interval = setInterval(() => setProgress(p => (p >= 98 ? 98 : p + 0.5)), 20)
    } else {
      setProgress(100)
      const t = setTimeout(() => setProgress(0), 400)
      return () => { clearInterval(interval); clearTimeout(t) }
    }
    return () => clearInterval(interval)
  }, [loading])

  const loadIntel = useCallback(async () => {
    try {
      const res = await fetch(`${API}/threat_intel`, { headers: getAuthHeaders() })
      if (res.ok) setIntelData(await res.json())
    } catch { /* backend offline */ }
  }, [])

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API}/reports`, { headers: getAuthHeaders() })
      if (res.ok) setRuns(await res.json())
    } catch { /* backend offline */ }
  }, [])

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await fetch(`${API}/upload`, { 
        method: 'POST', 
        headers: getAuthHeaders(),
        body: fd 
      })
      if (!res.ok) {
        const err = await res.json()
        alert('Error: ' + err.error + (err.logs ? '\n\nLogs:\n' + err.logs : ''))
        setLoading(false)
        return
      }
      setReport(await res.json())
    } catch {
      alert('Cannot connect to backend. Ensure api_server.py is running on port 5000.')
    }
    setLoading(false)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const loadReport = async (id: string) => {
    try {
      const res = await fetch(`${API}/reports/${id}`, { headers: getAuthHeaders() })
      if (res.ok) { setReport(await res.json()); setShowHistory(false) }
    } catch { alert('Failed to load report') }
  }

  const escapeCSVField = (value: string): string => {
    if (/^[=+\-@\t\r]/.test(value)) {
      value = "'" + value
    }
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return '"' + value.replace(/"/g, '""') + '"'
    }
    return value
  }

  const exportCSV = () => {
    if (!report) return
    const meta = `# Omnilog Export\n# Minimum Event Threshold: ${report.threshold}\n`
    const h = 'Source IP,Classification,Source,Detection Type,Evidence Type,Start Time,End Time,Event Count,Host Name,Windows User Account,Machine Account,Malware,C2 IP,C2 Port\n'
    const rows = report.alerts.map(a => {
      const idetails = a.intel_details || {}
      const getField = (key: string) => String(idetails[key] || '')
      return [
        a.source_ip,
        a.classification,
        a.classification_source || '',
        a.detection_label || '',
        a.detection_confidence || '',
        a.window_start,
        a.window_end,
        String(a.event_count),
        getField('Host Name'),
        getField('Windows User Account'),
        getField('Machine Account'),
        getField('Malware'),
        getField('C2 IP'),
        getField('C2 Port')
      ].map(escapeCSVField).join(',')
    }).join('\n')
    const blob = new Blob([meta + h + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `omnilog_export_${Date.now()}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  const handleTag = async (ip: string, classification: string) => {
    try {
      const res = await fetch(`${API}/mark_intel`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        body: JSON.stringify({ ip, classification }),
      })
      if (res.ok) {
        setReport(prev => prev ? {
          ...prev,
          alerts: prev.alerts.map(a => a.source_ip === ip ? { ...a, classification, classification_source: 'Manual Tag' } : a),
        } : prev)
        if (selectedAlert?.source_ip === ip)
          setSelectedAlert(prev => prev ? { ...prev, classification, classification_source: 'Manual Tag' } : prev)
      } else { alert('Failed: ' + res.status) }
    } catch (err: unknown) { alert('Network error: ' + (err instanceof Error ? err.message : String(err))) }
  }

  const deleteIntel = async (ip: string) => {
    try {
      const res = await fetch(`${API}/threat_intel/${ip}`, { 
        method: 'DELETE',
        headers: getAuthHeaders()
      })
      if (res.ok) { const next = { ...intelData }; delete next[ip]; setIntelData(next) }
    } catch { /* ignore */ }
  }

  const tpCount = report?.alerts.filter(a => a.classification === 'TRUE POSITIVE').length ?? 0
  const fpCount = report?.alerts.filter(a => a.classification === 'FALSE POSITIVE').length ?? 0
  const unkCount = report?.alerts.filter(a => a.classification === 'UNKNOWN').length ?? 0

  const toggleFilter = (classification: string) => {
    setActiveFilter(prev => prev === classification ? null : classification)
  }

  const filteredAlerts = report?.alerts.filter(a => {
    if (!activeFilter) return true
    if (activeFilter === 'ALL') return true
    return a.classification === activeFilter
  }) ?? []

  const fmtTs = (iso: string) => iso.replace('T', ' ').substring(0, 19)

  const describeEvent = (log: Record<string, unknown>): string => {
    if (log.service === 'ssh' || log.auth_success !== undefined)
      return `SSH auth ${log.auth_success === true || log.auth_success === 'T' ? 'success' : 'attempt (failed)'}${log.username ? ` [${log.username}]` : ''}`
    if (log.service === 'dns')
      return `DNS ${log.rcode_name || ''}${log.query ? ` — ${log.query}` : ''}`
    if (log.service === 'http')
      return `HTTP ${log.status_code || ''}`
    if (log.service === 'windows')
      return `Windows Event ${log.event_id || ''} (${log.auth_success === false ? 'failed logon' : 'logon'})`
    if (log.pcap_event === 'syn')
      return `TCP SYN → port ${log['id.resp_p'] || '?'}`
    return 'Network event'
  }

  return (
    <div className="dashboard-container">

      {/* ── Alert Detail Modal ─────────────────────────────────── */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Alert Detail — {selectedAlert.source_ip}</h3>
              <button className="modal-close-btn" onClick={() => setSelectedAlert(null)}>[ Close ]</button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">Classification</span>
                  <span className="detail-value" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '4px' }}>
                    <span className={`badge ${selectedAlert.classification === 'TRUE POSITIVE' ? 'critical' : selectedAlert.classification === 'FALSE POSITIVE' ? 'warn' : 'ok'}`}>
                      {selectedAlert.classification}
                    </span>
                    {selectedAlert.classification_source && <span className="source-tag" style={{ marginLeft: 0 }}>{selectedAlert.classification_source}</span>}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Detection Rule</span>
                  <span className="detail-value">{selectedAlert.detection_label || selectedAlert.detection_type || 'Generic'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Source IP</span>
                  <span className="detail-value">{selectedAlert.source_ip}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Destination</span>
                  <span className="detail-value">{selectedAlert.dest_ip || '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Time Window</span>
                  <span className="detail-value">{fmtTs(selectedAlert.window_start)} → {fmtTs(selectedAlert.window_end)}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Confidence</span>
                  <span className="detail-value">
                    <span className={`badge ${selectedAlert.detection_confidence === 'Parsed Log' ? 'ok' : 'info'}`}>
                      {selectedAlert.detection_confidence || 'Parsed Log'}
                    </span>
                    {selectedAlert.detection_confidence === 'Heuristic (PCAP)' && (
                      <span className="source-tag" title="PCAP SSH detection counts connection attempts (SYN packets), not actual auth results — SSH traffic is encrypted">⚠ PCAP heuristic</span>
                    )}
                  </span>
                </div>
              </div>

              {!!(selectedAlert.intel_details && selectedAlert.intel_details["Executive Summary"]) && (
                <div className="detail-section">
                  <div className="detail-section-title">Executive Summary</div>
                  <p style={{ lineHeight: 1.5, color: '#e2e8f0', margin: '8px 0' }}>
                    {String(selectedAlert.intel_details["Executive Summary"])}
                  </p>
                </div>
              )}

              {selectedAlert.intel_details && Object.keys(selectedAlert.intel_details).filter(k => k !== 'Executive Summary').length > 0 && (
                <div className="detail-section">
                  <div className="detail-section-title">Threat Intelligence</div>
                  <div className="detail-grid">
                    {Object.entries(selectedAlert.intel_details)
                      .filter(([k]) => k !== 'Executive Summary')
                      .map(([k, v]) => (
                      <div className="detail-item" key={k}>
                        <span className="detail-label">{k.replace(/_/g, ' ')}</span>
                        <span className="detail-value">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedAlert.raw_logs && selectedAlert.raw_logs.length > 0 && (
                <div className="detail-section">
                  <div className="detail-section-title">Event Timeline ({selectedAlert.raw_logs.length}{selectedAlert.event_count > selectedAlert.raw_logs.length ? ` of ${selectedAlert.event_count}` : ''} events)</div>
                  <ul className="detail-timeline">
                    {selectedAlert.raw_logs.map((log, i) => {
                      const ts = log.ts ? new Date(Number(log.ts) * 1000).toISOString().replace('T', ' ').substring(0, 19) : '—'
                      return <li key={i}><span className="ts">{ts} UTC</span><span className="event">{describeEvent(log)}</span></li>
                    })}
                  </ul>
                </div>
              )}

              <div className="detail-actions">
                <button className="tag-btn tag-btn-danger" onClick={() => handleTag(selectedAlert.source_ip, 'TRUE POSITIVE')}>Tag Malicious</button>
                <button className="tag-btn tag-btn-safe" onClick={() => handleTag(selectedAlert.source_ip, 'FALSE POSITIVE')}>Tag Safe</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Threat Intel Browser Modal ────────────────────────── */}
      {showIntel && (
        <div className="modal-overlay" onClick={() => setShowIntel(false)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Threat Intel Database</h3>
              <button className="modal-close-btn" onClick={() => setShowIntel(false)}>[ Close ]</button>
            </div>
            <div className="modal-body">
              {Object.keys(intelData).length === 0 ? (
                <div className="empty-state">No IPs tagged yet. Use TAG BAD / TAG SAFE on alerts to build your database.</div>
              ) : (
                <table className="data-table">
                  <thead><tr><th>IP Address</th><th>Classification</th><th>Source</th><th>Remove</th></tr></thead>
                  <tbody>
                    {Object.entries(intelData).map(([ip, val]) => {
                      const cls = typeof val === 'object' && val !== null ? (val as Record<string, string>).classification : String(val)
                      const src = typeof val === 'object' && val !== null ? (val as Record<string, string>).source : 'Legacy'
                      return (
                        <tr key={ip}>
                          <td className="data-text">{ip}</td>
                          <td><span className={`badge ${cls === 'TRUE POSITIVE' ? 'critical' : 'warn'}`}>{cls}</span></td>
                          <td className="data-text">{src || '—'}</td>
                          <td>
                            <button className="raw-log-btn" onClick={() => deleteIntel(ip)} title="Remove from database">
                              <Trash2 size={16} color="var(--critical)" />
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Run History Modal ─────────────────────────────────── */}
      {showHistory && (
        <div className="modal-overlay" onClick={() => setShowHistory(false)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Analysis History</h3>
              <button className="modal-close-btn" onClick={() => setShowHistory(false)}>[ Close ]</button>
            </div>
            <div className="modal-body">
              {runs.length === 0 ? (
                <div className="empty-state">No past analyses found. Upload a file to create the first run.</div>
              ) : (
                <table className="data-table">
                  <thead><tr><th>Timestamp</th><th>Mode</th><th>Alerts</th><th>Load</th></tr></thead>
                  <tbody>
                    {runs.map(r => (
                      <tr key={r.id}>
                        <td className="data-text">{fmtTs(r.timestamp)} UTC</td>
                        <td><span className={`badge ${r.mode === 'lab' ? 'warn' : 'info'}`}>{r.mode}</span></td>
                        <td className="data-text">{r.alert_count}</td>
                        <td>
                          <button className="tag-btn tag-btn-safe" onClick={() => loadReport(r.id)}>Load</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Header ───────────────────────────────────────────── */}
      <header className="header">
        <div>
          <h1>Adversary Emulation Lab</h1>
          <p className="text-muted">OmniLog Detection Harness &amp; Telemetry Viewer</p>
        </div>
        <div className="flex-center gap-sm">
          <input
            type="file"
            accept=".json,.jsonl,.log,.tsv,.csv,.gz,.pcap,.pcapng,.cap,.xml,.txt"
            style={{ display: 'none' }}
            ref={fileInputRef}
            onChange={handleUpload}
            disabled={loading}
          />
          {loading ? (
            <div className="upload-progress">
              <div className="upload-progress-bar" style={{ width: `${progress}%` }} />
              <Activity size={16} className="spin upload-progress-text" />
              <span className="upload-progress-text">Analyzing... {Math.round(progress)}%</span>
            </div>
          ) : (
            <button className="upload-btn" onClick={() => fileInputRef.current?.click()}>
              <Upload size={16} /> Upload Data
            </button>
          )}
          <button className="export-btn" onClick={() => { loadIntel(); setShowIntel(true) }} title="Browse Threat Intel Database">
            <Database size={16} /> Intel DB
          </button>
          <button className="export-btn" onClick={() => { loadHistory(); setShowHistory(true) }} title="View past analysis runs">
            <History size={16} /> History
          </button>
          <button className="export-btn" onClick={exportCSV} disabled={!report}>
            <Download size={16} /> Export CSV
          </button>
          <button className="export-btn" onClick={() => {
            const key = prompt('Enter API Key for backend authentication (stored locally):', localStorage.getItem('OMNILOG_API_KEY') || '')
            if (key !== null) localStorage.setItem('OMNILOG_API_KEY', key)
          }} title="Set API Key">
            API Key
          </button>
        </div>
      </header>

      {/* ── Mode Banner ──────────────────────────────────────── */}
      {report && (
        <div className={`mode-banner ${report.mode === 'lab' ? 'lab' : 'live'}`}>
          {report.mode === 'lab'
            ? <><Beaker size={14} /> Lab Validation Mode — classifications verified against ground truth</>
            : <><Globe size={14} /> Live Analysis Mode — classifications from real threat intelligence</>}
        </div>
      )}

      {/* ── Stats Grid ───────────────────────────────────────── */}
      <div className="stats-grid">
        <div
          className={`stat-card stat-card-clickable ${activeFilter === 'ALL' || (!activeFilter && !report) ? '' : activeFilter === null && report ? 'stat-active stat-active-all' : ''}`}
          onClick={() => report && toggleFilter('ALL')}
          title={report ? 'Show all alerts' : ''}
          id="stat-total-alerts"
        >
          <div className="stat-label">Total Alerts</div>
          <div className={`stat-value ${report ? 'text-primary' : 'text-muted'}`}>{report ? report.alerts.length : '—'}</div>
          {activeFilter === null && report && <div className="stat-indicator stat-indicator-all" />}
        </div>
        <div
          className={`stat-card stat-card-clickable ${activeFilter === 'TRUE POSITIVE' ? 'stat-active stat-active-critical' : ''}`}
          onClick={() => report && tpCount > 0 && toggleFilter('TRUE POSITIVE')}
          title={report && tpCount > 0 ? 'Filter: True Positives only' : ''}
          id="stat-true-positives"
        >
          <div className="stat-label">True Positives</div>
          <div className={`stat-value ${tpCount > 0 ? 'text-critical' : 'text-muted'}`}>{report ? tpCount : '—'}</div>
          {activeFilter === 'TRUE POSITIVE' && <div className="stat-indicator stat-indicator-critical" />}
        </div>
        <div
          className={`stat-card stat-card-clickable ${activeFilter === 'FALSE POSITIVE' ? 'stat-active stat-active-warn' : ''}`}
          onClick={() => report && fpCount > 0 && toggleFilter('FALSE POSITIVE')}
          title={report && fpCount > 0 ? 'Filter: False Positives only' : ''}
          id="stat-false-positives"
        >
          <div className="stat-label">False Positives</div>
          <div className={`stat-value ${fpCount > 0 ? 'text-warn' : (report ? 'text-ok' : 'text-muted')}`}>{report ? fpCount : '—'}</div>
          {activeFilter === 'FALSE POSITIVE' && <div className="stat-indicator stat-indicator-warn" />}
        </div>
        <div
          className={`stat-card stat-card-clickable ${activeFilter === 'UNKNOWN' ? 'stat-active stat-active-unknown' : ''}`}
          onClick={() => report && unkCount > 0 && toggleFilter('UNKNOWN')}
          title={report && unkCount > 0 ? 'Filter: Needs Review only' : ''}
          id="stat-needs-review"
        >
          <div className="stat-label">Needs Review</div>
          <div className={`stat-value ${unkCount > 0 ? 'text-warn' : 'text-muted'}`}>{report ? unkCount : '—'}</div>
          {activeFilter === 'UNKNOWN' && <div className="stat-indicator stat-indicator-unknown" />}
        </div>
      </div>

      {/* ── Content Grid ─────────────────────────────────────── */}
      <div className="content-grid">
        <div className="panel">
          <div className="panel-title flex-between">
            <span className="flex-center gap-sm">
              <ShieldAlert size={16} /> Validated Alerts
              {activeFilter && (
                <span className="filter-chip" onClick={() => setActiveFilter(null)}>
                  <Filter size={12} />
                  {activeFilter === 'ALL' ? 'All' : activeFilter}
                  <X size={12} className="filter-chip-x" />
                </span>
              )}
            </span>
            <span className="data-text">
              {report
                ? `${filteredAlerts.length}${activeFilter ? ` of ${report.alerts.length}` : ''} — ${fmtTs(report.timestamp)} UTC`
                : 'Awaiting data'}
            </span>
          </div>

          {loading ? (
            <div>{[...Array(4)].map((_, i) => <div key={i} className="skeleton-row" />)}</div>
          ) : !report ? (
            <div className="empty-state">Upload a log file, PCAP, XML export, or syslog to begin analysis</div>
          ) : report.alerts.length === 0 ? (
            <div className="empty-state" style={{ border: 'none' }}>No alerts generated for this dataset</div>
          ) : filteredAlerts.length === 0 ? (
            <div className="empty-state" style={{ border: 'none' }}>
              No {activeFilter} alerts in this report
              <br />
              <button className="filter-clear-btn" onClick={() => setActiveFilter(null)}>Clear Filter</button>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr><th>Class</th><th>Source IP</th><th>Detection</th><th>Evidence</th><th>Events</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  {filteredAlerts.map((a, i) => (
                    <tr key={i} className="alert-row-enter">
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '4px' }}>
                          <span className={`badge ${a.classification === 'TRUE POSITIVE' ? 'critical' : a.classification === 'FALSE POSITIVE' ? 'warn' : 'ok'}`}>
                            {a.classification}
                          </span>
                          {a.classification_source && <span className="source-tag" style={{ marginLeft: 0 }}>{a.classification_source}</span>}
                        </div>
                      </td>
                      <td className="data-text" title={a.source_ip}>{a.source_ip}</td>
                      <td className="data-text" title={a.detection_label}>{a.detection_label?.split('(')[0]?.trim() || a.detection_type || '—'}</td>
                      <td>
                        <span className="source-tag" title="Source of the telemetry data">{a.detection_confidence || '—'}</span>
                      </td>
                      <td className="data-text">{a.event_count}</td>
                      <td>
                        <div className="flex-center">
                          <button className="raw-log-btn" onClick={() => setSelectedAlert(a)} title="View Alert Detail">
                            <FileJson size={18} color="var(--signal)" />
                          </button>
                          {a.classification === 'UNKNOWN' && (
                            <>
                              <button className="tag-btn tag-btn-danger" onClick={() => handleTag(a.source_ip, 'TRUE POSITIVE')}>BAD</button>
                              <button className="tag-btn tag-btn-safe" onClick={() => handleTag(a.source_ip, 'FALSE POSITIVE')}>SAFE</button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Panel */}
        <div className="panel">
          <div className="panel-title">Rule Efficacy Summary</div>
          {!report ? (
            <div className="empty-state">Awaiting validation results</div>
          ) : (
            <>
              <div className="rule-summary">
                <div className="rule-name">{report.rule_name}</div>
                <div className="rule-meta flex-between">
                  <span>Threshold: ≥{report.threshold}</span>
                  <span className={fpCount > 0 ? 'text-warn' : 'text-ok'}>{tpCount} TP / {fpCount} FP / {unkCount} UNK</span>
                </div>
              </div>

              {report.pcap_stats && (
                <div className="detail-section">
                  <div className="detail-section-title">PCAP Extraction Stats</div>
                  <div className="detail-grid">
                    {Object.entries(report.pcap_stats).map(([k, v]) => (
                      <div className="detail-item" key={k}>
                        <span className="detail-label">{k.replace(/_/g, ' ')}</span>
                        <span className="detail-value">{v?.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {report.alerts.length > 0 && (
                <div className="detail-section">
                  <div className="detail-section-title">Alert Breakdown</div>
                  {Object.entries(
                    report.alerts.reduce<Record<string, number>>((acc, a) => {
                      const key = a.detection_label || a.detection_type || 'Unknown'
                      acc[key] = (acc[key] || 0) + 1
                      return acc
                    }, {})
                  ).map(([type, count]) => (
                    <div key={type} className="flex-between" style={{ fontSize: '0.8rem', marginBottom: '0.4rem' }}>
                      <span className="text-muted">{type}</span>
                      <span className="data-text">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
