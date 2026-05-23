import React, { useState } from 'react'

const SEVERITY_STYLES = {
  critical: { bg: 'bg-red-950/40',  border: 'border-soc-critical', text: 'text-soc-critical',  badge: 'bg-soc-critical/20 text-soc-critical border border-soc-critical/40' },
  high:     { bg: 'bg-orange-950/30', border: 'border-soc-high',     text: 'text-soc-high',      badge: 'bg-soc-high/20 text-soc-high border border-soc-high/40' },
  medium:   { bg: 'bg-amber-950/20', border: 'border-soc-medium',   text: 'text-soc-medium',    badge: 'bg-soc-medium/20 text-soc-medium border border-soc-medium/40' },
  low:      { bg: 'bg-green-950/10', border: 'border-soc-low',      text: 'text-soc-low',       badge: 'bg-soc-low/20 text-soc-low border border-soc-low/40' },
  info:     { bg: 'bg-blue-950/10',  border: 'border-soc-info',     text: 'text-soc-info',      badge: 'bg-soc-info/20 text-soc-info border border-soc-info/40' },
}

function FindingRow({ finding, index }) {
  const [expanded, setExpanded] = useState(false)
  const styles = SEVERITY_STYLES[finding.severity?.toLowerCase()] || SEVERITY_STYLES.info

  return (
    <div className={`rounded border-l-2 ${styles.border} ${styles.bg} mb-2`}>
      <button
        className="w-full text-left p-3 flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <span className={`severity-badge mt-0.5 shrink-0 ${styles.badge}`}>
          {finding.severity}
        </span>
        <span className="text-sm text-soc-text flex-1">{finding.finding}</span>
        <span className="text-soc-muted text-xs shrink-0 mt-0.5">
          {expanded ? '▲' : '▼'}
        </span>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2 text-xs">
          <div>
            <span className="text-soc-muted uppercase tracking-wider block mb-1">Evidence</span>
            <code className="text-soc-accent bg-soc-bg rounded px-2 py-1 block break-all">
              {finding.evidence}
            </code>
          </div>
          <div>
            <span className="text-soc-muted uppercase tracking-wider block mb-1">Recommendation</span>
            <p className="text-soc-text leading-relaxed">{finding.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default function FindingsList({ findings }) {
  if (!findings?.length) {
    return (
      <div className="panel">
        <div className="panel-header">
          <span className="text-soc-accent">&#9632;</span>
          Detection Findings
        </div>
        <div className="p-6 text-center text-soc-muted text-sm">
          No suspicious indicators detected.
        </div>
      </div>
    )
  }

  // Group by category
  const byCategory = findings.reduce((acc, f) => {
    const cat = f.category || 'General'
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(f)
    return acc
  }, {})

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sortFindings = (arr) =>
    [...arr].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        Detection Findings
        <span className="ml-auto flex gap-2">
          {['critical', 'high', 'medium', 'low'].map((sev) =>
            counts[sev] ? (
              <span key={sev} className={`severity-badge ${SEVERITY_STYLES[sev].badge}`}>
                {counts[sev]} {sev}
              </span>
            ) : null
          )}
        </span>
      </div>

      <div className="p-4 space-y-5">
        {Object.entries(byCategory).map(([category, catFindings]) => (
          <div key={category}>
            <h3 className="text-xs font-semibold text-soc-muted uppercase tracking-wider mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-soc-accent inline-block" />
              {category}
              <span className="text-soc-border">({catFindings.length})</span>
            </h3>
            {sortFindings(catFindings).map((f, i) => (
              <FindingRow key={i} finding={f} index={i} />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
