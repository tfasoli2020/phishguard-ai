import React, { useEffect, useState } from 'react'
import { getHistory, deleteAnalysis } from '../api/client'

const LEVEL_COLORS = {
  Critical: 'text-soc-critical',
  High:     'text-soc-high',
  Medium:   'text-soc-medium',
  Low:      'text-soc-low',
}

const LEVEL_BADGE_CLASSES = {
  Critical: 'bg-soc-critical/20 text-soc-critical border border-soc-critical/40',
  High:     'bg-soc-high/20 text-soc-high border border-soc-high/40',
  Medium:   'bg-soc-medium/20 text-soc-medium border border-soc-medium/40',
  Low:      'bg-soc-low/20 text-soc-low border border-soc-low/40',
}

// Short abbreviations for history list (space-constrained)
const CLASSIFICATION_SHORT = {
  phishing:                  'PHISHING',
  business_email_compromise: 'BEC',
  spam:                      'SPAM',
  likely_legitimate:         'LEGIT',
  inconclusive:              'INCONCL.',
}

export default function AnalysisHistory({ onSelect, currentId }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchHistory = async () => {
    try {
      setLoading(true)
      const data = await getHistory(50)
      setHistory(data)
      setError(null)
    } catch {
      setError('Failed to load history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [currentId])

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    if (!window.confirm('Delete this analysis record?')) return
    try {
      await deleteAnalysis(id)
      setHistory((prev) => prev.filter((r) => r.analysis_id !== id))
    } catch {
      alert('Failed to delete record.')
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        Analysis History
        <span className="ml-auto text-soc-muted font-normal normal-case tracking-normal text-xs">
          {history.length} record{history.length !== 1 ? 's' : ''}
        </span>
        <button
          onClick={fetchHistory}
          className="text-xs text-soc-muted hover:text-soc-accent transition-colors ml-2"
          title="Refresh"
        >
          ↻
        </button>
      </div>

      <div className="max-h-[400px] overflow-y-auto">
        {loading && (
          <div className="p-4 text-center text-soc-muted text-xs">Loading…</div>
        )}
        {error && (
          <div className="p-4 text-center text-soc-critical text-xs">{error}</div>
        )}
        {!loading && !error && history.length === 0 && (
          <div className="p-4 text-center text-soc-muted text-xs">No analyses yet.</div>
        )}

        {!loading && history.map((record) => {
          const active = record.analysis_id === currentId
          const levelColor = LEVEL_COLORS[record.risk_level] || 'text-soc-muted'
          const badgeClass = LEVEL_BADGE_CLASSES[record.risk_level] || 'bg-soc-border/20 text-soc-muted border border-soc-border'
          const classShort = CLASSIFICATION_SHORT[record.classification] || record.classification.toUpperCase()
          const ts = new Date(record.timestamp).toLocaleString()
          const fullLabel = record.classification_label || record.classification

          return (
            <div
              key={record.analysis_id}
              onClick={() => onSelect(record.analysis_id)}
              className={`px-4 py-3 border-b border-soc-border cursor-pointer transition-colors
                flex items-start gap-3 group
                ${active ? 'bg-soc-accent/10 border-l-2 border-l-soc-accent' : 'hover:bg-soc-bg'}`}
              title={`Classification: ${fullLabel}`}
            >
              {/* Score */}
              <div className="text-center shrink-0 w-10">
                <div className={`text-sm font-bold ${levelColor}`}>{record.risk_score}</div>
                <div className="text-soc-muted text-xs">/100</div>
              </div>

              <div className="flex-1 min-w-0 text-xs space-y-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`font-bold ${levelColor}`}>{classShort}</span>
                  <span className={`severity-badge text-xs px-1.5 py-0 ${badgeClass}`}>
                    {record.risk_level}
                  </span>
                </div>
                <div className="text-soc-text truncate">
                  {record.subject || record.sender || '(no subject / sender)'}
                </div>
                <div className="text-soc-muted text-xs">{ts}</div>
              </div>

              <button
                onClick={(e) => handleDelete(e, record.analysis_id)}
                className="text-soc-border hover:text-soc-critical transition-colors shrink-0
                           opacity-0 group-hover:opacity-100 text-xs"
                title="Delete"
              >
                ✕
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
