import React from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts'

const LEVEL_COLORS = {
  Critical: '#f85149',
  High:     '#ff7b72',
  Medium:   '#f0883e',
  Low:      '#3fb950',
}

// Maps internal codes to full professional display labels
const CLASSIFICATION_LABELS = {
  phishing:                  'Phishing',
  business_email_compromise: 'Business Email Compromise',
  spam:                      'Spam',
  likely_legitimate:         'Likely Legitimate',
  inconclusive:              'Inconclusive',
  unknown:                   'Unknown',
}

const ML_LABEL_STYLES = {
  phishing:                  { color: '#f85149', label: 'Phishing' },
  business_email_compromise: { color: '#ff7b72', label: 'Business Email Compromise' },
  spam:                      { color: '#f0883e', label: 'Spam' },
  likely_legitimate:         { color: '#3fb950', label: 'Likely Legitimate' },
  legitimate:                { color: '#3fb950', label: 'Legitimate' },
  inconclusive:              { color: '#8b949e', label: 'Inconclusive' },
}

function ScoreGauge({ score, level }) {
  const color = LEVEL_COLORS[level] || '#8b949e'
  const data = [{ value: score, fill: color }]

  return (
    <div className="relative w-36 h-36 mx-auto">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          cx="50%" cy="50%"
          innerRadius="70%" outerRadius="100%"
          startAngle={220} endAngle={-40}
          data={data}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar
            background={{ fill: '#30363d' }}
            dataKey="value"
            angleAxisId={0}
            cornerRadius={4}
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-3xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-soc-muted">/100</span>
      </div>
    </div>
  )
}

export default function RiskScoreCard({ result }) {
  const color = LEVEL_COLORS[result.risk_level] || '#8b949e'
  // Prefer the server-provided display label; fall back to local map
  const label = result.classification_label
    || CLASSIFICATION_LABELS[result.classification]
    || result.classification

  const mlInfo = result.ml_prediction ? ML_LABEL_STYLES[result.ml_prediction] : null
  const isInconclusive = result.ml_prediction === 'inconclusive'
  const isLowRisk = result.risk_level === 'Low' && result.risk_score === 0

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        Risk Assessment
      </div>

      <div className="p-4 space-y-4">
        <ScoreGauge score={result.risk_score} level={result.risk_level} />

        {/* Risk level badge */}
        <div className="text-center">
          <span
            className="severity-badge text-sm px-4 py-1"
            style={{ backgroundColor: `${color}22`, color, border: `1px solid ${color}44` }}
          >
            {result.risk_level.toUpperCase()}
          </span>
        </div>

        {/* Classification grid */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="bg-soc-bg rounded p-3 space-y-1 col-span-2">
            <div className="text-soc-muted uppercase tracking-wider text-xs">Classification</div>
            <div className="font-bold text-sm" style={{ color }}>{label}</div>
          </div>

          <div className="bg-soc-bg rounded p-3 space-y-1">
            <div className="text-soc-muted uppercase tracking-wider">Findings</div>
            <div className="font-semibold text-soc-text">{result.findings?.length ?? 0}</div>
          </div>

          <div className="bg-soc-bg rounded p-3 space-y-1">
            <div className="text-soc-muted uppercase tracking-wider">Risk Score</div>
            <div className="font-semibold" style={{ color }}>{result.risk_score}/100</div>
          </div>
        </div>

        {/* ML section */}
        {result.ml_prediction && (
          <div className={`rounded p-3 text-xs border ${
            isInconclusive
              ? 'border-soc-border bg-soc-bg'
              : 'border-soc-border bg-soc-bg'
          }`}>
            <div className="text-soc-muted uppercase tracking-wider mb-2">
              ML Classifier — Supporting Signal
            </div>
            <div className="flex items-center justify-between">
              <span
                className="font-semibold"
                style={{ color: mlInfo?.color || '#8b949e' }}
              >
                {mlInfo?.label || result.ml_prediction}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded border ${
                isInconclusive
                  ? 'text-soc-muted border-soc-border'
                  : 'text-soc-text border-soc-border'
              }`}>
                {result.ml_confidence != null
                  ? `${(result.ml_confidence * 100).toFixed(1)}% confidence`
                  : '—'}
              </span>
            </div>
            {isInconclusive && (
              <p className="text-soc-muted mt-1.5 leading-relaxed">
                ML confidence is below the 65% threshold. This result is treated as
                inconclusive and does not affect the final classification.
              </p>
            )}
          </div>
        )}

        {/* Summary */}
        <div
          className="bg-soc-bg rounded p-3 text-xs leading-relaxed border-l-2"
          style={{ borderColor: color }}
        >
          {isLowRisk
            ? <span className="text-soc-low">{result.summary}</span>
            : <span className={result.risk_level === 'Critical' || result.risk_level === 'High'
                ? 'text-soc-text' : 'text-soc-muted'}>{result.summary}</span>
          }
        </div>

        {/* Recommended actions */}
        {result.recommended_actions?.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-xs font-semibold text-soc-muted uppercase tracking-wider mb-2">
              Recommended Actions
            </div>
            {result.recommended_actions.map((action, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span
                  className="mt-0.5 shrink-0"
                  style={{ color: isLowRisk ? '#3fb950' : color }}
                >
                  &#9657;
                </span>
                <span className="text-soc-text leading-relaxed">{action}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
