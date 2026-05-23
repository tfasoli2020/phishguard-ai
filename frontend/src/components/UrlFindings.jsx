import React, { useState } from 'react'

function isSuspiciousUrl(url) {
  const lower = url.toLowerCase()
  return (
    lower.startsWith('http://') ||
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) ||
    ['bit.ly', 'tinyurl', 't.co', 'goo.gl'].some((s) => lower.includes(s)) ||
    /xn--/.test(url) ||
    ['login', 'signin', 'verify', 'secure', 'account', 'password'].some((kw) => lower.includes(kw))
  )
}

export default function UrlFindings({ urls }) {
  const [showAll, setShowAll] = useState(false)
  const suspicious = urls?.filter(isSuspiciousUrl) || []
  const clean = urls?.filter((u) => !isSuspiciousUrl(u)) || []
  const displayed = showAll ? urls : (urls || []).slice(0, 10)

  if (!urls?.length) {
    return (
      <div className="panel">
        <div className="panel-header">
          <span className="text-soc-accent">&#9632;</span>
          URL Analysis
        </div>
        <div className="p-4 text-soc-muted text-sm">No URLs extracted from this email.</div>
      </div>
    )
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        URL Analysis
        <span className="ml-auto flex gap-2 text-xs">
          {suspicious.length > 0 && (
            <span className="severity-badge bg-soc-critical/20 text-soc-critical border border-soc-critical/40">
              {suspicious.length} suspicious
            </span>
          )}
          <span className="text-soc-muted">{urls.length} total</span>
        </span>
      </div>

      <div className="p-4 space-y-2">
        <div className="text-xs text-soc-muted border border-soc-border rounded p-2 bg-soc-bg mb-3">
          URLs are not fetched or resolved. All analysis is structural and lexical only.
        </div>

        {(showAll ? urls : urls.slice(0, 10)).map((url, i) => {
          const suspicious = isSuspiciousUrl(url)
          return (
            <div
              key={i}
              className={`rounded p-2 flex items-start gap-2 text-xs font-mono ${
                suspicious
                  ? 'bg-red-950/30 border border-soc-critical/30'
                  : 'bg-soc-bg border border-soc-border'
              }`}
            >
              <span className={`shrink-0 mt-0.5 ${suspicious ? 'text-soc-critical' : 'text-soc-low'}`}>
                {suspicious ? '⚠' : '✓'}
              </span>
              {/* Display only — never rendered as a clickable <a> link */}
              <span className={`break-all ${suspicious ? 'text-soc-critical' : 'text-soc-muted'}`}>
                {url.length > 120 ? url.slice(0, 120) + '…' : url}
              </span>
            </div>
          )
        })}

        {urls.length > 10 && (
          <button
            onClick={() => setShowAll(!showAll)}
            className="text-xs text-soc-accent hover:underline mt-1"
          >
            {showAll ? 'Show fewer' : `Show all ${urls.length} URLs`}
          </button>
        )}
      </div>
    </div>
  )
}
