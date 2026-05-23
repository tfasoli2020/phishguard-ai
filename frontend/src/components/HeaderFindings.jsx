import React from 'react'

function MetaRow({ label, value, alert }) {
  if (!value) return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 text-xs py-1.5 border-b border-soc-border/50">
      <span className="text-soc-muted">{label}</span>
      <span className="text-soc-border italic">[not present]</span>
    </div>
  )

  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 text-xs py-1.5 border-b border-soc-border/50">
      <span className="text-soc-muted">{label}</span>
      <span className={`break-all font-mono ${alert ? 'text-soc-high' : 'text-soc-text'}`}>
        {alert && <span className="text-soc-high mr-1">⚠</span>}
        {value.length > 200 ? value.slice(0, 200) + '…' : value}
      </span>
    </div>
  )
}

export default function HeaderFindings({ metadata }) {
  if (!metadata) return null

  const domainMismatch =
    metadata.sender && metadata.reply_to &&
    metadata.sender !== metadata.reply_to &&
    metadata.sender.split('@')[1] !== metadata.reply_to.split('@')[1]

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        Email Header Analysis
        {domainMismatch && (
          <span className="ml-auto severity-badge bg-soc-high/20 text-soc-high border border-soc-high/40 text-xs">
            Domain Mismatch
          </span>
        )}
      </div>

      <div className="p-4">
        <div className="space-y-0">
          <MetaRow label="From" value={metadata.sender} />
          <MetaRow label="Reply-To" value={metadata.reply_to} alert={domainMismatch} />
          <MetaRow label="To" value={metadata.recipient} />
          <MetaRow label="Subject" value={metadata.subject} />
          <MetaRow label="Date" value={metadata.date} />
        </div>

        {domainMismatch && (
          <div className="mt-3 text-xs bg-soc-high/10 border border-soc-high/30 rounded p-2 text-soc-high">
            Sender domain and Reply-To domain do not match. Replies will be directed
            to a different domain — a common phishing and BEC tactic.
          </div>
        )}

        {metadata.domains?.length > 0 && (
          <div className="mt-4">
            <div className="text-xs text-soc-muted uppercase tracking-wider mb-2">
              Unique Domains Detected
            </div>
            <div className="flex flex-wrap gap-1">
              {metadata.domains.map((d, i) => (
                <span key={i} className="text-xs px-2 py-0.5 bg-soc-bg border border-soc-border rounded font-mono text-soc-muted">
                  {d}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
