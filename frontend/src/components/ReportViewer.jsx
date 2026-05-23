import React, { useState } from 'react'

export default function ReportViewer({ report, analysisId }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(report)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API unavailable
    }
  }

  const handleDownload = () => {
    const blob = new Blob([report], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `phishguard-report-PG-${String(analysisId).padStart(6, '0')}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        SOC Analyst Report
        <span className="ml-auto flex gap-2">
          <button
            onClick={handleCopy}
            className="text-xs px-3 py-1 border border-soc-border rounded text-soc-muted
                       hover:border-soc-accent hover:text-soc-accent transition-colors"
          >
            {copied ? '✓ Copied' : 'Copy'}
          </button>
          <button
            onClick={handleDownload}
            className="text-xs px-3 py-1 border border-soc-border rounded text-soc-muted
                       hover:border-soc-accent hover:text-soc-accent transition-colors"
          >
            Download .txt
          </button>
        </span>
      </div>

      <div className="p-4">
        <pre className="bg-soc-bg border border-soc-border rounded p-4 text-xs text-soc-text
                        font-mono overflow-auto max-h-[500px] whitespace-pre leading-relaxed">
          {report}
        </pre>
      </div>
    </div>
  )
}
