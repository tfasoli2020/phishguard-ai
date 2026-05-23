import React, { useState, useEffect } from 'react'
import EmailInput from './components/EmailInput'
import RiskScoreCard from './components/RiskScoreCard'
import FindingsList from './components/FindingsList'
import UrlFindings from './components/UrlFindings'
import HeaderFindings from './components/HeaderFindings'
import ReportViewer from './components/ReportViewer'
import AnalysisHistory from './components/AnalysisHistory'
import { analyzeEmail, getAnalysis, getHealth } from './api/client'

const TABS = ['Findings', 'URLs', 'Headers', 'SOC Report']

function StatusBar({ health }) {
  if (!health) return null
  return (
    <div className="flex items-center gap-3 text-xs text-soc-muted">
      <span className={`w-1.5 h-1.5 rounded-full ${health.status === 'ok' ? 'bg-soc-low' : 'bg-soc-critical'}`} />
      <span>API {health.status === 'ok' ? 'Online' : 'Offline'}</span>
      <span className="text-soc-border">|</span>
      <span>ML Model: {health.ml_model_loaded ? 'Loaded' : 'Offline'}</span>
      <span className="text-soc-border">|</span>
      <span>v{health.version}</span>
    </div>
  )
}

export default function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('Findings')
  const [health, setHealth] = useState(null)
  const [currentId, setCurrentId] = useState(null)

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'offline', ml_model_loaded: false, version: '?' }))
  }, [])

  const handleAnalyze = async (emailText) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setActiveTab('Findings')
    try {
      const data = await analyzeEmail(emailText)
      setResult(data)
      setCurrentId(data.analysis_id)
    } catch (err) {
      const detail = err.response?.data?.detail || err.message || 'Analysis failed.'
      setError(String(detail))
    } finally {
      setLoading(false)
    }
  }

  const handleSelectHistory = async (id) => {
    setLoading(true)
    setError(null)
    setActiveTab('Findings')
    try {
      const data = await getAnalysis(id)
      setResult(data)
      setCurrentId(data.analysis_id)
    } catch {
      setError('Failed to load analysis.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text">
      {/* Top bar */}
      <header className="bg-soc-panel border-b border-soc-border px-6 py-3 flex items-center gap-4">
        <div className="flex items-center gap-3">
          <span className="text-soc-critical text-xl">⚠</span>
          <div>
            <h1 className="text-sm font-bold tracking-widest text-soc-text uppercase">
              PhishGuard AI
            </h1>
            <p className="text-xs text-soc-muted">Email Threat Triage System</p>
          </div>
        </div>
        <div className="ml-auto">
          <StatusBar health={health} />
        </div>
      </header>

      {/* Disclaimer banner */}
      <div className="bg-soc-medium/10 border-b border-soc-medium/30 px-6 py-2 text-xs text-soc-medium text-center">
        DEFENSIVE TOOL — For security education and portfolio demonstration only.
        No URLs are fetched. Do not submit real personal data.
      </div>

      <div className="max-w-[1600px] mx-auto p-4 grid grid-cols-1 xl:grid-cols-[340px_1fr_320px] gap-4">
        {/* Left column: Input + History */}
        <div className="space-y-4">
          <EmailInput onAnalyze={handleAnalyze} loading={loading} />
          <AnalysisHistory onSelect={handleSelectHistory} currentId={currentId} />
        </div>

        {/* Center column: Results */}
        <div className="space-y-4">
          {error && (
            <div className="panel border-soc-critical">
              <div className="p-4 text-soc-critical text-sm">
                <span className="font-bold">Error:</span> {error}
              </div>
            </div>
          )}

          {!result && !loading && !error && (
            <div className="panel p-10 text-center space-y-3">
              <div className="text-4xl opacity-20">⚠</div>
              <p className="text-soc-muted text-sm">
                Paste a suspicious email and click <strong className="text-soc-text">Analyze Email</strong> to begin triage.
              </p>
              <p className="text-soc-border text-xs">
                Use the sample loaders to try pre-built phishing, BEC, spam, and legitimate emails.
              </p>
            </div>
          )}

          {loading && (
            <div className="panel p-10 text-center space-y-3">
              <div className="inline-block w-8 h-8 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
              <p className="text-soc-muted text-sm">Running analysis…</p>
            </div>
          )}

          {result && !loading && (
            <>
              {/* Analysis ID badge */}
              <div className="flex items-center gap-3 text-xs text-soc-muted">
                <span className="font-mono bg-soc-panel border border-soc-border rounded px-2 py-0.5">
                  PG-{String(result.analysis_id).padStart(6, '0')}
                </span>
                <span>{result.findings?.length} finding{result.findings?.length !== 1 ? 's' : ''} detected</span>
              </div>

              {/* Tab bar */}
              <div className="flex gap-1 bg-soc-panel border border-soc-border rounded p-1">
                {TABS.map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 py-1.5 text-xs font-medium rounded transition-colors ${
                      activeTab === tab
                        ? 'bg-soc-accent text-soc-bg'
                        : 'text-soc-muted hover:text-soc-text'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {activeTab === 'Findings' && <FindingsList findings={result.findings} />}
              {activeTab === 'URLs' && (
                <UrlFindings urls={result.email_metadata?.urls} />
              )}
              {activeTab === 'Headers' && (
                <HeaderFindings metadata={result.email_metadata} />
              )}
              {activeTab === 'SOC Report' && (
                <ReportViewer report={result.report} analysisId={result.analysis_id} />
              )}
            </>
          )}
        </div>

        {/* Right column: Risk score card */}
        <div className="space-y-4">
          {result && !loading && <RiskScoreCard result={result} />}
          {!result && !loading && (
            <div className="panel p-6 text-center">
              <div className="text-soc-border text-xs">
                Risk score will appear here after analysis.
              </div>
            </div>
          )}
        </div>
      </div>

      <footer className="border-t border-soc-border text-center py-4 text-xs text-soc-border">
        PhishGuard AI v1.0.0 — Defensive security portfolio project.
        Not for use in production environments. All email analysis is local and static.
      </footer>
    </div>
  )
}
