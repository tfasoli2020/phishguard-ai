import React, { useState } from 'react'

const SAMPLE_EMAILS = {
  phishing: `From: security-alert@paypa1-verify.com
Reply-To: collect@evil-harvester.net
To: victim@company.com
Subject: URGENT: Your PayPal account has been suspended
Date: Mon, 21 May 2024 09:15:00 +0000

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been
temporarily suspended pending verification.

IMMEDIATE ACTION REQUIRED — failure to verify within 24 hours will result in
permanent account closure.

Click here to verify your account immediately:
http://paypa1-secure-login.verification-center.net/verify?user=victim

Do not ignore this message. Your account will be permanently terminated.

PayPal Security Team`,

  bec: `From: "Robert Johnson" <ceo.johnson@company-corp.net>
Reply-To: r.johnson.ceo@gmail.com
To: finance@company.com
Subject: Confidential - Urgent Wire Transfer Needed
Date: Fri, 17 May 2024 09:12:00 +0000

Hi,

Are you available? I need you to handle something confidential and urgent.

We are finalizing a time-sensitive acquisition and I need a wire transfer of
$47,500 processed today to our legal counsel's escrow account. I am in a meeting
and cannot be reached by phone.

Please do not discuss this with anyone else in the office yet. Keep this strictly
between us until the deal closes.

New wire details:
Bank: First National Trust
Account: 8821047733
Routing: 021000021

Process this immediately and confirm by email only.

Thanks,
Robert Johnson
CEO`,

  marketing: `From: newsletter@shopdeals.example.com
To: subscriber@example.com
Subject: Summer Sale — Up to 40% off this weekend only
Date: Fri, 17 May 2024 14:00:00 +0000

Hi there,

Our biggest sale of the season starts tomorrow! Shop thousands of items at
up to 40% off — limited time only.

Top deals this weekend:
  - Clothing & Accessories — 30% off
  - Electronics — up to 25% off select items
  - Home & Garden — 40% off clearance

Browse deals: http://shopdeals.example.com/sale?ref=newsletter_may24

To manage your email preferences or unsubscribe, visit:
http://shopdeals.example.com/preferences

ShopDeals Inc.`,

  spam: `From: deals@super-discounts.net
To: user@example.com
Subject: YOU HAVE BEEN SELECTED - Claim Your $1000 Prize NOW!

CONGRATULATIONS!!!

You have been randomly selected as our lucky winner this month!

Claim your $1,000 Amazon gift card today - LIMITED TIME OFFER!

You are pre-approved for our exclusive members club. No experience required.
Work from home and earn $5,000 per week!

Click NOW before this offer expires: http://claim-prize.example.net

Unsubscribe | Privacy Policy`,

  legitimate: `From: hr@acmecorp.com
To: john.smith@acmecorp.com
Subject: Q2 Performance Review - Scheduled for June 3rd
Date: Mon, 21 May 2024 08:30:00 +0000

Hi John,

I wanted to reach out to confirm your Q2 performance review is scheduled for
Tuesday, June 3rd at 2:00 PM in Conference Room 4B.

Please take a few minutes beforehand to complete the self-assessment form in
the HR portal. The form is due by end of day on Friday, May 31st.

Let me know if you have any scheduling conflicts and we can find an alternative
time.

Best regards,
Sarah Mitchell
HR Business Partner
ACME Corporation`
}

export default function EmailInput({ onAnalyze, loading }) {
  const [emailText, setEmailText] = useState('')
  const [sampleKey, setSampleKey] = useState('')

  const handleLoadSample = (key) => {
    setEmailText(SAMPLE_EMAILS[key])
    setSampleKey(key)
  }

  const handleClear = () => {
    setEmailText('')
    setSampleKey('')
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (emailText.trim()) onAnalyze(emailText)
  }

  const charCount = emailText.length
  const isOverLimit = charCount > 500000

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="text-soc-accent">&#9632;</span>
        Email Input — Paste Suspicious Email Content
      </div>

      <div className="p-4 space-y-3">
        {/* Sample loaders */}
        <div className="flex flex-wrap gap-2">
          <span className="text-soc-muted text-xs self-center">Load sample:</span>
          {Object.keys(SAMPLE_EMAILS).map((key) => (
            <button
              key={key}
              onClick={() => handleLoadSample(key)}
              className={`text-xs px-3 py-1 rounded border transition-colors ${
                sampleKey === key
                  ? 'border-soc-accent text-soc-accent bg-soc-accent/10'
                  : 'border-soc-border text-soc-muted hover:border-soc-muted'
              }`}
            >
              {key.replace('_', ' ')}
            </button>
          ))}
        </div>

        {/* Textarea */}
        <form onSubmit={handleSubmit}>
          <textarea
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
            placeholder="Paste the full email content here, including headers if available…"
            rows={16}
            className={`w-full bg-soc-bg border rounded p-3 text-sm text-soc-text font-mono
              resize-y focus:outline-none focus:ring-1 focus:ring-soc-accent transition-colors
              ${isOverLimit ? 'border-soc-critical' : 'border-soc-border'}`}
            spellCheck={false}
          />
          <div className="flex items-center justify-between mt-1">
            <span className={`text-xs ${isOverLimit ? 'text-soc-critical' : 'text-soc-muted'}`}>
              {charCount.toLocaleString()} / 500,000 characters
            </span>
          </div>

          {/* Security disclaimer */}
          <p className="text-xs text-soc-muted mt-2 border-l-2 border-soc-border pl-2">
            <span className="text-soc-medium font-semibold">NOTE:</span>{' '}
            No URLs are fetched or executed. This tool performs static analysis only.
            Do not submit emails containing sensitive personal data.
          </p>

          {/* Action buttons */}
          <div className="flex gap-3 mt-4">
            <button
              type="submit"
              disabled={!emailText.trim() || loading || isOverLimit}
              className="btn-primary flex items-center gap-2"
            >
              {loading ? (
                <>
                  <span className="inline-block w-3 h-3 border-2 border-soc-bg border-t-transparent rounded-full animate-spin" />
                  Analyzing…
                </>
              ) : (
                <>&#128269; Analyze Email</>
              )}
            </button>
            <button type="button" onClick={handleClear} className="btn-ghost">
              Clear
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
