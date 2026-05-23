import re

# Email header extraction
RE_FROM = re.compile(r"^From:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
RE_REPLY_TO = re.compile(r"^Reply-To:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
RE_TO = re.compile(r"^To:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
RE_SUBJECT = re.compile(r"^Subject:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
RE_DATE = re.compile(r"^Date:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# Email address extraction
RE_EMAIL_ADDR = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
RE_EMAIL_IN_HEADER = re.compile(r"<?([\w.+-]+@[\w.-]+\.[a-zA-Z]{2,})>?")

# URL extraction — catches http/https/ftp links and bare www. links
RE_URL = re.compile(
    r"(?:https?://|ftp://|www\.)(?:[^\s\"'<>\]\)]+)",
    re.IGNORECASE,
)

# IP address as hostname in URL
RE_IP_URL = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}[/:]",
    re.IGNORECASE,
)

# URL shortener domains
URL_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bc.vc", "short.link", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "s.id", "lnkd.in",
})

# Punycode detection
RE_PUNYCODE = re.compile(r"xn--", re.IGNORECASE)

# Suspicious keywords in URLs
SUSPICIOUS_URL_KEYWORDS = frozenset({
    "login", "signin", "verify", "account", "secure", "update",
    "confirm", "banking", "paypal", "password", "credential",
    "authenticate", "validation", "suspended", "unlock", "recover",
})

# Brand names commonly impersonated
IMPERSONATED_BRANDS = frozenset({
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "docusign", "fedex", "ups", "usps", "irs", "chase", "wellsfargo",
    "bankofamerica", "citibank", "usbank",
})

# Free email providers often abused in BEC
FREE_EMAIL_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "icloud.com", "mail.com", "zoho.com", "yandex.com",
    "gmx.com", "live.com", "msn.com", "inbox.com",
})

# Urgency language patterns
URGENCY_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
        r"\baccount.{0,20}suspend", r"\bwithin \d{1,2} hours?\b",
        r"\bwithin \d{1,2} days?\b", r"\bdeadline\b",
        r"\blast chance\b", r"\bfinal notice\b", r"\bexpir(e|ed|ing)\b",
        r"\bfailure to.{0,30}result", r"\blimited time\b",
        r"\bact now\b", r"\bdo not (ignore|delay)\b",
        r"\byour account (will be|has been) (suspended|terminated|closed)",
    ]
]

# Threatening language
THREAT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bterminate(d)?\b", r"\bsuspend(ed)?\b", r"\bpermanently (close|block|lock)",
        r"\blegal action\b", r"\bauthorities\b", r"\blaw enforcement\b",
        r"\bcriminal (charge|complaint)\b", r"\bprosecute\b",
    ]
]

# Credential harvesting patterns
CREDENTIAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bverify your (account|identity|email|password)\b",
        r"\bconfirm your (account|identity|information|details)\b",
        r"\benter your (username|password|credentials|login)\b",
        r"\bclick (here|below|the link).{0,30}(verify|confirm|update|login)",
        r"\bupdate your (account|payment|billing) (information|details|method)\b",
        r"\bsign in to.{0,30}(continue|access|confirm)\b",
        r"\bvalidate your\b",
        r"\bsecurity check\b",
    ]
]

# Payment / financial request patterns
PAYMENT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bwire transfer\b", r"\bgift card\b",
        r"\biTunes (card|gift)\b", r"\bGoogle Play (card|gift)\b",
        r"\bAmazon (gift )?card\b",
        r"\bsend (me )?money\b", r"\bpayment (required|needed|urgent)\b",
        r"\binvoice (attached|due|overdue)\b",
        r"\bbank (account|transfer|wire)\b",
        r"\bchange (of |)bank(ing)? (details|account|information)\b",
        r"\bnew (account|banking) (details|information)\b",
        r"\bremit(tance)?\b", r"\bACH transfer\b",
    ]
]

# BEC-specific patterns
BEC_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bare you available\b", r"\bcan you handle\b",
        r"\bI need your (help|assistance) (on something|urgently|discreetly)\b",
        r"\bdo not (discuss|mention|share) this\b",
        r"\bkeep this (confidential|between us|private|discreet)\b",
        r"\bdo not (call|email) anyone else\b",
        r"\bprocess (this )?payment\b",
        r"\bdon't (call|contact) (me|my office)\b",
        r"\bI am in a meeting\b", r"\bI am traveling\b",
        r"\bCEO\b", r"\bCFO\b", r"\bPresident\b",
        r"\bexecutive (request|approval)\b",
        r"\bvendor (change|update|request)\b",
    ]
]

# Generic / impersonal greetings
GENERIC_GREETING_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"^dear (customer|user|member|account holder|valued customer|client)\b",
        r"^dear sir(/|,| )? madam\b",
        r"^to whom it may concern\b",
        r"^hello (user|customer|member)\b",
        r"^greetings,?\s*$",
    ]
]

# MFA / password reset language
AUTH_RESET_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\breset your password\b", r"\bpassword reset\b",
        r"\bmulti.factor\b", r"\bMFA (reset|code|token)\b",
        r"\bone.time (password|code|pin)\b", r"\bOTP\b",
        r"\bauthenticator (app|code)\b",
        r"\bsecurity code\b", r"\bverification code\b",
    ]
]

# Excessive subdomains: more than 3 labels before the registered domain
RE_EXCESSIVE_SUBDOMAINS = re.compile(
    r"https?://([a-zA-Z0-9-]+\.){4,}[a-zA-Z]{2,}",
    re.IGNORECASE,
)
