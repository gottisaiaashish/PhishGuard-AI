// Predefined realistic test samples for fast hackathon demo testing

// Synthetic sample base64 screenshot representing a fake Microsoft 365 login alert
export const SAMPLE_SCREENSHOT_SVG = `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="600" height="380" viewBox="0 0 600 380">
  <rect width="600" height="380" fill="%23181818" rx="10"/>
  <rect x="15" y="15" width="570" height="40" fill="%23222222" rx="6"/>
  <circle cx="35" cy="35" r="5" fill="%23ef4444"/>
  <circle cx="50" cy="35" r="5" fill="%23f59e0b"/>
  <circle cx="65" cy="35" r="5" fill="%2310b981"/>
  <rect x="90" y="24" width="400" height="22" rx="4" fill="%23111111" stroke="%23333333"/>
  <text x="105" y="39" fill="%23ef4444" font-family="monospace" font-size="11">https://login-micros0ft-security-verify.azurepub.cc/auth</text>
  <rect x="130" y="80" width="340" height="260" fill="%23ffffff" rx="8"/>
  <text x="160" y="125" fill="%230078d4" font-family="sans-serif" font-weight="bold" font-size="20">Microsoft</text>
  <text x="160" y="160" fill="%231b1b1b" font-family="sans-serif" font-weight="bold" font-size="16">Sign in to your account</text>
  <text x="160" y="185" fill="%23d83b01" font-family="sans-serif" font-size="12">Your session has expired. Re-enter password immediately.</text>
  <rect x="160" y="205" width="280" height="32" fill="%23f3f2f1" stroke="%238a8886" rx="2"/>
  <text x="170" y="226" fill="%23605e5c" font-family="sans-serif" font-size="13">user@company.com</text>
  <rect x="160" y="248" width="280" height="32" fill="%23f3f2f1" stroke="%238a8886" rx="2"/>
  <text x="170" y="269" fill="%23605e5c" font-family="sans-serif" font-size="13">••••••••••••</text>
  <rect x="340" y="295" width="100" height="32" fill="%230067b8" rx="2"/>
  <text x="365" y="316" fill="%23ffffff" font-family="sans-serif" font-weight="bold" font-size="13">Sign In</text>
</svg>`;

export const PRESETS = [
  {
    id: 'm365-phish',
    label: 'Microsoft 365 Phish',
    type: 'email',
    riskLevel: 'critical',
    data: {
      sender: 'security-alert@micros0ft-verify.com',
      subject: 'URGENT: Microsoft 365 Password Expiration Notice - Immediate Action Required',
      body: `Dear User,

Your Office 365 password expires in 24 hours. Failure to update your security credentials will result in immediate suspension of your Microsoft account and deletion of your pending emails.

Please retain your existing password or sync a new one using our secure Microsoft identity portal:
https://login-micros0ft-security-verify.azurepub.cc/auth/login?session=98234194

Notice: Do not ignore this automated alert. IT Security Operations Team.
Ref: MS-SEC-89214710`
    }
  },
  {
    id: 'usps-smish',
    label: 'USPS Package Smishing',
    type: 'sms',
    riskLevel: 'critical',
    data: {
      sender: '+1 (855) 902-1849',
      body: `[U.S. Postal Service] Alert: We could not deliver parcel #US9400192 due to an incomplete street address. Update your delivery address & settle $1.85 redelivery surcharge within 12 hours: https://usps-parcel-track-update.top/delivery or package will be returned to sender.`
    }
  },
  {
    id: 'paypal-spoof',
    label: 'PayPal Payment Spoof',
    type: 'email',
    riskLevel: 'critical',
    data: {
      sender: 'service@notification-paypaI.com',
      subject: 'Transaction Receipt: Authorized charge of $849.99 for Apple iPhone 15 Pro',
      body: `Hello Customer,

Thank you for your recent purchase. You sent a payment of $849.99 USD to CryptoDirect Trading LLC.

If you DID NOT authorize this transaction, click below within 30 minutes to cancel this transaction and refund your funds immediately:
http://194.26.29.112/dispute/resolve-unauthorized-payment.php

If you have questions, contact PayPal Customer Resolution Center.
PayPal Help Center: https://www.paypal.com`
    }
  },
  {
    id: 'github-safe',
    label: 'GitHub Safe Alert',
    type: 'email',
    riskLevel: 'safe',
    data: {
      sender: 'no-reply@github.com',
      subject: '[GitHub] A new public SSH key was added to your account',
      body: `Hey developer,

We're pinging you to notify you that the following SSH key was added to your GitHub account:

Title: macbook-pro-ed25519
Fingerprint: SHA256:d8K9z5j+LkWvP67s...

If you added this key, you can safely ignore this email.
If you did not add this key, please visit https://github.com/settings/keys to remove it immediately and review your account security audit log.`
    }
  },
  {
    id: 'screenshot-sample',
    label: 'Fake Login Screenshot',
    type: 'screenshot',
    riskLevel: 'critical',
    data: {
      imagePreview: SAMPLE_SCREENSHOT_SVG,
      filename: 'microsoft_login_alert.png',
      ocrText: 'https://login-micros0ft-security-verify.azurepub.cc/auth Microsoft Sign in to your account. Your session has expired. Re-enter password immediately. user@company.com Sign In'
    }
  }
];

export const INITIAL_HISTORY = [
  {
    id: 'SCAN-84920',
    timestamp: '2026-09-02 14:15:32',
    type: 'Email',
    target: 'security-alert@micros0ft-verify.com',
    snippet: 'URGENT: Microsoft 365 Password Expiration Notice...',
    score: 94,
    status: 'Phishing',
    statusClass: 'phishing',
    threats: ['Domain Typosquatting', 'Urgency Coercion', 'Credential Harvesting'],
    urlsFound: ['https://login-micros0ft-security-verify.azurepub.cc/auth'],
    aiExplanation: 'The email uses high-urgency language ("expires in 24 hours") and sender domain "micros0ft-verify.com" exhibits classic character substitution (zero for "o"). Destination URL leads to an unauthorized third-party subdomain attempting credential harvesting.'
  },
  {
    id: 'SCAN-84918',
    timestamp: '2026-09-02 13:42:10',
    type: 'SMS',
    target: '+1 (855) 902-1849',
    snippet: '[U.S. Postal Service] Alert: We could not deliver parcel...',
    score: 88,
    status: 'Phishing',
    statusClass: 'phishing',
    threats: ['Smishing Lure', 'Fee Surcharge Bait', 'Unverified TLD (.top)'],
    urlsFound: ['https://usps-parcel-track-update.top/delivery'],
    aiExplanation: 'Classic smishing vector simulating Postal Authority with fake urgency and non-governmental high-risk TLD (.top). Designed to capture credit card details under the guise of an $1.85 redelivery fee.'
  },
  {
    id: 'SCAN-84904',
    timestamp: '2026-09-02 11:18:05',
    type: 'Email',
    target: 'no-reply@github.com',
    snippet: '[GitHub] A new public SSH key was added to your account...',
    score: 6,
    status: 'Safe',
    statusClass: 'safe',
    threats: ['No Malicious Vectors Detected'],
    urlsFound: ['https://github.com/settings/keys'],
    aiExplanation: 'DKIM and SPF headers match authentic GitHub origin. Destination URLs route directly to official second-level domain (github.com) over TLS with no deceptive call-to-action.'
  },
  {
    id: 'SCAN-84882',
    timestamp: '2026-09-02 09:30:44',
    type: 'Screenshot',
    target: 'wellsfargo_alert_portal.png',
    snippet: 'OCR: Wells Fargo Security Center - Verification of Debit Card...',
    score: 91,
    status: 'Phishing',
    statusClass: 'phishing',
    threats: ['Brand Impersonation', 'Fake Bank Portal', 'Sensitive PII Ingestion'],
    urlsFound: ['http://secure-wellsfargo-update.net/login'],
    aiExplanation: 'Visual telemetry identified authentic Wells Fargo branding overlaid on an unregistered hostile domain. Input fields request full debit card numbers and PINs.'
  }
];
