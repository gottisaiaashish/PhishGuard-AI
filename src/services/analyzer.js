/**
 * PhishGuard AI - Threat Analysis Engine (Mock / Extensible Service)
 * 
 * Pre-configured with heuristic rules, NLP urgency triggers, domain typosquatting detection,
 * and structured interfaces ready to connect Gemini API, VirusTotal, and Google Safe Browsing.
 */

// Heuristic keyword definitions
const URGENCY_PATTERNS = [
  /urgent/i, /immediate(ly)?/i, /suspend(ed|ion)/i, /action required/i,
  /24 hours/i, /expires/i, /critical security/i, /terminate/i, /unauthorized/i,
  /freeze/i, /final notice/i, /restricted/i, /within \d+ (hours|minutes)/i
];

const CREDENTIAL_PATTERNS = [
  /password/i, /credential/i, /sign in/i, /log in/i, /re-enter/i,
  /verify identity/i, /pin code/i, /social security/i, /update payment/i,
  /billing information/i, /debit card/i, /security questions/i
];

const SUSPICIOUS_DOMAINS = [
  /micros0ft/i, /paypa[il]/i, /g00gle/i, /app[il]e-id/i, /amaz0n/i,
  /netf[il]ix/i, /wellsfarg0/i, /chase-verify/i, /secure-login/i,
  /azurepub\.cc/i, /\.top$/i, /\.xyz$/i, /\.cc$/i, /\.tk$/i, /\.su$/i
];

const RAW_IP_PATTERN = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;

export async function analyzeThreatContent({ type, sender = '', subject = '', text = '', filename = '' }) {
  // Aggregate searchable text
  const combinedText = `${sender} ${subject} ${text}`.trim();

  // Extract all HTTP/HTTPS URLs
  const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
  const rawUrls = combinedText.match(urlRegex) || [];
  const uniqueUrls = [...new Set(rawUrls)];

  // Initialize scoring metrics
  let score = 5; // Baseline low risk
  const detectedThreats = [];
  const analyzedUrls = [];
  const findings = [];

  // Check 1: Urgent Coercion Language
  let urgencyHits = 0;
  URGENCY_PATTERNS.forEach(pattern => {
    if (pattern.test(combinedText)) urgencyHits++;
  });

  if (urgencyHits >= 3) {
    score += 35;
    detectedThreats.push({ name: 'Extreme Psychological Urgency', level: 'critical' });
    findings.push(`Contains ${urgencyHits} distinct high-urgency keywords demanding immediate action to coerce compliance.`);
  } else if (urgencyHits >= 1) {
    score += 18;
    detectedThreats.push({ name: 'Urgency & Pressure Tactics', level: 'warning' });
    findings.push('Uses psychological time-limit triggers to discourage verification.');
  }

  // Check 2: Credential & PII Harvesting Signals
  let credHits = 0;
  CREDENTIAL_PATTERNS.forEach(pattern => {
    if (pattern.test(combinedText)) credHits++;
  });

  if (credHits >= 2) {
    score += 30;
    detectedThreats.push({ name: 'Credential Harvesting Vector', level: 'critical' });
    findings.push('Explicitly requests authentication credentials, passwords, or personal identity verification.');
  } else if (credHits === 1) {
    score += 12;
    detectedThreats.push({ name: 'Account Auth Ingestion', level: 'warning' });
    findings.push('Mentions user credentials or sign-in state alteration.');
  }

  // Check 3: Raw IP addresses in URLs
  if (RAW_IP_PATTERN.test(combinedText)) {
    score += 40;
    detectedThreats.push({ name: 'Direct IP URL (No Domain Name)', level: 'critical' });
    findings.push('Links route directly to a numerical IP address, bypassing standard DNS domain trust filters.');
  }

  // Check 4: Suspicious Domain Typosquatting / High-risk TLDs
  let hasTyposquat = false;
  let hasUntrustedTld = false;

  SUSPICIOUS_DOMAINS.forEach(pattern => {
    if (pattern.test(combinedText)) {
      hasTyposquat = true;
    }
  });

  if (hasTyposquat) {
    score += 35;
    detectedThreats.push({ name: 'Brand Impersonation / Typosquatting', level: 'critical' });
    findings.push('Contains deceptive domain spelling imitating trusted enterprise brands (e.g., character substitution or unauthorized proxy).');
  }

  // Check 5: Sender Mismatch & Anomalies
  if (sender) {
    if (/@(gmail|yahoo|hotmail|outlook)\.com/i.test(sender) && /microsoft|apple|paypal|bank|netflix|chase/i.test(combinedText)) {
      score += 25;
      detectedThreats.push({ name: 'Public Webmail Impersonation', level: 'critical' });
      findings.push(`Sender claims corporate affiliation but dispatches from a free consumer email address (${sender}).`);
    } else if (/@.*(verify|security|alert|desk|portal).*\.com/i.test(sender) && !/@.*(google|microsoft|paypal|amazon|apple)\.com/i.test(sender)) {
      score += 20;
      detectedThreats.push({ name: 'Spoofed Security Gateway', level: 'warning' });
      findings.push(`Sender domain "${sender}" simulates an official IT desk using generic security tokens.`);
    }
  }

  // URL Deep Analysis
  uniqueUrls.forEach(urlStr => {
    let urlObj;
    let hostname = '';
    try {
      urlObj = new URL(urlStr);
      hostname = urlObj.hostname;
    } catch (e) {
      hostname = urlStr;
    }

    let urlThreat = 'clean';
    let threatLabel = 'Clean / Verified';
    let vtEngines = '0 / 92';
    let gsbStatus = 'SAFE';

    const isRawIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
    const isTyposquat = SUSPICIOUS_DOMAINS.some(p => p.test(hostname));
    const isSuspiciousTLD = /\.(top|cc|xyz|tk|su|ml|cf|gq)$/i.test(hostname);

    if (isRawIp || isTyposquat) {
      urlThreat = 'malicious';
      threatLabel = isRawIp ? 'Malicious Raw IP' : 'Hostile Impersonation';
      vtEngines = '27 / 92';
      gsbStatus = 'MALWARE / SOCIAL_ENGINEERING';
    } else if (isSuspiciousTLD || /login|verify|account|wallet|claim/i.test(urlStr)) {
      urlThreat = 'suspicious';
      threatLabel = 'Unverified Host';
      vtEngines = '8 / 92';
      gsbStatus = 'SUSPICIOUS';
    }

    analyzedUrls.push({
      url: urlStr,
      domain: hostname,
      threat: urlThreat,
      label: threatLabel,
      vtEngines,
      gsbStatus
    });
  });

  // Normalize final score between 0 and 100
  score = Math.min(Math.max(score, 4), 98);

  // Determine Status Classification
  let status = 'Safe';
  let statusClass = 'safe';
  if (score >= 70) {
    status = 'Phishing Detected';
    statusClass = 'phishing';
  } else if (score >= 35) {
    status = 'Suspicious';
    statusClass = 'suspicious';
  } else {
    status = 'Safe';
    statusClass = 'safe';
    if (detectedThreats.length === 0) {
      detectedThreats.push({ name: 'Verified Infrastructure', level: 'clean' });
      findings.push('No recognized deceptive heuristics, urgency coercion, or blacklisted domains detected.');
    }
  }

  // Generate explainable AI summary
  let aiExplanation = '';
  let recommendations = '';

  if (statusClass === 'phishing') {
    aiExplanation = `High-confidence phishing threat detected (Risk Score: ${score}/100). ${findings.join(' ')}`;
    recommendations = 'Block the sender, quarantine message, do NOT click any embedded links or provide credentials. If credentials were submitted, execute an immediate password rotation and revoke active tokens.';
  } else if (statusClass === 'suspicious') {
    aiExplanation = `Elevated risk signals detected (Risk Score: ${score}/100). Content displays several indicators common in social engineering attacks: ${findings.join(' ')}`;
    recommendations = 'Proceed with extreme caution. Do not follow links directly; navigate to official services through your verified bookmarks or phone app.';
  } else {
    aiExplanation = `Content appears legitimate (Risk Score: ${score}/100). Syntactic analysis, sender reputation indicators, and destination URLs match typical genuine communications without deceptive payload markers.`;
    recommendations = 'Standard caution applies. Ensure multi-factor authentication (MFA) remains enabled on all company and personal accounts.';
  }

  return {
    id: `SCAN-${Math.floor(10000 + Math.random() * 90000)}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    type: type.toUpperCase(),
    target: sender || filename || (type === 'sms' ? 'SMS Message' : 'Uploaded Content'),
    snippet: (subject ? subject + ' - ' : '') + (text || filename || 'Visual Scan Content').substring(0, 75) + '...',
    score,
    status,
    statusClass,
    threats: detectedThreats,
    urls: analyzedUrls,
    aiExplanation,
    recommendations,
    meta: {
      tokensAnalyzed: combinedText.split(/\s+/).length,
      nlpEntropy: (score * 0.084).toFixed(2),
      engineVersion: 'PhishGuard Heuristics v2.4 (Ready for Gemini Pro)'
    }
  };
}
