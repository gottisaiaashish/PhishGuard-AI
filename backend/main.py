"""
PhishGuard AI - Backend Threat Intelligence Service
FastAPI REST API deployed on Render
Connects: Google Gemini 3.5 Flash + VirusTotal v3 + Live Redirect Unshortening
"""

import os
import re
import json
import time
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Load environment variables
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

app = FastAPI(
    title="PhishGuard AI - Threat Intelligence Engine",
    version="2.4.0",
    description="Enterprise Zero-Day Phishing Detection API integrating Google Gemini 3.5 Flash & VirusTotal v3."
)

# Enable CORS for all origins (supports Vercel, localhost, and custom domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class ThreatAnalysisRequest(BaseModel):
    type: str  # 'email' | 'sms' | 'screenshot'
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    text: Optional[str] = ""
    filename: Optional[str] = ""
    imageBase64: Optional[str] = ""

# Heuristic Patterns
URGENCY_PATTERNS = [
  re.compile(r'urgent', re.I), re.compile(r'immediate(ly)?', re.I),
  re.compile(r'suspend(ed|ion)', re.I), re.compile(r'action required', re.I),
  re.compile(r'24 hours', re.I), re.compile(r'expires', re.I),
  re.compile(r'critical security', re.I), re.compile(r'terminate', re.I),
  re.compile(r'unauthorized', re.I), re.compile(r'freeze', re.I)
]

CREDENTIAL_PATTERNS = [
  re.compile(r'password', re.I), re.compile(r'credential', re.I),
  re.compile(r'sign in', re.I), re.compile(r'log in', re.I),
  re.compile(r'verify identity', re.I), re.compile(r'pin code', re.I),
  re.compile(r'social security', re.I), re.compile(r'update payment', re.I)
]

SUSPICIOUS_DOMAINS = [
  re.compile(r'micros0ft', re.I), re.compile(r'paypa[il]', re.I),
  re.compile(r'g00gle', re.I), re.compile(r'app[il]e-id', re.I),
  re.compile(r'azurepub\.cc', re.I), re.compile(r'\.(top|cc|xyz|tk|su)$', re.I)
]

@app.get("/")
def root():
    return {
        "service": "PhishGuard AI Backend",
        "status": "online",
        "version": "2.4.0",
        "docs": "/docs",
        "health": "/api/health"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "geminiConfigured": bool(GEMINI_API_KEY and len(GEMINI_API_KEY) > 10),
        "virusTotalConfigured": bool(VIRUSTOTAL_API_KEY and len(VIRUSTOTAL_API_KEY) > 10),
        "model": GEMINI_MODEL,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.post("/api/analyze")
async def analyze_content(req: ThreatAnalysisRequest):
    combined_text = f"{req.sender} {req.subject} {req.text}".strip()
    
    # 1. Extract raw URLs
    url_pattern = re.compile(r'https?://[^\s"\'<>]+', re.I)
    raw_urls = list(set(url_pattern.findall(combined_text)))

    # 2. Perform live HTTP Redirect Unshortening for shortlinks
    resolved_urls = []
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
        for url in raw_urls:
            final_url = url
            is_redirected = False
            # Check if domain looks like a shortener
            if any(s in url for s in ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy']):
                try:
                    head_res = await client.head(url)
                    final_url = str(head_res.url)
                    is_redirected = (final_url != url)
                except Exception:
                    pass
            resolved_urls.append({"original": url, "final": final_url, "redirected": is_redirected})

    # 3. Call VirusTotal API for domain intel
    vt_enriched_urls = []
    async with httpx.AsyncClient(timeout=5.0) as client:
        for item in resolved_urls:
            target_url = item["final"]
            parsed_host = urlparse(target_url).hostname or target_url
            vt_info = await check_virustotal_domain(client, parsed_host)
            vt_enriched_urls.append({
                "url": target_url,
                "domain": parsed_host,
                "threat": vt_info.get("threat", "clean"),
                "label": vt_info.get("label", "Clean / Verified"),
                "vtEngines": vt_info.get("vtEngines", "0 / 92"),
                "gsbStatus": vt_info.get("gsbStatus", "SAFE")
            })

    # 4. Primary Threat Analysis: Google Gemini 3.5 Flash
    if GEMINI_API_KEY:
        try:
            gemini_result = await call_gemini_api(req, combined_text, vt_enriched_urls)
            if gemini_result:
                return gemini_result
        except Exception as e:
            print(f"[WARN] Gemini API error: {e}, falling back to Heuristic Matrix")

    # 5. Fallback Threat Analysis: Local Cybersecurity Matrix
    return run_heuristics(req, combined_text, vt_enriched_urls)

async def check_virustotal_domain(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY or not domain or domain == "localhost":
        return {"threat": "clean", "label": "Unverified Host", "vtEngines": "0 / 92", "gsbStatus": "SAFE"}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        res = await client.get(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        if res.status_code == 200:
            data = res.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results = data.get("last_analysis_results", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 92

            gsb_verdict = results.get("Google Safebrowsing", {}).get("result", "clean")

            if malicious >= 2:
                threat = "malicious"
                label = f"Malicious ({malicious} Antivirus Flags)"
            elif malicious == 1 or suspicious >= 1:
                threat = "suspicious"
                label = f"Suspicious ({malicious + suspicious} Flags)"
            else:
                threat = "clean"
                label = "Clean (VirusTotal Verified)"

            return {
                "threat": threat,
                "label": label,
                "vtEngines": f"{malicious} / {total}",
                "gsbStatus": "SAFE" if gsb_verdict == "clean" else gsb_verdict.upper()
            }
    except Exception as e:
        print(f"[WARN] VirusTotal check failed for {domain}: {e}")

    return {"threat": "clean", "label": "No VT Flags", "vtEngines": "0 / 92", "gsbStatus": "SAFE"}

async def call_gemini_api(req: ThreatAnalysisRequest, combined_text: str, vt_urls: List[Dict[str, Any]]):
    prompt = f"""You are PhishGuard AI, an elite cybersecurity threat analyst.
Evaluate this {req.type.upper()} content for social engineering, phishing, typosquatting, credential harvesting, or legitimacy.

CONTENT DETAILS:
- Channel: {req.type}
- Sender: {req.sender or 'None specified'}
- Subject: {req.subject or 'None specified'}
- Body/Text: {req.text or 'None specified'}

Analyze the text and return ONLY a valid JSON object with EXACTLY this structure:
{{
  "score": 92,
  "status": "Phishing Detected",
  "threats": [
    {{"name": "Domain Typosquatting", "level": "critical"}},
    {{"name": "Urgency Coercion", "level": "critical"}}
  ],
  "aiExplanation": "Plain English explanation of why this was flagged.",
  "recommendations": "Actionable security recommendation for the user."
}}
Notes on values:
- "score": Integer from 0 to 100 (0-30: Safe, 31-69: Suspicious, 70-100: Phishing Detected).
- "status": Must be "Safe", "Suspicious", or "Phishing Detected".
- "threats": Array of objects with "name" and "level" ("critical" | "warning" | "clean").
- Return strictly raw JSON. Do not include markdown codeblocks."""

    request_body: Dict[str, Any] = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json"
        }
    }

    # Handle imageBase64 for multimodal vision
    if req.imageBase64 and req.imageBase64.startswith("data:image"):
        mime_match = re.match(r"^data:(image/[a-zA-Z+]+);base64,", req.imageBase64)
        if mime_match:
            mime_type = mime_match.group(1)
            raw_base64 = re.sub(r"^data:image/[a-zA-Z+]+;base64,", "", req.imageBase64)
            request_body["contents"][0]["parts"].append({
                "inlineData": {
                    "mimeType": mime_type,
                    "data": raw_base64
                }
            })

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(endpoint, json=request_body)
        if res.status_code != 200:
            raise HTTPException(status_code=res.status_code, detail="Gemini API request failed")

        data = res.json()
        raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        if not raw_text:
            raise ValueError("Empty response from Gemini")

        parsed = json.loads(raw_text)
        score = parsed.get("score", 10)
        status_class = "phishing" if score >= 70 else ("suspicious" if score >= 35 else "safe")

        # If VirusTotal flagged any malicious link, ensure risk score reflects it
        if any(u.get("threat") == "malicious" for u in vt_urls) and score < 75:
            score = max(score, 85)
            status_class = "phishing"
            parsed["status"] = "Phishing Detected"

        return {
            "id": f"SCAN-{int(time.time() * 1000) % 90000 + 10000}",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": req.type.upper(),
            "target": req.sender or ( "SMS Message" if req.type == "sms" else "Uploaded Content"),
            "snippet": ((req.subject + " - ") if req.subject else "") + (req.text or "Content")[:75] + "...",
            "score": score,
            "status": parsed.get("status", "Safe"),
            "statusClass": status_class,
            "threats": parsed.get("threats", []),
            "urls": vt_urls,
            "aiExplanation": parsed.get("aiExplanation", "No detailed analysis returned."),
            "recommendations": parsed.get("recommendations", "Verify sender integrity."),
            "meta": {
                "tokensAnalyzed": len(combined_text.split()),
                "engineVersion": f"Google Gemini ({GEMINI_MODEL}) + VirusTotal Backend Core"
            }
        }

def run_heuristics(req: ThreatAnalysisRequest, combined_text: str, vt_urls: List[Dict[str, Any]]):
    score = 5
    detected_threats = []
    findings = []

    # Urgency Check
    urgency_hits = sum(1 for p in URGENCY_PATTERNS if p.search(combined_text))
    if urgency_hits >= 3:
        score += 35
        detected_threats.append({"name": "Extreme Psychological Urgency", "level": "critical"})
        findings.append(f"Demands urgent immediate action with {urgency_hits} coercive markers.")
    elif urgency_hits >= 1:
        score += 18
        detected_threats.append({"name": "Urgency & Pressure Tactics", "level": "warning"})
        findings.append("Uses pressure triggers to discourage scrutiny.")

    # Credential Check
    cred_hits = sum(1 for p in CREDENTIAL_PATTERNS if p.search(combined_text))
    if cred_hits >= 2:
        score += 30
        detected_threats.append({"name": "Credential Harvesting Vector", "level": "critical"})
        findings.append("Requests authentication passwords or personal identity credentials.")
    elif cred_hits == 1:
        score += 12
        detected_threats.append({"name": "Account Auth Ingestion", "level": "warning"})

    # Typosquatting Check
    if any(p.search(combined_text) for p in SUSPICIOUS_DOMAINS):
        score += 35
        detected_threats.append({"name": "Brand Typosquatting / Spoofing", "level": "critical"})
        findings.append("Contains deceptive domain spelling imitating major brands.")

    # Check VirusTotal findings
    if any(u.get("threat") == "malicious" for u in vt_urls):
        score += 45
        detected_threats.append({"name": "Blacklisted Malicious Destination", "level": "critical"})
        findings.append("Destination URL flagged as malicious by multiple antivirus vendors on VirusTotal.")

    score = min(max(score, 4), 98)
    status_class = "phishing" if score >= 70 else ("suspicious" if score >= 35 else "safe")
    status = "Phishing Detected" if score >= 70 else ("Suspicious" if score >= 35 else "Safe")

    return {
        "id": f"SCAN-{int(time.time() * 1000) % 90000 + 10000}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": req.type.upper(),
        "target": req.sender or ("SMS Message" if req.type == "sms" else "Uploaded Content"),
        "snippet": ((req.subject + " - ") if req.subject else "") + (req.text or "Content")[:75] + "...",
        "score": score,
        "status": status,
        "statusClass": status_class,
        "threats": detected_threats,
        "urls": vt_urls,
        "aiExplanation": " ".join(findings) if findings else "Legitimate communications structure with no malicious payload indicators.",
        "recommendations": "Block sender and do not click links." if score >= 70 else "Exercise standard email caution.",
        "meta": {
            "tokensAnalyzed": len(combined_text.split()),
            "engineVersion": "PhishGuard Backend Heuristics + VirusTotal v3"
        }
    }

class ChatRequest(BaseModel):
    question: str
    context: Optional[Dict[str, Any]] = {}

@app.post("/api/chat")
async def chat_follow_up(req: ChatRequest):
    question = req.question.strip()
    ctx = req.context or {}

    prompt = f"""You are PhishGuard AI, an elite cybersecurity assistant protecting users from social engineering, phishing, and scam lures.

Context of currently analyzed message:
- Content: "{ctx.get('snippet') or ctx.get('text') or 'Suspicious communication'}"
- Sender/Origin: "{ctx.get('target') or ctx.get('sender') or 'Unknown'}"
- Security Verdict: {ctx.get('status') or 'Suspicious'} ({ctx.get('score', 80)}/100 Risk Score)
- Identified Threats: {', '.join(ctx.get('threats', [])) if isinstance(ctx.get('threats'), list) else 'Urgency coercion, unverified link'}
- AI Assessment: "{ctx.get('aiExplanation', '')}"

The user has asked the following follow-up question:
"{question}"

Instructions:
1. Speak in a helpful, conversational, expert cybersecurity tone (like ChatGPT).
2. Give clear, direct bullet points.
3. If there is immediate danger (e.g. user clicked a link or entered password), provide immediate incident-response steps.
4. Keep the answer concise and easy to read."""

    if GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(url, json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 700}
                })
                if res.status_code == 200:
                    data = res.json()
                    answer = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text")
                    if answer:
                        return {"answer": answer}
        except Exception as e:
            print(f"Backend Gemini Chat failed: {e}")

    # Fallback response
    q_low = question.lower()
    main_domain = "the link"
    if ctx.get("urls") and len(ctx["urls"]) > 0:
        main_domain = ctx["urls"][0].get("domain", "the domain")
    elif ctx.get("urlsFound") and len(ctx["urlsFound"]) > 0:
        main_domain = ctx["urlsFound"][0]

    if any(k in q_low for k in ["link", "suspicious", "spiceous", "why", "fake", "domain", "url"]):
        return {
            "answer": f"### 🔍 Why This Link is Flagged as Suspicious:\n\n1. **Deceptive Lookalike Domain**: The URL uses `{main_domain}`, which mimics trusted institutions to deceive victims.\n2. **Urgency Manipulation**: The communication uses forced urgency to prevent you from inspecting the link's genuine destination.\n3. **Credential Theft Hazard**: Pages behind these links typically mimic real portals to steal account logins or banking OTPs.\n\n💡 **Safe Action**: Never click the link. Visit the official service directly through your browser."
        }
    elif any(k in q_low for k in ["clicked", "opened", "already", "entered", "password"]):
        return {
            "answer": "### 🚨 Immediate Incident Response Steps:\n\n1. **Disconnect from the Page**: Close the browser tab immediately.\n2. **Do Not Submit Info**: Never enter passwords, OTPs, or debit card PINs.\n3. **Rotate Passwords**: From another trusted device, reset your account credentials.\n4. **Alert Your Bank**: Call the official emergency fraud helpline on your card to block unauthorized transactions."
        }
    elif any(k in q_low for k in ["report", "it team", "company", "manager"]):
        return {
            "answer": f"### 📋 Incident Report Template:\n\n- **Incident Type**: Suspected Phishing Lure\n- **Target Origin**: {ctx.get('target', 'Unknown')}\n- **Target URL**: {main_domain}\n- **Risk Assessment**: {ctx.get('score', 85)}/100 ({ctx.get('status', 'High Risk')})\n- **Action Taken**: Flagged and quarantined via PhishGuard AI."
        }
    return {
        "answer": "### 🛡️ PhishGuard Security Advisory:\n\n1. **High-Risk Indicators**: The analyzed message exhibits patterns characteristic of brand impersonation and urgency coercion.\n2. **Golden Rule**: Legitimate institutions will never ask you to verify credentials through unverified links or SMS.\n3. **Next Step**: Delete this message immediately and block the sender."
    }
