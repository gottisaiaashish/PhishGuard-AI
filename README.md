# PhishGuard AI 🛡️

**PhishGuard AI** is a next-generation AI-powered cybersecurity platform designed to detect and neutralize advanced phishing attacks across emails, SMS/messages, and uploaded screenshots with explainable threat scoring.

---

## ✨ Features

- **Cybersecurity Operations Dashboard**: Dark obsidian & cyber-neon aesthetic with real-time operational status and metrics telemetry.
- **Multi-Modal Threat Ingestion**:
  - **Email Inspector**: Analyzes sender headers, subject line, and message body / MIME headers.
  - **SMS / Smishing Inspector**: Evaluates mobile message text, shortlinks, and sender IDs.
  - **Screenshot OCR Scanner**: Drag-and-drop file upload with live image preview and simulated laser scan telemetry.
- **1-Click Hackathon Presets**: Quick-load realistic attack samples (Microsoft 365 credential phish, USPS parcel smishing, PayPal payment spoof, legitimate GitHub notification, fake login portal screenshot).
- **Explainable Threat Report (XAI)**:
  - Animated circular Risk Gauge (`0-100`)
  - Status classification (`Safe`, `Suspicious`, `Phishing Detected`)
  - Detected threat signatures (Urgency coercion, typosquatting, credential harvesting, direct IP links)
  - Suspicious URLs and domain inspection table
  - Plain-English breakdown explaining why content was flagged with actionable recommendations
- **Persistent Scan History**: Local storage-backed scan history log with filterable search and forensic inspection modals.
- **Ready for API Integration**: Modularized analyzer architecture designed for Google Gemini API, VirusTotal, and Google Safe Browsing v4.

---

## 🛠️ Tech Stack

- **Core**: Vanilla HTML5, ES Modules (JavaScript)
- **Styling**: Vanilla CSS (Cyber Tactical Dark Theme, Glassmorphism, Micro-animations)
- **Build Tool**: Vite

---

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+)
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/gottisaiaashish/PhishGuard-AI.git

# Navigate to project directory
cd PhishGuard-AI

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
npm run build
npm run preview
```

---

## 🔒 Roadmap & API Connectors

- [ ] Connect **Google Gemini API** for deep contextual NLP & Vision-based OCR
- [ ] Connect **VirusTotal API** for live multi-engine domain/URL reputation checks
- [ ] Connect **Google Safe Browsing API v4** for threat list lookups
- [ ] Real-time browser extension companion

---

## 📄 License

MIT License. Developed for Cybersecurity Hackathon.
