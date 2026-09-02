import { PRESETS, INITIAL_HISTORY, SAMPLE_SCREENSHOT_SVG } from './data/mockData.js';
import { analyzeThreatContent, askGeminiFollowUp } from './services/analyzer.js';
import { mountFuzzyText } from './components/FuzzyText.js';
import { mountFaultyTerminal } from './components/FaultyTerminal.js';

// Application State
const state = {
  activeTab: 'url', // 'url' | 'email' | 'sms' | 'screenshot'
  uploadedFile: null,
  uploadedFileDataUrl: null,
  currentAnalysis: null,
  history: []
};

// Storage Key
const HISTORY_STORAGE_KEY = 'phishguard_scan_history_v1';

// DOM Elements Cache
const elements = {
  // Tabs
  tabBtns: document.querySelectorAll('.tab-btn'),
  contentUrl: document.getElementById('contentUrl'),
  contentEmail: document.getElementById('contentEmail'),
  contentSms: document.getElementById('contentSms'),
  contentScreenshot: document.getElementById('contentScreenshot'),

  // URL Input
  urlInput: document.getElementById('urlInput'),

  // Email Inputs
  emailSender: document.getElementById('emailSender'),
  emailSubject: document.getElementById('emailSubject'),
  emailBody: document.getElementById('emailBody'),
  emailBodyCounter: document.getElementById('emailBodyCounter'),

  // SMS Inputs
  smsSender: document.getElementById('smsSender'),
  smsBody: document.getElementById('smsBody'),
  smsBodyCounter: document.getElementById('smsBodyCounter'),

  // Screenshot Inputs
  dropzone: document.getElementById('dropzone'),
  screenshotFileInput: document.getElementById('screenshotFileInput'),
  imagePreviewCard: document.getElementById('imagePreviewCard'),
  imagePreview: document.getElementById('imagePreview'),
  imagePreviewWrapper: document.getElementById('imagePreviewWrapper'),
  previewFilename: document.getElementById('previewFilename'),
  btnRemoveImg: document.getElementById('btnRemoveImg'),

  // Presets & Workbench Actions
  presetsContainer: document.getElementById('presetsContainer'),
  btnClearInputs: document.getElementById('btnClearInputs'),
  btnAnalyze: document.getElementById('btnAnalyze'),

  // Telemetry HUD
  scanningHud: document.getElementById('scanningHud'),
  hudProgressBar: document.getElementById('hudProgressBar'),
  hudPercent: document.getElementById('hudPercent'),
  hudTelemetryLog: document.getElementById('hudTelemetryLog'),

  // Results Section
  resultSection: document.getElementById('resultSection'),
  resultBanner: document.getElementById('resultBanner'),
  resultStatusBadge: document.getElementById('resultStatusBadge'),
  resultStatusText: document.getElementById('resultStatusText'),
  resultTargetName: document.getElementById('resultTargetName'),
  resultMetaTime: document.getElementById('resultMetaTime'),
  gaugeProgressCircle: document.getElementById('gaugeProgressCircle'),
  gaugeScoreValue: document.getElementById('gaugeScoreValue'),
  gaugeScoreDesc: document.getElementById('gaugeScoreDesc'),
  threatTagsGrid: document.getElementById('threatTagsGrid'),
  aiExplanationText: document.getElementById('aiExplanationText'),
  aiRecommendationBox: document.getElementById('aiRecommendationBox'),
  aiRecommendationText: document.getElementById('aiRecommendationText'),
  urlsTableBody: document.getElementById('urlsTableBody'),
  resultEngineVer: document.getElementById('resultEngineVer'),
  btnCopyReport: document.getElementById('btnCopyReport'),
  btnExportJson: document.getElementById('btnExportJson'),
  btnNewScan: document.getElementById('btnNewScan'),

  // ChatGPT Assistant Elements
  chatgptAssistantCard: document.getElementById('chatgptAssistantCard'),
  chatgptMessagesStream: document.getElementById('chatgptMessagesStream'),
  aiMainVerdictBubble: document.getElementById('aiMainVerdictBubble'),
  aiTypingIndicator: document.getElementById('aiTypingIndicator'),
  aiStreamContent: document.getElementById('aiStreamContent'),
  chatSuggestions: document.getElementById('chatSuggestions'),
  chatgptInputForm: document.getElementById('chatgptInputForm'),
  chatgptUserInput: document.getElementById('chatgptUserInput'),
  btnSendChat: document.getElementById('btnSendChat'),

  // Metrics
  metricTotalScans: document.getElementById('metricTotalScans'),
  metricBlocked: document.getElementById('metricBlocked'),
  metricSuspicious: document.getElementById('metricSuspicious'),

  // History
  historyTableBody: document.getElementById('historyTableBody'),
  historySearch: document.getElementById('historySearch'),
  btnClearHistory: document.getElementById('btnClearHistory'),
  historyModal: document.getElementById('historyModal'),
  modalCloseBtn: document.getElementById('modalCloseBtn'),
  modalTitle: document.getElementById('modalTitle'),
  modalBody: document.getElementById('modalBody')
};

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  initFaultyTerminalBg();
  initFuzzyHero();
  initHistory();
  initTabs();
  initPresetListeners();
  initScreenshotUploader();
  initCharCounters();
  initActionButtons();
  initModal();
  updateMetricsRibbon();
});

// Mount FaultyTerminal Ambient WebGL Background from React Bits
function initFaultyTerminalBg() {
  const bgContainer = document.getElementById('faultyTerminalBg');
  if (!bgContainer) return;

  mountFaultyTerminal(bgContainer, {
    scale: 1.75,
    gridMul: [3, 2],
    digitSize: 1.0,
    timeScale: 0.22,
    pause: false,
    scanlineIntensity: 0.25,
    glitchAmount: 0.65,
    flickerAmount: 0.4,
    noiseAmp: 0.7,
    curvature: 0.08,
    tint: '#00f0ff', // Unified Cyber Cyan matching brand & UI icons
    mouseReact: true,
    mouseStrength: 0.25,
    pageLoadAnimation: true,
    brightness: 0.28 // Subtle high-tech ambient texture
  });
}

// Mount Holographic FuzzyText from React Bits
function initFuzzyHero() {
  const fuzzyContainer = document.getElementById('heroFuzzyContainer');
  if (!fuzzyContainer) return;

  mountFuzzyText(fuzzyContainer, {
    text: 'PHISHGUARD AI',
    fontSize: 'clamp(2.4rem, 6vw, 4.2rem)',
    fontWeight: 900,
    fontFamily: "'Inter', system-ui, sans-serif",
    color: '#00f0ff',
    enableHover: true,
    baseIntensity: 0.12,
    hoverIntensity: 0.45,
    fuzzRange: 18,
    fps: 60,
    direction: 'horizontal',
    transitionDuration: 6,
    clickEffect: true,
    glitchMode: true,
    glitchInterval: 3200,
    glitchDuration: 140,
    gradient: ['#ffffff', '#38bdf8', '#00f0ff'], // Cohesive White-to-Cyan cyber gradient
    letterSpacing: 4
  });
}

// Load History from localStorage or initial mock seeds
function initHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (saved) {
      state.history = JSON.parse(saved);
    } else {
      state.history = [...INITIAL_HISTORY];
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(state.history));
    }
  } catch (e) {
    state.history = [...INITIAL_HISTORY];
  }
  renderHistoryTable();
}

function saveHistory() {
  try {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(state.history));
  } catch (e) {
    console.error('Could not save history to localStorage', e);
  }
  renderHistoryTable();
  updateMetricsRibbon();
}

// Update Top Metrics Ribbon
function updateMetricsRibbon() {
  const total = 1420 + state.history.length;
  const blockedCount = 840 + state.history.filter(h => h.statusClass === 'phishing').length;
  const suspCount = 290 + state.history.filter(h => h.statusClass === 'suspicious').length;

  if (elements.metricTotalScans) elements.metricTotalScans.textContent = total.toLocaleString();
  if (elements.metricBlocked) elements.metricBlocked.textContent = blockedCount.toLocaleString();
  if (elements.metricSuspicious) elements.metricSuspicious.textContent = suspCount.toLocaleString();
}

// Tab Switching
function initTabs() {
  elements.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      switchTab(tabId);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;

  elements.tabBtns.forEach(btn => {
    const isActive = btn.getAttribute('data-tab') === tabId;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });

  if (elements.contentUrl) elements.contentUrl.classList.toggle('active', tabId === 'url');
  if (elements.contentEmail) elements.contentEmail.classList.toggle('active', tabId === 'email');
  if (elements.contentSms) elements.contentSms.classList.toggle('active', tabId === 'sms');
  if (elements.contentScreenshot) elements.contentScreenshot.classList.toggle('active', tabId === 'screenshot');
}

// Char Counters
function initCharCounters() {
  elements.emailBody.addEventListener('input', () => {
    elements.emailBodyCounter.textContent = `${elements.emailBody.value.length} chars`;
  });
  elements.smsBody.addEventListener('input', () => {
    elements.smsBodyCounter.textContent = `${elements.smsBody.value.length} chars`;
  });
}

// Screenshot Upload & Drag/Drop
function initScreenshotUploader() {
  const { dropzone, screenshotFileInput, btnRemoveImg } = elements;

  dropzone.addEventListener('click', () => screenshotFileInput.click());

  screenshotFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleImageFile(file);
  });

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleImageFile(e.dataTransfer.files[0]);
    }
  });

  btnRemoveImg.addEventListener('click', () => {
    clearScreenshot();
  });
}

function handleImageFile(file) {
  if (!file.type.startsWith('image/')) {
    alert('Please upload an image file (PNG, JPG, WebP).');
    return;
  }

  const reader = new FileReader();
  reader.onload = (event) => {
    displayImagePreview(event.target.result, file.name);
    state.uploadedFile = file;
    state.uploadedFileDataUrl = event.target.result;
  };
  reader.readAsDataURL(file);
}

function displayImagePreview(src, filename) {
  elements.imagePreview.src = src;
  elements.previewFilename.textContent = filename || 'screenshot.png';
  elements.imagePreviewCard.classList.add('active');
  elements.dropzone.style.display = 'none';
}

function clearScreenshot() {
  state.uploadedFile = null;
  state.uploadedFileDataUrl = null;
  elements.screenshotFileInput.value = '';
  elements.imagePreview.src = '';
  elements.imagePreviewCard.classList.remove('active');
  elements.dropzone.style.display = 'block';
}

// Preset Quick-Tests
function initPresetListeners() {
  if (!elements.presetsContainer) return;
  elements.presetsContainer.addEventListener('click', (e) => {
    const chip = e.target.closest('.preset-chip');
    if (!chip) return;

    const presetId = chip.getAttribute('data-preset');
    const preset = PRESETS.find(p => p.id === presetId);
    if (!preset) return;

    loadPreset(preset);
  });
}

function loadPreset(preset) {
  switchTab(preset.type);

  if (preset.type === 'email') {
    elements.emailSender.value = preset.data.sender || '';
    elements.emailSubject.value = preset.data.subject || '';
    elements.emailBody.value = preset.data.body || '';
    elements.emailBodyCounter.textContent = `${preset.data.body.length} chars`;
  } else if (preset.type === 'sms') {
    elements.smsSender.value = preset.data.sender || '';
    elements.smsBody.value = preset.data.body || '';
    elements.smsBodyCounter.textContent = `${preset.data.body.length} chars`;
  } else if (preset.type === 'screenshot') {
    displayImagePreview(preset.data.imagePreview, preset.data.filename);
    state.uploadedFileDataUrl = preset.data.imagePreview;
    state.uploadedFile = { name: preset.data.filename, mockOcr: preset.data.ocrText };
  }

  // Scroll workbench smoothly into view
  elements.btnAnalyze.scrollIntoView({ behavior: 'smooth', block: 'center' });
  
  // Subtle flash animation on Analyze button to invite test
  elements.btnAnalyze.style.animation = 'pulse-glow 0.8s ease 2';
  setTimeout(() => { elements.btnAnalyze.style.animation = ''; }, 1600);
}

// Action Buttons
function initActionButtons() {
  // Clear
  elements.btnClearInputs.addEventListener('click', () => {
    if (elements.urlInput) elements.urlInput.value = '';

    elements.emailSender.value = '';
    elements.emailSubject.value = '';
    elements.emailBody.value = '';
    elements.emailBodyCounter.textContent = '0 chars';

    elements.smsSender.value = '';
    elements.smsBody.value = '';
    elements.smsBodyCounter.textContent = '0 chars';

    clearScreenshot();
  });

  // Analyze Button
  elements.btnAnalyze.addEventListener('click', triggerAnalysis);

  // New Scan
  elements.btnNewScan.addEventListener('click', () => {
    window.scrollTo({ top: 120, behavior: 'smooth' });
    if (state.activeTab === 'url' && elements.urlInput) elements.urlInput.focus();
    else if (state.activeTab === 'email') elements.emailBody.focus();
    else if (state.activeTab === 'sms') elements.smsBody.focus();
  });

  // Export JSON
  elements.btnExportJson.addEventListener('click', () => {
    if (!state.currentAnalysis) return;
    const blob = new Blob([JSON.stringify(state.currentAnalysis, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_${state.currentAnalysis.id.toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Copy Report
  elements.btnCopyReport.addEventListener('click', () => {
    if (!state.currentAnalysis) return;
    const reportText = `[PhishGuard AI Threat Report]
Scan ID: ${state.currentAnalysis.id}
Risk Score: ${state.currentAnalysis.score}/100 (${state.currentAnalysis.status})
Target: ${state.currentAnalysis.target}
Threats: ${state.currentAnalysis.threats.map(t => t.name).join(', ')}
AI Breakdown: ${state.currentAnalysis.aiExplanation}
Recommendations: ${state.currentAnalysis.recommendations}`;

    navigator.clipboard.writeText(reportText).then(() => {
      const originalText = elements.btnCopyReport.innerHTML;
      elements.btnCopyReport.innerHTML = `✓ Copied!`;
      setTimeout(() => { elements.btnCopyReport.innerHTML = originalText; }, 2000);
    });
  });

  // History Search
  if (elements.historySearch) {
    elements.historySearch.addEventListener('input', (e) => {
      renderHistoryTable(e.target.value);
    });
  }

  // Clear History
  if (elements.btnClearHistory) {
    elements.btnClearHistory.addEventListener('click', () => {
      if (confirm('Clear all local scan history?')) {
        state.history = [];
        saveHistory();
      }
    });
  }

  // ChatGPT Interactive Follow-up Chat
  if (elements.chatgptInputForm) {
    elements.chatgptInputForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const question = elements.chatgptUserInput.value.trim();
      if (!question) return;
      elements.chatgptUserInput.value = '';
      await handleChatFollowUp(question);
    });
  }

  if (elements.chatSuggestions) {
    elements.chatSuggestions.addEventListener('click', async (e) => {
      const chip = e.target.closest('.chat-chip');
      if (!chip) return;
      const question = chip.getAttribute('data-question');
      if (question) {
        await handleChatFollowUp(question);
      }
    });
  }

  // Quick Demo Links Click Handler
  const demoLinksRow = document.getElementById('demoLinksRow');
  if (demoLinksRow) {
    demoLinksRow.addEventListener('click', (e) => {
      const chip = e.target.closest('.demo-link-chip');
      if (!chip) return;
      const url = chip.getAttribute('data-url');
      if (url && elements.urlInput) {
        elements.urlInput.value = url;
        elements.urlInput.focus();
        // Trigger quick pulse effect on analyze button
        elements.btnAnalyze.style.animation = 'pulse-glow 0.8s ease 2';
        setTimeout(() => { elements.btnAnalyze.style.animation = ''; }, 1600);
      }
    });
  }
}

// Trigger Threat Analysis with Interactive HUD Telemetry
async function triggerAnalysis() {
  let payload = { type: state.activeTab };

  if (state.activeTab === 'url') {
    const rawUrl = elements.urlInput ? elements.urlInput.value.trim() : '';
    if (!rawUrl) {
      alert('Please paste a link or URL to analyze.');
      if (elements.urlInput) elements.urlInput.focus();
      return;
    }
    payload.url = rawUrl;
    payload.target = rawUrl;
    payload.text = rawUrl;
  } else if (state.activeTab === 'email') {
    payload.sender = elements.emailSender.value.trim();
    payload.subject = elements.emailSubject.value.trim();
    payload.text = elements.emailBody.value.trim();

    if (!payload.sender && !payload.subject && !payload.text) {
      alert('Please enter an email address, subject, or message content to analyze.');
      elements.emailBody.focus();
      return;
    }
  } else if (state.activeTab === 'sms') {
    payload.sender = elements.smsSender.value.trim();
    payload.text = elements.smsBody.value.trim();

    if (!payload.sender && !payload.text) {
      alert('Please enter an SMS sender number or message text to analyze.');
      elements.smsBody.focus();
      return;
    }
  } else if (state.activeTab === 'screenshot') {
    if (!state.uploadedFileDataUrl) {
      alert('Please upload a screenshot or select the "Fake Login Screenshot" demo preset.');
      return;
    }
    payload.filename = (state.uploadedFile && state.uploadedFile.name) || 'screenshot.png';
    payload.imageBase64 = state.uploadedFileDataUrl;
    payload.text = (state.uploadedFile && state.uploadedFile.mockOcr) ||
      'Suspicious login portal or email screenshot for visual phishing inspection';
  }

  // Visual Scanning State
  elements.btnAnalyze.disabled = true;
  elements.scanningHud.classList.add('active');
  elements.hudProgressBar.style.width = '12%';
  elements.hudPercent.textContent = '12% (Initializing...)';
  elements.hudTelemetryLog.innerHTML = '';

  if (state.activeTab === 'screenshot') {
    elements.imagePreviewWrapper.classList.add('scanning');
  }

  function appendLog(msg, isFinished = false) {
    const logLine = document.createElement('div');
    logLine.className = 'hud-log-line';
    logLine.innerHTML = `<span class="timestamp">[${new Date().toLocaleTimeString()}]</span> <span class="${isFinished ? 'status-ok' : 'status-warn'}">${isFinished ? '✓' : '⟳'}</span> <span>${msg}</span>`;
    elements.hudTelemetryLog.appendChild(logLine);
    elements.hudTelemetryLog.scrollTop = elements.hudTelemetryLog.scrollHeight;
  }

  appendLog('Initializing multi-modal inspection pipeline...');

  // Start real threat analysis asynchronously
  const analysisPromise = analyzeThreatContent(payload);

  // Smoothly advance progress up to exactly 90% and hold there!
  let progress = 15;
  const stages = [
    { target: 40, msg: 'Extracting destination hyperlinks & unshortening redirects...' },
    { target: 68, msg: 'Querying live VirusTotal domain reputation intelligence...' },
    { target: 90, msg: 'Synthesizing contextual threat vectors with Gemini 3.5 Flash...' }
  ];

  let currentStage = 0;
  let isRequestDone = false;

  const progressInterval = setInterval(() => {
    if (isRequestDone) return;
    if (currentStage < stages.length) {
      const stage = stages[currentStage];
      if (progress < stage.target) {
        progress += 4;
        elements.hudProgressBar.style.width = `${progress}%`;
        elements.hudPercent.textContent = `${progress}% (Analyzing...)`;
      } else {
        appendLog(stage.msg);
        currentStage++;
      }
    } else {
      // Hold firmly at 90% while waiting for API!
      progress = 90;
      elements.hudProgressBar.style.width = '90%';
      elements.hudPercent.textContent = '90% (Finalizing AI analysis...)';
    }
  }, 120);

  // Await the real API response
  let result;
  try {
    result = await analysisPromise;
  } catch (err) {
    console.error('Analysis failed:', err);
  } finally {
    isRequestDone = true;
    clearInterval(progressInterval);
  }

  // The instant response is ready: hit 100% and reveal result immediately!
  elements.hudProgressBar.style.width = '100%';
  elements.hudPercent.textContent = '100% Complete';
  appendLog('Threat inspection complete. Verdict generated.', true);

  state.currentAnalysis = result;

  // Add to History
  state.history.unshift({
    id: result.id,
    timestamp: result.timestamp,
    type: result.type,
    target: result.target,
    snippet: result.snippet,
    score: result.score,
    status: result.status,
    statusClass: result.statusClass,
    threats: result.threats.map(t => t.name),
    urlsFound: result.urls.map(u => u.url),
    aiExplanation: result.aiExplanation,
    recommendations: result.recommendations
  });

  saveHistory();

  // Reset UI scanning flags
  elements.imagePreviewWrapper.classList.remove('scanning');
  elements.btnAnalyze.disabled = false;

  // Render & Show Results
  renderAnalysisResult(result);
}

// Render Results Section
function renderAnalysisResult(res) {
  elements.resultSection.classList.add('active');

  // Status Banner styling
  elements.resultBanner.className = `result-banner status-${res.statusClass}`;
  elements.resultStatusBadge.className = `status-badge ${res.statusClass}`;
  elements.resultStatusText.textContent = res.status;
  elements.resultTargetName.textContent = res.target;
  elements.resultMetaTime.textContent = `${res.id} • ${res.timestamp}`;

  // Animate Gauge & Score Number
  animateGauge(res.score, res.statusClass);

  // Score Description
  if (res.statusClass === 'phishing') {
    elements.gaugeScoreDesc.textContent = 'High Confidence Social Engineering / Phish';
    elements.gaugeScoreDesc.style.color = 'var(--threat-danger)';
  } else if (res.statusClass === 'suspicious') {
    elements.gaugeScoreDesc.textContent = 'Medium Risk / Unverified Origin Markers';
    elements.gaugeScoreDesc.style.color = 'var(--threat-warning)';
  } else {
    elements.gaugeScoreDesc.textContent = 'Safe / Genuine Infrastructure Indicators';
    elements.gaugeScoreDesc.style.color = 'var(--threat-safe)';
  }

  // Threat Tags
  elements.threatTagsGrid.innerHTML = '';
  if (res.threats.length === 0) {
    elements.threatTagsGrid.innerHTML = `<span class="threat-tag clean">No Malicious Vectors Identified</span>`;
  } else {
    res.threats.forEach(t => {
      const span = document.createElement('span');
      span.className = `threat-tag ${t.level || 'warning'}`;
      span.textContent = t.name;
      elements.threatTagsGrid.appendChild(span);
    });
  }

  // Render ChatGPT Style Interactive Copilot Verdict
  renderChatGptVerdict(res);

  // URLs Table
  elements.urlsTableBody.innerHTML = '';
  if (res.urls.length === 0) {
    elements.urlsTableBody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1.25rem;">
          No hyperlinks or external endpoints extracted in this payload.
        </td>
      </tr>`;
  } else {
    res.urls.forEach(u => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><span class="url-text" title="${u.url}">${u.url}</span></td>
        <td><code>${u.domain}</code></td>
        <td><span class="url-badge ${u.threat}">${u.label}</span></td>
        <td><span style="font-family: var(--font-mono); font-size: 0.75rem;">${u.vtEngines}</span></td>
        <td><span class="url-badge ${u.threat === 'malicious' ? 'malicious' : (u.threat === 'suspicious' ? 'suspicious' : 'clean')}">${u.gsbStatus}</span></td>
      `;
      elements.urlsTableBody.appendChild(row);
    });
  }
}

// Render ChatGPT-style verdict with clear conversational breakdown
function renderChatGptVerdict(res) {
  if (!elements.aiStreamContent) return;

  const isPhish = res.statusClass === 'phishing';
  const isSusp = res.statusClass === 'suspicious';
  
  const headline = isPhish
    ? '🚨 CRITICAL WARNING: High-Risk Phishing Attempt Detected'
    : (isSusp ? '⚠️ CAUTION: Suspicious Communication Detected' : '✅ VERIFIED: Communication Appears Safe');

  const headlineColor = isPhish ? 'var(--threat-danger)' : (isSusp ? 'var(--threat-warning)' : 'var(--threat-safe)');

  // Clear any previous chat messages and reset to initial verdict
  if (elements.chatgptMessagesStream) {
    elements.chatgptMessagesStream.innerHTML = `
      <div class="chat-bubble ai-bubble" id="aiMainVerdictBubble">
        <h4 style="color: ${headlineColor}; display: flex; align-items: center; gap: 0.5rem; font-size: 1.08rem; margin-bottom: 0.75rem;">
          ${headline} <span style="font-size: 0.8rem; font-family: var(--font-mono); opacity: 0.85;">(${res.score}/100 Risk)</span>
        </h4>
        <div style="font-size: 0.93rem; line-height: 1.65; color: #e2e8f0;">
          <p style="margin-bottom: 0.75rem;">
            <strong>AI Threat Summary:</strong> ${escapeHtml(res.aiExplanation)}
          </p>
          ${res.threats.length ? `
            <div style="margin-bottom: 0.75rem;">
              <strong style="color: #ffffff;">🔍 Deceptive Signals Unmasked:</strong>
              <ul style="margin-top: 0.35rem;">
                ${res.threats.map(t => `<li><strong>${escapeHtml(t.name)}</strong>: High probability social engineering pattern.</li>`).join('')}
              </ul>
            </div>
          ` : ''}
          <div style="background: rgba(0, 240, 255, 0.08); border-left: 3px solid ${headlineColor}; padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.9rem; margin-top: 0.5rem;">
            <strong style="color: #ffffff;">🛡️ What You Should Do:</strong>
            <p style="margin-top: 0.25rem; color: #e2e8f0;">${escapeHtml(res.recommendations)}</p>
          </div>
        </div>
      </div>
    `;
  }

  // Immediately scroll to the ChatGPT Assistant card
  requestAnimationFrame(() => {
    if (elements.chatgptAssistantCard) {
      elements.chatgptAssistantCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (elements.resultSection) {
      elements.resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
}

// Handle Interactive ChatGPT Follow-up Q&A
async function handleChatFollowUp(question) {
  if (!elements.chatgptMessagesStream) return;

  // Append user bubble
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble user-bubble';
  userBubble.textContent = question;
  elements.chatgptMessagesStream.appendChild(userBubble);

  // Append loading AI bubble
  const aiBubble = document.createElement('div');
  aiBubble.className = 'chat-bubble ai-bubble';
  aiBubble.innerHTML = `
    <div style="display: flex; align-items: center; gap: 0.6rem;">
      <div class="typing-indicator"><span></span><span></span><span></span></div>
      <span style="font-size: 0.82rem; color: var(--accent-cyan); font-family: var(--font-mono);">PhishGuard AI Thinking...</span>
    </div>
  `;
  elements.chatgptMessagesStream.appendChild(aiBubble);
  elements.chatgptMessagesStream.scrollTop = elements.chatgptMessagesStream.scrollHeight;

  // Call Gemini Follow-up
  const answer = await askGeminiFollowUp({
    question,
    context: state.currentAnalysis || {}
  });

  // Render formatted markdown answer
  aiBubble.innerHTML = formatMarkdownToHtml(answer);
  elements.chatgptMessagesStream.scrollTop = elements.chatgptMessagesStream.scrollHeight;
}

function formatMarkdownToHtml(md) {
  if (!md) return '';
  return md
    .replace(/### (.*?)\n/g, '<h4 style="color:#ffffff;margin-top:0.5rem;margin-bottom:0.35rem;font-size:0.98rem;">$1</h4>')
    .replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--accent-cyan);">$1</strong>')
    .replace(/^- (.*?)$/gm, '<li style="margin-left:1.2rem; margin-bottom: 0.3rem;">$1</li>')
    .replace(/\n\n/g, '<br>');
}

// Animate Circular SVG Gauge
function animateGauge(targetScore, statusClass) {
  const circumference = 2 * Math.PI * 65; // ~408.4
  const offset = circumference - (targetScore / 100) * circumference;

  let strokeColor = 'var(--accent-cyan)';
  if (statusClass === 'phishing') strokeColor = 'var(--threat-danger)';
  else if (statusClass === 'suspicious') strokeColor = 'var(--threat-warning)';
  else strokeColor = 'var(--threat-safe)';

  elements.gaugeProgressCircle.style.strokeDasharray = circumference;
  elements.gaugeProgressCircle.style.strokeDashoffset = circumference;
  elements.gaugeProgressCircle.style.stroke = strokeColor;

  // Trigger browser paint then animate stroke
  requestAnimationFrame(() => {
    elements.gaugeProgressCircle.style.strokeDashoffset = offset;
  });

  // Counter number roll
  let currentVal = 0;
  const stepTime = 1000 / Math.max(targetScore, 1);
  const timer = setInterval(() => {
    if (currentVal >= targetScore) {
      elements.gaugeScoreValue.textContent = targetScore;
      clearInterval(timer);
    } else {
      currentVal++;
      elements.gaugeScoreValue.textContent = currentVal;
    }
  }, stepTime);
}

// Render History Table
function renderHistoryTable(filterText = '') {
  const tbody = elements.historyTableBody;
  if (!tbody) return;
  tbody.innerHTML = '';

  const query = filterText.toLowerCase().trim();
  const filtered = state.history.filter(item => {
    if (!query) return true;
    return (
      (item.target && item.target.toLowerCase().includes(query)) ||
      (item.type && item.type.toLowerCase().includes(query)) ||
      (item.status && item.status.toLowerCase().includes(query)) ||
      (item.snippet && item.snippet.toLowerCase().includes(query))
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-history-state">
          No matching threat scan logs found.
        </td>
      </tr>`;
    return;
  }

  filtered.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div style="font-weight: 600; font-family: var(--font-mono);">${item.id}</div>
        <div style="font-size: 0.72rem; color: var(--text-muted);">${item.timestamp}</div>
      </td>
      <td>
        <span class="type-badge">${item.type}</span>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-primary);">
        ${escapeHtml(item.target)}
      </td>
      <td class="snippet-cell" title="${escapeHtml(item.snippet)}">
        ${escapeHtml(item.snippet)}
      </td>
      <td class="history-score-cell" style="color: ${item.score >= 70 ? 'var(--threat-danger)' : (item.score >= 35 ? 'var(--threat-warning)' : 'var(--threat-safe)')};">
        ${item.score}/100
      </td>
      <td>
        <span class="status-badge ${item.statusClass || 'safe'}" style="font-size: 0.7rem; padding: 0.2rem 0.5rem;">
          ${item.status}
        </span>
      </td>
      <td>
        <button type="button" class="btn-inspect" data-scan-id="${item.id}">
          Inspect
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Bind inspect buttons
  tbody.querySelectorAll('.btn-inspect').forEach(btn => {
    btn.addEventListener('click', () => {
      const scanId = btn.getAttribute('data-scan-id');
      openHistoryModal(scanId);
    });
  });
}

// Modal handling
function initModal() {
  elements.modalCloseBtn.addEventListener('click', () => {
    elements.historyModal.classList.remove('active');
  });

  elements.historyModal.addEventListener('click', (e) => {
    if (e.target === elements.historyModal) {
      elements.historyModal.classList.remove('active');
    }
  });
}

function openHistoryModal(scanId) {
  const item = state.history.find(h => h.id === scanId);
  if (!item) return;

  elements.modalTitle.textContent = `Threat Inspection: ${item.id}`;
  elements.modalBody.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.5rem;">
      <span><strong>Channel:</strong> ${item.type}</span>
      <span class="status-badge ${item.statusClass || 'safe'}" style="font-size: 0.75rem; padding: 0.25rem 0.6rem;">${item.status} (${item.score}/100)</span>
    </div>
    <div><strong>Target / Origin:</strong> <code style="color: var(--accent-cyan);">${escapeHtml(item.target)}</code></div>
    <div><strong>Timestamp:</strong> ${item.timestamp}</div>
    <div>
      <strong>Identified Threat Vectors:</strong>
      <div style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.4rem;">
        ${(item.threats || []).map(t => `<span class="threat-tag critical" style="font-size: 0.75rem;">${escapeHtml(t)}</span>`).join('') || '<span style="color:var(--text-muted)">None</span>'}
      </div>
    </div>
    <div style="background: var(--bg-input); padding: 0.75rem; border-radius: 6px; border: 1px solid var(--border-subtle);">
      <strong style="color: var(--accent-cyan);">AI Analysis Breakdown:</strong>
      <p style="margin-top: 0.25rem; line-height: 1.5;">${escapeHtml(item.aiExplanation || 'No detailed log available.')}</p>
    </div>
    ${item.urlsFound && item.urlsFound.length ? `
      <div>
        <strong>Discovered Destination URLs:</strong>
        <ul style="margin-left: 1.25rem; margin-top: 0.25rem; font-family: var(--font-mono); font-size: 0.78rem;">
          ${item.urlsFound.map(u => `<li>${escapeHtml(u)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}
    <div style="margin-top: 0.5rem;">
      <button type="button" class="btn-analyze" id="btnReloadIntoWorkbench" style="font-size: 0.8rem; padding: 0.5rem 1rem; width: 100%; justify-content: center;">
        Load into Workbench & Re-Scan
      </button>
    </div>
  `;

  document.getElementById('btnReloadIntoWorkbench').addEventListener('click', () => {
    elements.historyModal.classList.remove('active');
    if (item.type === 'EMAIL') {
      switchTab('email');
      elements.emailSender.value = item.target;
      elements.emailBody.value = item.snippet;
    } else if (item.type === 'SMS') {
      switchTab('sms');
      elements.smsSender.value = item.target;
      elements.smsBody.value = item.snippet;
    }
    triggerAnalysis();
  });

  elements.historyModal.classList.add('active');
}

// Utility: HTML Escape
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
