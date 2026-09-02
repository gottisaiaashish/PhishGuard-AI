import { PRESETS, INITIAL_HISTORY, SAMPLE_SCREENSHOT_SVG } from './data/mockData.js';
import { analyzeThreatContent } from './services/analyzer.js';
import { mountFuzzyText } from './components/FuzzyText.js';
import { mountFaultyTerminal } from './components/FaultyTerminal.js';

// Application State
const state = {
  activeTab: 'email', // 'email' | 'sms' | 'screenshot'
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
  contentEmail: document.getElementById('contentEmail'),
  contentSms: document.getElementById('contentSms'),
  contentScreenshot: document.getElementById('contentScreenshot'),

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

  elements.contentEmail.classList.toggle('active', tabId === 'email');
  elements.contentSms.classList.toggle('active', tabId === 'sms');
  elements.contentScreenshot.classList.toggle('active', tabId === 'screenshot');
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
    if (state.activeTab === 'email') elements.emailBody.focus();
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
  elements.historySearch.addEventListener('input', (e) => {
    renderHistoryTable(e.target.value);
  });

  // Clear History
  elements.btnClearHistory.addEventListener('click', () => {
    if (confirm('Clear all local scan history?')) {
      state.history = [];
      saveHistory();
    }
  });
}

// Trigger Threat Analysis with Interactive HUD Telemetry
async function triggerAnalysis() {
  let payload = { type: state.activeTab };

  if (state.activeTab === 'email') {
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
  elements.hudProgressBar.style.width = '0%';
  elements.hudPercent.textContent = '0%';
  elements.hudTelemetryLog.innerHTML = '';

  if (state.activeTab === 'screenshot') {
    elements.imagePreviewWrapper.classList.add('scanning');
  }

  // Telemetry stages simulation
  const telemetrySteps = [
    { pct: 20, log: 'Initializing NLP heuristic pipelines & tokenizer...' },
    { pct: 45, log: 'Parsing lexical structure, RFC headers & psychological urgency tokens...' },
    { pct: 70, log: 'Extracting destination hyperlinks & querying domain reputation...' },
    { pct: 90, log: 'Synthesizing threat vector matrix & generating explainable breakdown...' },
    { pct: 100, log: 'Analysis complete. Compiling threat score & intelligence report.' }
  ];

  for (let i = 0; i < telemetrySteps.length; i++) {
    const step = telemetrySteps[i];
    await new Promise(r => setTimeout(r, 220));
    elements.hudProgressBar.style.width = `${step.pct}%`;
    elements.hudPercent.textContent = `${step.pct}%`;

    const logLine = document.createElement('div');
    logLine.className = 'hud-log-line';
    logLine.innerHTML = `<span class="timestamp">[${new Date().toLocaleTimeString()}]</span> <span class="${step.pct === 100 ? 'status-ok' : 'status-warn'}">✓</span> <span>${step.log}</span>`;
    elements.hudTelemetryLog.appendChild(logLine);
    elements.hudTelemetryLog.scrollTop = elements.hudTelemetryLog.scrollHeight;
  }

  // Execute Analysis
  const result = await analyzeThreatContent(payload);
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
    elements.threatTagsGrid.innerHTML = `<span class="threat-tag clean">✓ No Malicious Vectors Identified</span>`;
  } else {
    res.threats.forEach(t => {
      const span = document.createElement('span');
      span.className = `threat-tag ${t.level || 'warning'}`;
      span.innerHTML = `<span>${t.level === 'critical' ? '⚠️' : 'ℹ️'}</span> ${t.name}`;
      elements.threatTagsGrid.appendChild(span);
    });
  }

  // AI Explanation & Recommendation
  elements.aiExplanationText.textContent = res.aiExplanation;
  elements.aiRecommendationText.textContent = res.recommendations;

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

  // Smoothly scroll to results
  elements.resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
