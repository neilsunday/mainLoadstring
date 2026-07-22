async function handleOAuthCallback() {
  const hasHash =
    window.location.hash.includes("access_token") ||
    window.location.hash.includes("error");
  const hasCode = window.location.search.includes("code=");
  if (!hasHash && !hasCode) return;
  await new Promise((resolve) => {
    let done = false;
    const { data: { subscription } } = sb.auth.onAuthStateChange((event, session) => {
      if (session && !done) {
        done = true;
        subscription.unsubscribe();
        history.replaceState(null, "", window.location.pathname);
        resolve();
      }
    });
    setTimeout(() => {
      if (!done) { done = true; subscription.unsubscribe(); resolve(); }
    }, 10000);
  });
}

const MAX_SCRIPT_SIZE = 10 * 1024 * 1024;
const OBFUSCATE_ENDPOINT = "/obfuscate";

const userEmailEl = document.getElementById("userEmail");
const logoutBtn = document.getElementById("logoutBtn");
const scriptNameInput = document.getElementById("scriptName");
const scriptCodeInput = document.getElementById("scriptCode");
const charCountEl = document.getElementById("charCount");
const uploadBtn = document.getElementById("uploadBtn");
const fileUpload = document.getElementById("fileUpload");
const fileNameEl = document.getElementById("fileName");

// v24 NEW: Reference script upload
const referenceUpload = document.getElementById("referenceUpload");
const referenceUploadBtn = document.getElementById("referenceUploadBtn");
const referenceClearBtn = document.getElementById("referenceClearBtn");
const referenceFileNameEl = document.getElementById("referenceFileName");
let referenceCode = "";  // in-memory only ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â not persisted
let referenceFileName = "";
const clearBtn = document.getElementById("clearBtn");
const saveBtn = document.getElementById("saveBtn");
const previewBtn = document.getElementById("previewBtn");
const messageDiv = document.getElementById("message");
const obfuscationLevelSelect = document.getElementById("obfuscationLevel");
const requireKeyCheckbox = document.getElementById("requireKey");

// v16 NEW: force maximum + advanced options
const forceMaximumCheckbox = document.getElementById("forceMaximum");
const advOptionsToggle = document.getElementById("advOptionsToggle");
const advOptionsBody = document.getElementById("advOptionsBody");

// v16 NEW: modal
const forceMaxModal = document.getElementById("forceMaxModal");
const forceMaxConfirmCheck = document.getElementById("forceMaxConfirmCheck");
const forceMaxProceedBtn = document.getElementById("forceMaxProceedBtn");
const forceMaxCancelBtn = document.getElementById("forceMaxCancelBtn");

// v16 NEW: report card
const reportCard = document.getElementById("reportCard");
const closeReportBtn = document.getElementById("closeReportBtn");
const abCompareBtn = document.getElementById("abCompareBtn");
const abCompareResult = document.getElementById("abCompareResult");
const viewCodeToggle = document.getElementById("viewCodeToggle");
const viewCodeBody = document.getElementById("viewCodeBody");
const reportCodeOutput = document.getElementById("reportCodeOutput");
const viewCodeChars = document.getElementById("viewCodeChars");
const copyReportCodeBtn = document.getElementById("copyReportCodeBtn");

// v25 NEW: Live obfuscation modal
const liveModal = document.getElementById("liveModal");
const liveStagesEl = document.getElementById("liveStages");
const liveStatusEl = document.getElementById("liveStatus");
const liveSubtitleEl = document.getElementById("liveSubtitle");
const liveProgressFill = document.getElementById("liveProgressFill");
const liveCancelBtn = document.getElementById("liveCancelBtn");
const liveCloseBtn = document.getElementById("liveCloseBtn");
let _liveState = null; // { sessionId, eventSource, stages, resolve, reject, aborted }

const previewCard = document.getElementById("previewCard");
const previewStats = document.getElementById("previewStats");
const previewOutput = document.getElementById("previewOutput");
const closePreviewBtn = document.getElementById("closePreviewBtn");
const copyPreviewBtn = document.getElementById("copyPreviewBtn");

const resultCard = document.getElementById("resultCard");
const loadstringOutput = document.getElementById("loadstringOutput");
const copyBtn = document.getElementById("copyBtn");

// Key management
const keysCard = document.getElementById("keysCard");
const keysList = document.getElementById("keysList");
const generateKeyBtn = document.getElementById("generateKeyBtn");
const keyScriptSelect = document.getElementById("keyScriptSelect");
const keyPlaceIdsInput = document.getElementById("keyPlaceIds");
const keyMaxExecInput = document.getElementById("keyMaxExec");
const keyExpiresInput = document.getElementById("keyExpires");

// v25 FIX: Bulletproof safe-DOM helpers. Every DOM interaction routes through
// these to no-op silently when an element is missing, preventing the
// "Cannot read properties of null (reading 'classList')" family of crashes.
function _cls(el, action, ...classes) {
  if (!el || !el.classList) return;
  try { el.classList[action](...classes); } catch (_) {}
}
function _clsAdd(el, ...cs) { _cls(el, "add", ...cs); }
function _clsRemove(el, ...cs) { _cls(el, "remove", ...cs); }
function _clsToggle(el, cls, force) {
  if (!el || !el.classList) return;
  try {
    if (typeof force === "boolean") _clsToggle(el, cls, force);
    else _clsToggle(el, cls);
  } catch (_) {}
}
function _setText(id, value) {
  const el = typeof id === "string" ? document.getElementById(id) : id;
  if (el) el.textContent = value;
}
function _setHtml(el, value) {
  if (el) el.innerHTML = value;
}
function _scroll(el, opts) {
  if (el && el.scrollIntoView) try { el.scrollIntoView(opts); } catch (_) {}
}
function _click(el, handler) {
  if (el && el.addEventListener) el.addEventListener("click", handler);
}
function _focus(el) { if (el && el.focus) try { el.focus(); } catch (_) {} }

let currentUser = null;
let lastPreviewedCode = "";
let lastReport = null;         // v16: cached most recent report
let lastRequestedLevel = null; // v16: for A/B compare
let lastSavedScriptId = null;

(async function init() {
  await handleOAuthCallback();
  const user = await requireAuth();
  if (!user) return;
  currentUser = user;
  if (userEmailEl) userEmailEl.textContent = user.email;
  await loadUserKeys();
})();

logoutBtn?.addEventListener("click", async () => {
  if (logoutBtn) logoutBtn.disabled = true;
  if (logoutBtn) logoutBtn.textContent = "Logging out...";
  try { await sb.auth.signOut(); } catch (err) {}
  finally { window.location.href = "index.html"; }
});

function updateUI() {
  const len = scriptCodeInput.value.length;
  if (charCountEl) charCountEl.textContent = `${len.toLocaleString()} characters`;
  const hasCode = len > 0;
  if (saveBtn) saveBtn.disabled = !hasCode;
  if (previewBtn) previewBtn.disabled = !hasCode;
}

scriptCodeInput.addEventListener("input", updateUI);
uploadBtn.addEventListener("click", () => fileUpload.click());

// v24 NEW: Reference upload handlers
referenceUploadBtn?.addEventListener("click", () => referenceUpload.click());

referenceUpload?.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > MAX_SCRIPT_SIZE) {
    showMessage("Reference file too large. Max 10MB.", "error");
    return;
  }
  const allowedTypes = [".lua", ".txt"];
  const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
  if (!allowedTypes.includes(ext)) {
    showMessage("Only .lua or .txt reference files allowed.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = (event) => {
    referenceCode = event.target.result;
    referenceFileName = file.name;
    if (referenceFileNameEl) referenceFileNameEl.textContent = "Reference: " + file.name + " (" +
      referenceCode.length.toLocaleString() + " chars)";
    _clsRemove(referenceClearBtn, "hidden");
    showMessage("Reference file loaded. It will be used for the next obfuscation.", "success");
  };
  reader.onerror = () => showMessage("Failed to read reference file.", "error");
  reader.readAsText(file);
});

referenceClearBtn?.addEventListener("click", () => {
  referenceCode = "";
  referenceFileName = "";
  referenceUpload.value = "";
  if (referenceFileNameEl) referenceFileNameEl.textContent = "";
  _clsAdd(referenceClearBtn, "hidden");
  showMessage("Reference cleared.", "info");
});

fileUpload.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > MAX_SCRIPT_SIZE) { showMessage("File too large. Max 10MB.", "error"); return; }
  const allowedTypes = [".lua", ".txt"];
  const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
  if (!allowedTypes.includes(ext)) { showMessage("Only .lua or .txt files allowed.", "error"); return; }
  const reader = new FileReader();
  reader.onload = (event) => {
    scriptCodeInput.value = event.target.result;
    if (fileNameEl) fileNameEl.textContent = `Loaded: ${file.name}`;
    if (!scriptNameInput.value.trim()) {
      const nameWithoutExt = file.name.replace(/\.(lua|txt)$/i, "");
      scriptNameInput.value = nameWithoutExt;
    }
    updateUI();
    showMessage(`Loaded "${file.name}"`, "success");
  };
  reader.onerror = () => showMessage("Failed to read file.", "error");
  reader.readAsText(file);
});

clearBtn.addEventListener("click", () => {
  if (!scriptCodeInput.value && !scriptNameInput.value) return;
  if (confirm("Clear the script editor?")) {
    scriptNameInput.value = "";
    scriptCodeInput.value = "";
    if (fileNameEl) fileNameEl.textContent = "";
    fileUpload.value = "";
    hideMessage();
    _clsAdd(resultCard, "hidden");
    _clsAdd(previewCard, "hidden");
    _clsAdd(reportCard, "hidden");
    updateUI();
  }
});

function generateId(length = 8) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id = "";
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) id += chars[array[i] % chars.length];
  return id;
}

function generateLicenseKey() {
  const chunks = [];
  for (let i = 0; i < 4; i++) {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    chunks.push(
      Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
    );
  }
  return "KEY-" + chunks.join("-");
}

function buildLoadstring(scriptId) {
  const rawUrl = `${window.location.origin}/s/${scriptId}`;
  return `loadstring(game:HttpGet("${rawUrl}"))()`;
}

function buildProtectedLoadstring(scriptId, key) {
  const baseUrl = `${window.location.origin}/s/${scriptId}`;
  return `local _k="${key}"\nlocal _h=game:GetService("RbxAnalyticsService"):GetClientId()\nlocal _p=tostring(game.PlaceId)\nloadstring(game:HttpGet("${baseUrl}?key=".._k.."&hwid=".._h.."&place=".._p))()`;
}

// ============================================================================
// v16: OBFUSCATION WITH REPORT
// ============================================================================
// v25: dispatcher -- live streaming for medium/maximum, one-shot for others.
async function obfuscateCodeAny(code, level, options) {
  options = options || {};
  if (level === "medium" || level === "maximum") {
    try {
      return await obfuscateCodeLive(code, level, options);
    } catch (e) {
      console.warn("Live obfuscation failed, falling back to one-shot:", e.message);
      closeLiveModal();
      return await obfuscateCode(code, level, options);
    }
  }
  return await obfuscateCode(code, level, options);
}

async function obfuscateCode(code, level, options) {
  options = options || {};
  if (level === "none") {
    return {
      code, elapsed: 0, originalSize: code.length, obfuscatedSize: code.length,
      report: null
    };
  }
  const response = await fetch(OBFUSCATE_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code, level,
      forceMaximum: !!options.forceMaximum,
      userId: currentUser ? currentUser.id : null,
      // v24 NEW: pass the uploaded reference script as an extra manifest source
      referenceCode: referenceCode || null,
    }),
  });
  if (!response.ok) {
    let errMsg = "Obfuscation failed";
    try { const errData = await response.json(); errMsg = errData.error || errMsg; } catch (e) {}
    throw new Error(errMsg);
  }
  const data = await response.json();
  if (!data.success || !data.code) throw new Error(data.error || "Obfuscation returned no code");
  return {
    code: data.code,
    elapsed: data.elapsed_ms,
    originalSize: data.original_size,
    obfuscatedSize: data.obfuscated_size,
    report: data.report || null,
  };
}

// ============================================================================
// v16: FORCE MAXIMUM CONFIRM MODAL
// ============================================================================
function openForceMaxModal() {
  return new Promise((resolve) => {
    forceMaxConfirmCheck.checked = false;
    if (forceMaxProceedBtn) forceMaxProceedBtn.disabled = true;
    _clsAdd(forceMaxModal, "open");
    const onCheck = () => { forceMaxProceedBtn.disabled = !forceMaxConfirmCheck.checked; };
    const onProceed = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    const cleanup = () => {
      _clsRemove(forceMaxModal, "open");
      forceMaxConfirmCheck.removeEventListener("change", onCheck);
      forceMaxProceedBtn.removeEventListener("click", onProceed);
      forceMaxCancelBtn.removeEventListener("click", onCancel);
    };
    forceMaxConfirmCheck.addEventListener("change", onCheck);
    forceMaxProceedBtn.addEventListener("click", onProceed);
    forceMaxCancelBtn.addEventListener("click", onCancel);
  });
}

// ============================================================================
// v25: LIVE OBFUSCATION (SSE + per-stage skip/continue)
// ============================================================================
//
// Runs an obfuscation via the streaming endpoints. Returns the same
// { code, elapsed, originalSize, obfuscatedSize, report } shape that
// obfuscateCode() returns so callers can swap between them freely.
// If any error occurs mid-flow, the promise rejects; the caller can then
// fall back to the classic one-shot /obfuscate endpoint.
//
async function obfuscateCodeLive(code, level, options) {
  options = options || {};
  if (level === "none") {
    return {
      code, elapsed: 0, originalSize: code.length,
      obfuscatedSize: code.length, report: null,
    };
  }

  // Step 1: reserve session.
  const startRes = await fetch("/obfuscate/stream/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code, level,
      forceMaximum: !!options.forceMaximum,
      userId: currentUser ? currentUser.id : null,
      referenceCode: referenceCode || null,
    }),
  });
  if (!startRes.ok) {
    let errMsg = "Failed to start stream";
    try { const d = await startRes.json(); errMsg = d.error || errMsg; } catch (e) {}
    throw new Error(errMsg);
  }
  const { sessionId } = await startRes.json();

  openLiveModal();
  setLiveStatus("Connecting...");

  // Step 2: open SSE + wait for completion.
  return new Promise((resolve, reject) => {
    const es = new EventSource("/obfuscate/stream/" + sessionId);
    _liveState = {
      sessionId, eventSource: es,
      stages: [],
      resolve, reject,
      aborted: false,
      finalPayload: null,
    };

    const cleanup = (why) => {
      try { es.close(); } catch (_) {}
      if (_liveState) _liveState.eventSource = null;
    };

    es.addEventListener("session-start", (ev) => {
      const d = JSON.parse(ev.data);
      _liveState.stages = d.stages || [];
      renderLiveStages(_liveState.stages);
      const lvl = (d.effectiveLevel || d.level || "").toUpperCase();
      if (liveSubtitleEl) liveSubtitleEl.textContent = "Applying " + lvl + " tier - " +
        _liveState.stages.length + " protection layer" +
        (_liveState.stages.length === 1 ? "" : "s") + " queued.";
      if (d.wasDowngraded && d.downgradeReason) {
        setLiveStatus("Auto-downgraded: " + d.downgradeReason);
      } else {
        setLiveStatus("Running...");
      }
    });

    es.addEventListener("stage-start", (ev) => {
      const d = JSON.parse(ev.data);
      updateLiveStage(d.stage, "running", d.label);
    });

    es.addEventListener("stage-await", (ev) => {
      const d = JSON.parse(ev.data);
      updateLiveStage(d.stage, "awaiting", d.label, "Waiting for your decision...");
    });

    es.addEventListener("stage-skip", (ev) => {
      const d = JSON.parse(ev.data);
      updateLiveStage(d.stage, "skipped", null, "Skipped");
      updateProgressBar();
    });

    es.addEventListener("stage-success", (ev) => {
      const d = JSON.parse(ev.data);
      const detail = (d.detail ? d.detail + " " : "") + "(" + (d.elapsedMs || 0) + " ms)";
      updateLiveStage(d.stage, "success", null, detail);
      updateProgressBar();
    });

    es.addEventListener("stage-failure", (ev) => {
      const d = JSON.parse(ev.data);
      updateLiveStage(d.stage, "failed", null, "Failed: " + (d.error || "unknown"));
      updateProgressBar();
    });

    es.addEventListener("session-complete", (ev) => {
      const d = JSON.parse(ev.data);
      _liveState.finalPayload = d;
      setLiveStatus("Done - " + ((d.report && d.report.stats && d.report.stats.elapsedMs) || 0) + " ms total");
      _clsAdd(liveCancelBtn, "hidden");
      _clsRemove(liveCloseBtn, "hidden");
      cleanup("complete");
      if (d && typeof d.code === "string") {
        resolve({
          code: d.code,
          elapsed: (d.report && d.report.stats && d.report.stats.elapsedMs) || 0,
          originalSize: d.original_size || code.length,
          obfuscatedSize: d.obfuscated_size || d.code.length,
          report: d.report || null,
        });
      } else {
        reject(new Error("Session finished without code"));
      }
    });

    es.addEventListener("session-error", (ev) => {
      const d = JSON.parse(ev.data);
      setLiveStatus("Error: " + (d.error || "unknown"));
      _clsAdd(liveCancelBtn, "hidden");
      _clsRemove(liveCloseBtn, "hidden");
      cleanup("error");
      reject(new Error(d.error || "Streaming pipeline failed"));
    });

    es.onerror = () => {
      if (_liveState && _liveState.finalPayload) return; // already completed
      setLiveStatus("Connection lost");
      _clsAdd(liveCancelBtn, "hidden");
      _clsRemove(liveCloseBtn, "hidden");
      cleanup("connection-error");
      reject(new Error("SSE connection lost"));
    };
  });
}

// Send a decision (skip: true|false) for the currently awaiting stage.
async function sendLiveDecision(stage, skip) {
  if (!_liveState || !_liveState.sessionId) return;
  try {
    await fetch("/obfuscate/stream/" + _liveState.sessionId + "/decision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stage, skip: !!skip }),
    });
  } catch (e) {
    setLiveStatus("Failed to send decision: " + e.message);
  }
}

function openLiveModal() {
  if (liveStagesEl) liveStagesEl.innerHTML = "";
  liveProgressFill.style.width = "0%";
  _clsRemove(liveCancelBtn, "hidden");
  _clsAdd(liveCloseBtn, "hidden");
  _clsAdd(liveModal, "open");
}

function closeLiveModal() {
  _clsRemove(liveModal, "open");
  // v25 FIX: reject any pending promise so the caller does not hang forever
  // if the user closes the modal mid-run.
  if (_liveState) {
    if (_liveState.eventSource) {
      try { _liveState.eventSource.close(); } catch (_) {}
    }
    if (_liveState.reject && !_liveState.finalPayload) {
      try { _liveState.reject(new Error("Live obfuscation cancelled")); } catch (_) {}
    }
  }
  _liveState = null;
}

function setLiveStatus(text) {
  if (liveStatusEl) liveStatusEl.textContent = text;
}

function renderLiveStages(stages) {
  if (liveStagesEl) liveStagesEl.innerHTML = "";
  for (const s of stages) {
    const div = document.createElement("div");
    div.className = "live-stage pending";
    div.setAttribute("data-stage", s.name);
    div.innerHTML =
      '<div class="live-stage-icon" data-role="icon">' + _stageIconSvg("pending") + '</div>' +
      '<div class="live-stage-body">' +
        '<div class="live-stage-label">' + escapeHtml(s.label) + '</div>' +
        '<div class="live-stage-detail" data-role="detail">Waiting to run</div>' +
      '</div>' +
      '<div class="live-stage-actions">' +
        '<button type="button" class="secondary small" data-action="skip">Skip</button>' +
        '<button type="button" class="primary small" data-action="continue">Continue</button>' +
      '</div>';
    div.querySelector('[data-action="skip"]').addEventListener("click", () => {
      sendLiveDecision(s.name, true);
      updateLiveStage(s.name, "running", null, "Skipping...");
    });
    div.querySelector('[data-action="continue"]').addEventListener("click", () => {
      sendLiveDecision(s.name, false);
      updateLiveStage(s.name, "running", null, "Running...");
    });
    liveStagesEl.appendChild(div);
  }
}

function updateLiveStage(stageName, status, label, detail) {
  const el = liveStagesEl.querySelector('[data-stage="' + stageName + '"]');
  if (!el) return;
  _clsRemove(el, "pending", "running", "awaiting", "success", "skipped", "failed");
  _clsAdd(el, status);
  const iconEl = el.querySelector('[data-role="icon"]');
  if (iconEl) iconEl.innerHTML = _stageIconSvg(status);
  if (label) {
    const lbl = el.querySelector(".live-stage-label");
    if (lbl) lbl.textContent = label;
  }
  if (detail != null) {
    const d = el.querySelector('[data-role="detail"]');
    if (d) d.textContent = detail;
  }
}

function updateProgressBar() {
  const nodes = liveStagesEl.querySelectorAll(".live-stage");
  if (!nodes.length) return;
  let done = 0;
  nodes.forEach(n => {
    if (n.classList.contains("success") || n.classList.contains("skipped") || n.classList.contains("failed")) done++;
  });
  liveProgressFill.style.width = ((done / nodes.length) * 100).toFixed(1) + "%";
}

function _stageIconSvg(status) {
  if (status === "running" || status === "awaiting") {
    return '<div class="live-stage-spinner"></div>';
  }
  if (status === "success") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><polyline points="20 6 9 17 4 12"/></svg>';
  }
  if (status === "skipped") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><line x1="5" y1="12" x2="19" y2="12"/></svg>';
  }
  if (status === "failed") {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
  }
  // pending
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;"><circle cx="12" cy="12" r="9"/></svg>';
}

liveCancelBtn?.addEventListener("click", () => {
  // v25 FIX: just close -- closeLiveModal now handles the reject itself.
  closeLiveModal();
});

liveCloseBtn?.addEventListener("click", closeLiveModal);

// ============================================================================
// v16: ADVANCED OPTIONS COLLAPSIBLE
// ============================================================================
advOptionsToggle?.addEventListener("click", () => {
  _clsToggle(advOptionsToggle, "open");
  _clsToggle(advOptionsBody, "open");
});

// ============================================================================
// v16: REPORT RENDERING
// ============================================================================
// v25 FIX: helper to set textContent only if element exists
function _setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function renderReport(report, generatedCode) {
  if (!report) {
    _clsAdd(reportCard, "hidden");
    return;
  }
  _clsRemove(reportCard, "hidden");
  if (abCompareResult) _clsAdd(abCompareResult, "hidden");

  // Hero
  _setText("reportRequestedLevel", (report.requestedLevel || "-").toUpperCase());
  _setText("reportActualLevel", (report.actualLevel || "-").toUpperCase());
  const downgradeBadge = document.getElementById("reportDowngradeBadge");
  if (report.wasDowngraded && downgradeBadge) {
    _clsRemove(downgradeBadge, "hidden");
    if (downgradeBadge) downgradeBadge.textContent = report.actualLevel === "fallback" || report.actualLevel === "minified"
      ? "FALLBACK" : "DOWNGRADED";
    downgradeBadge.className = "badge " + (
      report.actualLevel === "fallback" || report.actualLevel === "minified"
        ? "badge-danger" : "badge-warning"
    );
  } else if (downgradeBadge) {
    _clsAdd(downgradeBadge, "hidden");
  }

  // Downgrade banner
  const banner = document.getElementById("reportDowngradeBanner");
  if (report.wasDowngraded && report.downgradeReason && banner) {
    _clsRemove(banner, "hidden");
    const isError = report.actualLevel === "fallback" || report.actualLevel === "minified";
    _clsToggle(banner, "error", isError);
    _setText("reportDowngradeTitle", isError
      ? "Fallback mode active" : "Auto-downgrade applied");
    _setText("reportDowngradeMsg", report.downgradeReason);
  } else if (banner) {
    _clsAdd(banner, "hidden");
  }

  // Profile
  const p = report.profile || {};
  _setText("profRisk", p.riskTier || "-");
  _setText("profComplexity", p.complexityScore != null ? p.complexityScore : "-");
  _setText("profDepth", p.maxBlockDepth != null ? p.maxBlockDepth : "-");
  _setText("profFuncs", p.functionCount != null ? p.functionCount : "-");
  _setText("profPcalls", p.pcallCount != null ? p.pcallCount : "-");
  const hooks = [];
  if (p.hasHookfunction) hooks.push("hookfunction");
  if (p.hasHookmetamethod) hooks.push("hookmetamethod");
  _setText("profHooks", hooks.length > 0 ? hooks.join(" + ") : "none");

  // Layers
  const layersEl = document.getElementById("reportLayers");
  if (layersEl) layersEl.innerHTML = "";
  const L = report.layers || {};
  const layerDefs = [
    { key: "vmWrap", name: "Inner VM wrap" },
    { key: "outerVM", name: "Multi-layer outer VM" },
    { key: "antiDebugger", name: "Anti-debugger", mode: L.antiDebuggerMode },
    { key: "integrityCheck", name: "Integrity check" },
    { key: "stringEncryption", name: "String encryption", mode: L.stringEncryptionStrict ? "strict" : "normal" },
    { key: "constantObfuscation", name: "Numeric obfuscation" },
    { key: "constantPool", name: "Constant pool + poison" },
    { key: "antiTamper", name: "Anti-tamper wrapper" },
    { key: "antiDump", name: "Anti-dump" },
    { key: "byteLevelXor", name: "Byte-level XOR encryption" },
  ];
  for (const def of layerDefs) {
    const active = !!L[def.key];
    const div = document.createElement("div");
    div.className = "layer-item " + (active ? "active" : "inactive");
    div.innerHTML = `
      <svg class="check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
        ${active
          ? '<polyline points="20 6 9 17 4 12"/>'
          : '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>'}
      </svg>
      <span class="layer-name">${escapeHtml(def.name)}</span>
      ${active && def.mode ? `<span class="layer-mode">${escapeHtml(def.mode)}</span>` : ""}
    `;
    layersEl.appendChild(div);
  }

  // v22 NEW: Reference manifest stats
  const manifestSection = document.getElementById("reportManifestSection");
  const m = report.manifest;
  if (m && !m.error && typeof m.identifiers === "number" && manifestSection) {
    _clsRemove(manifestSection, "hidden");
    _setText("manifestIdentifiers", m.identifiers.toLocaleString());
    _setText("manifestStrings", (m.strings || 0).toLocaleString());
    _setText("manifestPropertyNames", (m.propertyNames || 0).toLocaleString());
    _setText("manifestZeroInits", (m.zeroInitLocals || 0).toLocaleString());
    _setText("manifestForwardRefs", (m.forwardRefs || 0).toLocaleString());
    _setText("manifestMethodBases", (m.methodCallBases || 0).toLocaleString());
  } else if (manifestSection) {
    _clsAdd(manifestSection, "hidden");
  }

  // Stats
  const s = report.stats || {};
  _setText("statOrig", s.originalBytes ? s.originalBytes.toLocaleString() + " B" : "-");
  _setText("statObf", s.obfuscatedBytes ? s.obfuscatedBytes.toLocaleString() + " B" : "-");
  _setText("statRatio", s.sizeRatio ? s.sizeRatio.toFixed(2) + "x" : "-");
  _setText("statElapsed", s.elapsedMs != null ? s.elapsedMs + " ms" : "-");
  _setText("statStrEnc", s.stringsEncrypted != null ? s.stringsEncrypted : "-");
  _setText("statStrSkip", s.stringsSkipped != null ? s.stringsSkipped : "-");
  _setText("statNumObf", s.numericConstsObfuscated != null ? s.numericConstsObfuscated : "-");
  _setText("statVmStmt", s.vmCompiledStatements != null ? s.vmCompiledStatements : "0");

  // Warnings
  const warningsWrap = document.getElementById("reportWarningsWrap");
  const warningsList = document.getElementById("reportWarningsList");
  if (report.warnings && report.warnings.length > 0 && warningsWrap) {
    _clsRemove(warningsWrap, "hidden");
    if (warningsList) warningsList.innerHTML = "";
    for (const w of report.warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      warningsList.appendChild(li);
    }
  } else if (warningsWrap) {
    _clsAdd(warningsWrap, "hidden");
  }

  // Generated code preview (Prism)
  if (generatedCode) {
    // Limit rendering to first 30KB for perf; show truncation notice
    const MAX_SHOW = 30000;
    const shown = generatedCode.length > MAX_SHOW
      ? generatedCode.slice(0, MAX_SHOW) + "\n\n-- ... (truncated, " + (generatedCode.length - MAX_SHOW).toLocaleString() + " chars hidden. Use Copy button for full code) --"
      : generatedCode;
    if (reportCodeOutput) reportCodeOutput.textContent = shown;
    if (viewCodeChars) viewCodeChars.textContent = "(" + generatedCode.length.toLocaleString() + " chars)";
    // Trigger Prism re-highlight
    if (window.Prism && window.Prism.highlightElement) {
      try { window.Prism.highlightElement(reportCodeOutput); } catch (e) {}
    }
  } else {
    if (reportCodeOutput) reportCodeOutput.textContent = "-- No code available --";
    if (viewCodeChars) viewCodeChars.textContent = "";
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

closeReportBtn?.addEventListener("click", () => _clsAdd(reportCard, "hidden"));

viewCodeToggle?.addEventListener("click", () => {
  _clsToggle(viewCodeToggle, "open");
  _clsToggle(viewCodeBody, "open");
});

copyReportCodeBtn?.addEventListener("click", async () => {
  if (!lastPreviewedCode) return;
  try {
    await navigator.clipboard.writeText(lastPreviewedCode);
    const original = copyReportCodeBtn.textContent;
    if (copyReportCodeBtn) copyReportCodeBtn.textContent = "Copied!";
    setTimeout(() => (copyReportCodeBtn.textContent = original), 1500);
  } catch (err) {
    showMessage("Failed to copy. Select and copy manually.", "error");
  }
});

// ============================================================================
// v16: A/B COMPARE (on-demand)
// ============================================================================
abCompareBtn?.addEventListener("click", async () => {
  if (!lastReport || !lastRequestedLevel) return;
  const code = scriptCodeInput.value;
  if (!code.trim()) return;

  // Pick the "other" tier to compare against
  const actual = lastReport.actualLevel;
  const alt = actual === "maximum" ? "medium"
             : actual === "medium" ? "maximum"
             : actual === "basic" ? "medium"
             : "basic";

  if (abCompareBtn) abCompareBtn.disabled = true;
  const originalText = abCompareBtn.textContent;
  if (abCompareBtn) abCompareBtn.textContent = "Running " + alt + "...";

  try {
    const altResult = await obfuscateCodeAny(code, alt, { forceMaximum: false });

    _clsRemove(abCompareResult, "hidden");
    document.getElementById("abThisLevel").textContent = actual.toUpperCase();
    document.getElementById("abThisSize").textContent =
      `${(lastReport.stats.obfuscatedBytes || 0).toLocaleString()} B (${(lastReport.stats.sizeRatio || 0).toFixed(2)}x) - ${lastReport.stats.elapsedMs || 0} ms`;

    document.getElementById("abAltLevel").textContent = (altResult.report ? altResult.report.actualLevel : alt).toUpperCase();
    const altRatio = altResult.originalSize > 0 ? (altResult.obfuscatedSize / altResult.originalSize) : 0;
    document.getElementById("abAltSize").textContent =
      `${altResult.obfuscatedSize.toLocaleString()} B (${altRatio.toFixed(2)}x) - ${altResult.elapsed} ms`;

    showMessage(`A/B compare complete. Alternate tier: ${alt}`, "success");
  } catch (err) {
    showMessage("A/B compare failed: " + err.message, "error");
  } finally {
    if (abCompareBtn) abCompareBtn.disabled = false;
    if (abCompareBtn) abCompareBtn.textContent = originalText;
  }
});

// ============================================================================
// PREVIEW HANDLER (v16: now populates report card too)
// ============================================================================
previewBtn.addEventListener("click", async () => {
  const code = scriptCodeInput.value;
  const level = obfuscationLevelSelect.value;
  const wantForce = !!(forceMaximumCheckbox && forceMaximumCheckbox.checked);
  hideMessage();

  if (!code.trim()) { showMessage("Wala kang na-paste na code.", "error"); return; }
  if (code.length > MAX_SCRIPT_SIZE) { showMessage("Script too long. Max 10MB.", "error"); return; }

  // v16: Force max confirm modal
  let forceMaximum = false;
  if (wantForce && level === "maximum") {
    const confirmed = await openForceMaxModal();
    if (!confirmed) { showMessage("Force-maximum canceled.", "info"); return; }
    forceMaximum = true;
  }

  if (previewBtn) previewBtn.disabled = true;
  const originalText = previewBtn.textContent;
  if (previewBtn) previewBtn.textContent = "Generating preview...";

  try {
    const result = await obfuscateCodeAny(code, level, { forceMaximum });
    lastPreviewedCode = result.code;
    lastReport = result.report;
    lastRequestedLevel = level;

    // Preview card
    const ratio = result.obfuscatedSize / result.originalSize;
    const ratioStr = ratio.toFixed(2);
    const actualLevel = result.report ? result.report.actualLevel : level;
    const statsText = level === "none"
      ? `Level: none | ${result.originalSize.toLocaleString()} chars (no changes)`
      : `Applied: ${actualLevel} | ${result.originalSize.toLocaleString()} chars -> ${result.obfuscatedSize.toLocaleString()} chars (${ratioStr}x) | ${result.elapsed}ms`;
    if (previewStats) previewStats.textContent = statsText;

    // Prism-highlighted preview (limit for perf)
    const MAX_SHOW = 30000;
    const shown = result.code.length > MAX_SHOW
      ? result.code.slice(0, MAX_SHOW) + "\n\n-- ... (truncated) --"
      : result.code;
    if (previewOutput) previewOutput.textContent = shown;
    if (window.Prism && window.Prism.highlightElement) {
      try { window.Prism.highlightElement(previewOutput); } catch (e) {}
    }
    _clsRemove(previewCard, "hidden");

    // v16: Report card (render with generated code, close preview code section by default)
    renderReport(result.report, result.code);
    // Make sure the collapsible starts closed
    _clsRemove(viewCodeToggle, "open");
    _clsRemove(viewCodeBody, "open");

    if (reportCard && reportCard.scrollIntoView) reportCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    showMessage(`Preview ready. Check the report below, then click Save Script.`, "success");
  } catch (err) {
    showMessage(err.message || "Failed to preview.", "error");
  } finally {
    if (previewBtn) previewBtn.disabled = false;
    if (previewBtn) previewBtn.textContent = originalText;
    updateUI();
  }
});

closePreviewBtn.addEventListener("click", () => {
  _clsAdd(previewCard, "hidden");
});

copyPreviewBtn.addEventListener("click", async () => {
  if (!lastPreviewedCode) return;
  try {
    await navigator.clipboard.writeText(lastPreviewedCode);
    const original = copyPreviewBtn.textContent;
    if (copyPreviewBtn) copyPreviewBtn.textContent = "Copied!";
    setTimeout(() => (copyPreviewBtn.textContent = original), 1500);
  } catch (err) {
    showMessage("Failed to copy. Select and copy manually.", "error");
  }
});

// ============================================================================
// SAVE HANDLER (v16: force max modal + report render)
// ============================================================================
saveBtn.addEventListener("click", async () => {
  const name = scriptNameInput.value.trim();
  const code = scriptCodeInput.value;
  const level = obfuscationLevelSelect ? obfuscationLevelSelect.value : "none";
  const requireKey = requireKeyCheckbox ? requireKeyCheckbox.checked : true;
  const wantForce = !!(forceMaximumCheckbox && forceMaximumCheckbox.checked);

  hideMessage();
  if (!code.trim()) { showMessage("Wala kang na-paste na code.", "error"); return; }
  if (code.length > MAX_SCRIPT_SIZE) { showMessage("Script too long. Max 10MB.", "error"); return; }

  // v16: Force max confirm modal
  let forceMaximum = false;
  if (wantForce && level === "maximum") {
    const confirmed = await openForceMaxModal();
    if (!confirmed) { showMessage("Force-maximum canceled.", "info"); return; }
    forceMaximum = true;
  }

  if (saveBtn) saveBtn.disabled = true;
  const originalText = saveBtn.textContent;

  try {
    let finalCode = code;
    let sizeInfo = "";
    let report = null;
    if (level !== "none") {
      if (saveBtn) saveBtn.textContent = "Obfuscating...";
      showMessage(`Obfuscating with level: ${level}${forceMaximum ? " (forced)" : ""}...`, "info");
      const result = await obfuscateCodeAny(code, level, { forceMaximum });
      finalCode = result.code;
      report = result.report;
      lastPreviewedCode = result.code;
      lastReport = result.report;
      lastRequestedLevel = level;
      sizeInfo = ` (${result.originalSize.toLocaleString()} -> ${result.obfuscatedSize.toLocaleString()} chars)`;
    }

    if (saveBtn) saveBtn.textContent = "Saving...";
    showMessage("Saving to database...", "info");

    let scriptId = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = generateId(8);
      const { error } = await sb.from("scripts").insert({
        id, user_id: currentUser.id, name: name || null,
        code: finalCode, key_required: requireKey,
      });
      if (!error) { scriptId = id; break; }
      if (error.code !== "23505") throw error;
    }
    if (!scriptId) throw new Error("Could not generate a unique ID. Try again.");

    lastSavedScriptId = scriptId;
    const loadstring = buildLoadstring(scriptId);
    if (loadstringOutput) loadstringOutput.textContent = loadstring;
    _clsRemove(resultCard, "hidden");

    // v16: Also render report if available
    if (report) {
      renderReport(report, finalCode);
      _clsRemove(viewCodeToggle, "open");
      _clsRemove(viewCodeBody, "open");
    }

    if (resultCard && resultCard.scrollIntoView) resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

    const actualLevel = report ? report.actualLevel : level;
    const modeInfo = requireKey
      ? ` Generate a key below to enable protection.`
      : ` Script is FREE (no key required) - anyone can run this loadstring.`;
    showMessage(
      `Script saved! ID: ${scriptId} | Applied: ${actualLevel}${sizeInfo}.${modeInfo}`,
      "success"
    );

    await refreshScriptOptions();
  } catch (err) {
    showMessage(err.message || "Failed to save script.", "error");
  } finally {
    if (saveBtn) saveBtn.disabled = false;
    if (saveBtn) saveBtn.textContent = originalText;
    updateUI();
  }
});

copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(loadstringOutput.textContent);
    const originalText = copyBtn.textContent;
    if (copyBtn) copyBtn.textContent = "Copied!";
    setTimeout(() => { copyBtn.textContent = originalText; }, 1500);
  } catch (err) {
    showMessage("Failed to copy. Select and copy manually.", "error");
  }
});

// ============================================================================
// KEY MANAGEMENT (unchanged)
// ============================================================================

async function refreshScriptOptions() {
  if (!keyScriptSelect) return;
  const { data: scripts, error } = await sb
    .from("scripts").select("id, name, created_at, key_required")
    .eq("user_id", currentUser.id).order("created_at", { ascending: false });
  if (error) { console.error("Failed to load scripts:", error); return; }

  if (keyScriptSelect) keyScriptSelect.innerHTML = '<option value="">-- Select a script --</option>';
  (scripts || []).forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.id;
    const mode = s.key_required === false ? " [FREE]" : "";
    if (opt) opt.textContent = `${s.name || "(unnamed)"} - ${s.id}${mode}`;
    if (s.key_required === false) opt.disabled = true;
    keyScriptSelect.appendChild(opt);
  });
  if (lastSavedScriptId) keyScriptSelect.value = lastSavedScriptId;
}

async function loadUserKeys() {
  if (!keysList) return;
  await refreshScriptOptions();
  const { data: keys, error } = await sb
    .from("user_keys").select("*, scripts(name)")
    .eq("owner_id", currentUser.id).order("created_at", { ascending: false });
  if (error) {
    console.error("Failed to load keys:", error);
    if (keysList) keysList.innerHTML = '<p class="muted">Failed to load keys.</p>';
    return;
  }
  if (!keys || keys.length === 0) {
    if (keysList) keysList.innerHTML = '<p class="muted">No keys generated yet. Create one above.</p>';
    return;
  }
  if (keysList) keysList.innerHTML = keys.map((k) => renderKeyRow(k)).join("");
  keysList.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", handleKeyAction);
  });
}

function renderKeyRow(k) {
  const scriptName = k.scripts?.name || "(unnamed)";
  const status = k.revoked
    ? '<span class="badge badge-danger">REVOKED</span>'
    : (k.expires_at && new Date(k.expires_at) < new Date())
    ? '<span class="badge badge-warning">EXPIRED</span>'
    : '<span class="badge badge-success">ACTIVE</span>';
  const hwidInfo = k.hwid
    ? `<code class="hwid">${k.hwid.substring(0, 16)}...</code>`
    : '<span class="muted">Not bound yet</span>';
  const placeIds = k.place_id_whitelist?.length ? k.place_id_whitelist.join(", ") : "Any game";
  const execInfo = k.max_executions ? `${k.execution_count} / ${k.max_executions}` : `${k.execution_count} / unlimited`;
  const expiresInfo = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "Never";
  return `
    <div class="key-row">
      <div class="key-row-head">
        <code class="key-value">${k.key}</code>
        ${status}
      </div>
      <div class="key-meta">
        <div><strong>Script:</strong> ${scriptName} (${k.script_id})</div>
        <div><strong>HWID:</strong> ${hwidInfo}</div>
        <div><strong>Allowed PlaceIds:</strong> ${placeIds}</div>
        <div><strong>Executions:</strong> ${execInfo}</div>
        <div><strong>Expires:</strong> ${expiresInfo}</div>
      </div>
      <div class="key-actions row" style="gap: 8px; flex-wrap: wrap">
        <button data-action="copy-loader" data-key="${k.key}" data-script="${k.script_id}" class="secondary small">Copy Loader</button>
        <button data-action="reset-hwid" data-key="${k.key}" class="secondary small" ${!k.hwid ? "disabled" : ""}>Reset HWID</button>
        ${k.revoked
          ? `<button data-action="unrevoke" data-key="${k.key}" class="secondary small">Unrevoke</button>`
          : `<button data-action="revoke" data-key="${k.key}" class="secondary small">Kill (Revoke)</button>`}
        <button data-action="delete" data-key="${k.key}" class="secondary small">Delete</button>
      </div>
    </div>
  `;
}

async function handleKeyAction(e) {
  const action = e.currentTarget.dataset.action;
  const key = e.currentTarget.dataset.key;
  const scriptId = e.currentTarget.dataset.script;
  if (action === "copy-loader") {
    const loader = buildProtectedLoadstring(scriptId, key);
    try {
      await navigator.clipboard.writeText(loader);
      const original = e.currentTarget.textContent;
      e.currentTarget.textContent = "Copied!";
      setTimeout(() => (e.currentTarget.textContent = original), 1500);
    } catch (err) {
      showMessage("Failed to copy loader.", "error");
    }
    return;
  }
  if (action === "reset-hwid") {
    if (!confirm("Reset HWID for this key? User will be able to re-bind on next execution.")) return;
    const { error } = await sb.from("user_keys").update({ hwid: null, first_used_at: null }).eq("key", key);
    if (error) { showMessage("Reset failed: " + error.message, "error"); return; }
    showMessage("HWID reset.", "success");
    await loadUserKeys();
    return;
  }
  if (action === "revoke") {
    if (!confirm("Revoke this key? User will get an error on next execution.")) return;
    const { error } = await sb.from("user_keys").update({ revoked: true }).eq("key", key);
    if (error) { showMessage("Revoke failed: " + error.message, "error"); return; }
    showMessage("Key revoked.", "success");
    await loadUserKeys();
    return;
  }
  if (action === "unrevoke") {
    const { error } = await sb.from("user_keys").update({ revoked: false }).eq("key", key);
    if (error) { showMessage("Unrevoke failed: " + error.message, "error"); return; }
    showMessage("Key restored.", "success");
    await loadUserKeys();
    return;
  }
  if (action === "delete") {
    if (!confirm("Delete this key permanently? This cannot be undone.")) return;
    const { error } = await sb.from("user_keys").delete().eq("key", key);
    if (error) { showMessage("Delete failed: " + error.message, "error"); return; }
    showMessage("Key deleted.", "success");
    await loadUserKeys();
    return;
  }
}

generateKeyBtn?.addEventListener("click", async () => {
  const scriptId = keyScriptSelect.value;
  if (!scriptId) { showMessage("Select a script first.", "error"); return; }
  const key = generateLicenseKey();
  const placeIdsRaw = (keyPlaceIdsInput.value || "").trim();
  const placeIds = placeIdsRaw
    ? placeIdsRaw.split(",").map((s) => Number(s.trim())).filter((n) => n > 0)
    : null;
  const maxExec = keyMaxExecInput.value ? Number(keyMaxExecInput.value) : null;
  const expiresAt = keyExpiresInput.value ? new Date(keyExpiresInput.value).toISOString() : null;

  if (generateKeyBtn) generateKeyBtn.disabled = true;
  const original = generateKeyBtn.textContent;
  if (generateKeyBtn) generateKeyBtn.textContent = "Creating...";
  try {
    const { error } = await sb.from("user_keys").insert({
      key, script_id: scriptId, owner_id: currentUser.id,
      place_id_whitelist: placeIds, max_executions: maxExec,
      expires_at: expiresAt, execution_count: 0, revoked: false,
    });
    if (error) throw error;
    showMessage(`Key created: ${key}`, "success");
    keyPlaceIdsInput.value = "";
    keyMaxExecInput.value = "";
    keyExpiresInput.value = "";
    await loadUserKeys();
  } catch (err) {
    showMessage("Failed to create key: " + err.message, "error");
  } finally {
    if (generateKeyBtn) generateKeyBtn.disabled = false;
    if (generateKeyBtn) generateKeyBtn.textContent = original;
  }
});

// ============================================================================
// UTIL
// ============================================================================
function showMessage(text, type = "info") {
  if (messageDiv) messageDiv.textContent = text;
  messageDiv.className = `message message-${type}`;
  _clsRemove(messageDiv, "hidden");
}
function hideMessage() { _clsAdd(messageDiv, "hidden"); }
