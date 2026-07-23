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
  logoutBtn.disabled = true;
  logoutBtn.textContent = "Logging out...";
  try { await sb.auth.signOut(); } catch (err) {}
  finally { window.location.href = "index.html"; }
});

function updateUI() {
  const len = scriptCodeInput.value.length;
  charCountEl.textContent = `${len.toLocaleString()} characters`;
  const hasCode = len > 0;
  saveBtn.disabled = !hasCode;
  previewBtn.disabled = !hasCode;
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
    referenceFileNameEl.textContent = "Reference: " + file.name + " (" +
      referenceCode.length.toLocaleString() + " chars)";
    referenceClearBtn.classList.remove("hidden");
    showMessage("Reference file loaded. It will be used for the next obfuscation.", "success");
  };
  reader.onerror = () => showMessage("Failed to read reference file.", "error");
  reader.readAsText(file);
});

referenceClearBtn?.addEventListener("click", () => {
  referenceCode = "";
  referenceFileName = "";
  referenceUpload.value = "";
  referenceFileNameEl.textContent = "";
  referenceClearBtn.classList.add("hidden");
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
    fileNameEl.textContent = `Loaded: ${file.name}`;
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
    fileNameEl.textContent = "";
    fileUpload.value = "";
    hideMessage();
    resultCard.classList.add("hidden");
    previewCard.classList.add("hidden");
    reportCard.classList.add("hidden");
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
// Phase 2a: Per-layer overrides + hint updater
// ============================================================================
const OVERRIDE_LAYERS = ["antiDebugger", "antiDump", "antiTamper", "byteLevelXor", "vmWrap", "outerVM"];

function readLayerOverrides() {
  const out = {};
  for (const key of OVERRIDE_LAYERS) {
    const el = document.getElementById("ovr_" + key);
    if (el && el.value && el.value !== "auto") out[key] = el.value;
  }
  return out;
}

function predictAutoDecision(layerKey, profile) {
  const p = profile || {};
  const hooks = !!p.hasHookfunction || !!p.hasHookmetamethod;
  const refl  = !!p.hasRuntimeReflection;
  switch (layerKey) {
    case "antiDebugger":
      return hooks
        ? { enabled: false, reason: "script installs hooks (would false-positive)" }
        : { enabled: true,  reason: "no hooks detected \u2014 safe to apply" };
    case "antiDump":
      return { enabled: true, reason: "pure global-existence probes \u2014 no collision risk" };
    case "antiTamper":
      return hooks
        ? { enabled: false, reason: "script installs hooks (would false-positive)" }
        : { enabled: true,  reason: "no hooks detected \u2014 safe to apply" };
    case "byteLevelXor":
      return hooks
        ? { enabled: false, reason: "script installs hooks (bit32.bxor collision risk)" }
        : { enabled: true,  reason: "no hooks detected \u2014 safe to apply" };
    case "vmWrap":
      return (hooks || refl)
        ? { enabled: false, reason: (hooks ? "hooks" : "reflection") + " detected (would false-positive)" }
        : { enabled: true,  reason: "eligible \u2014 will wrap qualifying print() calls" };
    case "outerVM":
      return hooks
        ? { enabled: false, reason: "script installs hooks (decoder collision risk)" }
        : { enabled: true,  reason: "safe \u2014 decoy or real path will emit" };
    default:
      return { enabled: true, reason: "" };
  }
}

function updateOverrideHints(profile) {
  for (const key of OVERRIDE_LAYERS) {
    const hintEl = document.getElementById("ovrHint_" + key);
    const selEl  = document.getElementById("ovr_" + key);
    if (!hintEl || !selEl) continue;
    if (selEl.value === "force") {
      hintEl.textContent = "Force: bypass smart-skip (may false-positive at runtime)";
      hintEl.className = "hint auto-off";
      continue;
    }
    if (selEl.value === "skip") {
      hintEl.textContent = "Skip: this layer will never be applied";
      hintEl.className = "hint";
      continue;
    }
    if (!profile) {
      hintEl.textContent = "Auto: obfuscate once to preview what this would do";
      hintEl.className = "hint";
      continue;
    }
    const dec = predictAutoDecision(key, profile);
    hintEl.textContent = "Auto: " + (dec.enabled ? "will be enabled" : "will be skipped") +
                        (dec.reason ? " (" + dec.reason + ")" : "");
    hintEl.className = "hint " + (dec.enabled ? "auto-on" : "auto-off");
  }
}

for (const key of OVERRIDE_LAYERS) {
  document.getElementById("ovr_" + key)?.addEventListener("change", () => {
    updateOverrideHints(lastReport ? lastReport.profile : null);
  });
}

// ============================================================================
// v16: OBFUSCATION WITH REPORT
// ============================================================================
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
      // Phase 2a: per-layer overrides
      layerOverrides: readLayerOverrides(),
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
    forceMaxProceedBtn.disabled = true;
    forceMaxModal.classList.add("open");
    const onCheck = () => { forceMaxProceedBtn.disabled = !forceMaxConfirmCheck.checked; };
    const onProceed = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    const cleanup = () => {
      forceMaxModal.classList.remove("open");
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
// v16: ADVANCED OPTIONS COLLAPSIBLE
// ============================================================================
advOptionsToggle?.addEventListener("click", () => {
  advOptionsToggle.classList.toggle("open");
  advOptionsBody.classList.toggle("open");
});

// ============================================================================
// v16: REPORT RENDERING
// ============================================================================
function renderReport(report, generatedCode) {
  if (!report) {
    reportCard.classList.add("hidden");
    return;
  }
  reportCard.classList.remove("hidden");
  abCompareResult.classList.add("hidden");

  // Hero
  document.getElementById("reportRequestedLevel").textContent = (report.requestedLevel || "-").toUpperCase();
  document.getElementById("reportActualLevel").textContent = (report.actualLevel || "-").toUpperCase();
  const downgradeBadge = document.getElementById("reportDowngradeBadge");
  if (report.wasDowngraded) {
    downgradeBadge.classList.remove("hidden");
    downgradeBadge.textContent = report.actualLevel === "fallback" || report.actualLevel === "minified"
      ? "FALLBACK" : "DOWNGRADED";
    downgradeBadge.className = "badge " + (
      report.actualLevel === "fallback" || report.actualLevel === "minified"
        ? "badge-danger" : "badge-warning"
    );
  } else {
    downgradeBadge.classList.add("hidden");
  }

  // Downgrade banner
  const banner = document.getElementById("reportDowngradeBanner");
  if (report.wasDowngraded && report.downgradeReason) {
    banner.classList.remove("hidden");
    const isError = report.actualLevel === "fallback" || report.actualLevel === "minified";
    banner.classList.toggle("error", isError);
    document.getElementById("reportDowngradeTitle").textContent = isError
      ? "Fallback mode active" : "Auto-downgrade applied";
    document.getElementById("reportDowngradeMsg").textContent = report.downgradeReason;
  } else {
    banner.classList.add("hidden");
  }

  // Profile
  const p = report.profile || {};
  document.getElementById("profRisk").textContent = p.riskTier || "-";
  document.getElementById("profComplexity").textContent = p.complexityScore != null ? p.complexityScore : "-";
  document.getElementById("profDepth").textContent = p.maxBlockDepth != null ? p.maxBlockDepth : "-";
  document.getElementById("profFuncs").textContent = p.functionCount != null ? p.functionCount : "-";
  document.getElementById("profPcalls").textContent = p.pcallCount != null ? p.pcallCount : "-";
  const hooks = [];
  if (p.hasHookfunction) hooks.push("hookfunction");
  if (p.hasHookmetamethod) hooks.push("hookmetamethod");
  document.getElementById("profHooks").textContent = hooks.length > 0 ? hooks.join(" + ") : "none";

  // Layers
  const layersEl = document.getElementById("reportLayers");
  layersEl.innerHTML = "";
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
  if (m && !m.error && typeof m.identifiers === "number") {
    manifestSection.classList.remove("hidden");
    document.getElementById("manifestIdentifiers").textContent = m.identifiers.toLocaleString();
    document.getElementById("manifestStrings").textContent = (m.strings || 0).toLocaleString();
    document.getElementById("manifestPropertyNames").textContent = (m.propertyNames || 0).toLocaleString();
    document.getElementById("manifestZeroInits").textContent = (m.zeroInitLocals || 0).toLocaleString();
    document.getElementById("manifestForwardRefs").textContent = (m.forwardRefs || 0).toLocaleString();
    document.getElementById("manifestMethodBases").textContent = (m.methodCallBases || 0).toLocaleString();
  } else {
    manifestSection.classList.add("hidden");
  }

  // Stats
  const s = report.stats || {};
  document.getElementById("statOrig").textContent = s.originalBytes ? s.originalBytes.toLocaleString() + " B" : "-";
  document.getElementById("statObf").textContent = s.obfuscatedBytes ? s.obfuscatedBytes.toLocaleString() + " B" : "-";
  document.getElementById("statRatio").textContent = s.sizeRatio ? s.sizeRatio.toFixed(2) + "x" : "-";
  document.getElementById("statElapsed").textContent = s.elapsedMs != null ? s.elapsedMs + " ms" : "-";
  document.getElementById("statStrEnc").textContent = s.stringsEncrypted != null ? s.stringsEncrypted : "-";
  document.getElementById("statStrSkip").textContent = s.stringsSkipped != null ? s.stringsSkipped : "-";
  document.getElementById("statNumObf").textContent = s.numericConstsObfuscated != null ? s.numericConstsObfuscated : "-";
  document.getElementById("statVmStmt").textContent = s.vmCompiledStatements != null ? s.vmCompiledStatements : "0";

  // Warnings Ã¢â‚¬â€ v2: with Copy all + Console toggle
  const warningsWrap = document.getElementById("reportWarningsWrap");
  const warningsList = document.getElementById("reportWarningsList");
  const warningsCount = document.getElementById("reportWarningsCount");
  const reportConsole = document.getElementById("reportConsole");
  const copyWarningsBtn = document.getElementById("copyWarningsBtn");
  const toggleConsoleBtn = document.getElementById("toggleConsoleBtn");

  if (report.warnings && report.warnings.length > 0) {
    warningsWrap.classList.remove("hidden");
    warningsList.innerHTML = "";
    for (const w of report.warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      warningsList.appendChild(li);
    }
    if (warningsCount) {
      warningsCount.textContent = "(" + report.warnings.length + ")";
    }

    // Build console text: warnings + stage flow + timings + stats summary
    const consoleLines = [];
    consoleLines.push("=== OBFUSCATION REPORT ===");
    consoleLines.push("Requested: " + (report.requestedLevel || "?") + "  |  Applied: " + (report.actualLevel || "?"));
    if (report.wasDowngraded) {
      consoleLines.push("!!! DOWNGRADED: " + (report.downgradeReason || "(no reason given)"));
    }
    consoleLines.push("");
    consoleLines.push("=== STATS ===");
    if (report.stats) {
      for (const k of Object.keys(report.stats)) {
        consoleLines.push("  " + k + ": " + JSON.stringify(report.stats[k]));
      }
    }
    if (report.stageTimings && Object.keys(report.stageTimings).length > 0) {
      consoleLines.push("");
      consoleLines.push("=== STAGE TIMINGS (ms) ===");
      for (const k of Object.keys(report.stageTimings)) {
        consoleLines.push("  " + k + ": " + report.stageTimings[k] + " ms");
      }
    }
    if (report.stagesSucceeded && report.stagesSucceeded.length > 0) {
      consoleLines.push("");
      consoleLines.push("=== STAGES SUCCEEDED ===");
      for (const s of report.stagesSucceeded) consoleLines.push("  Ã¢Å“â€œ " + s);
    }
    if (report.stagesSkipped && report.stagesSkipped.length > 0) {
      consoleLines.push("");
      consoleLines.push("=== STAGES SKIPPED ===");
      for (const s of report.stagesSkipped) consoleLines.push("  Ã¢Å“â€” " + s);
    }
    // v25.30 forensic: wide snippets from failed stages
    if (report.stageDebug && report.stageDebug.length > 0) {
      consoleLines.push("");
      consoleLines.push("=== STAGE FORENSIC (v25.30) ===");
      for (const d of report.stageDebug) {
        consoleLines.push("--- Stage: " + d.stage + " ---");
        consoleLines.push("Caret byte offset: " + d.caretByteOffset + " / " + d.outputTotalLen);
        consoleLines.push("Char at caret: [" + (d.wideSnippet.atChar || "") + "]");
        consoleLines.push("");
        consoleLines.push("BEFORE (last 200 chars):");
        consoleLines.push(d.wideSnippet.before);
        consoleLines.push("");
        consoleLines.push("AFTER (next 200 chars):");
        consoleLines.push(d.wideSnippet.after);
        consoleLines.push("");
      }
    }
    consoleLines.push("");
    consoleLines.push("=== WARNINGS (" + report.warnings.length + ") ===");
    report.warnings.forEach((w, i) => {
      consoleLines.push("[" + (i + 1) + "] " + w);
      consoleLines.push("");
    });
    const consoleText = consoleLines.join("\n");
    reportConsole.textContent = consoleText;

    // Wire Copy all Ã¢â‚¬â€ copies raw warning list (what most users want)
    if (copyWarningsBtn && !copyWarningsBtn._wired) {
      copyWarningsBtn._wired = true;
      copyWarningsBtn.addEventListener("click", async () => {
        const text = report.warnings.map((w, i) => "[" + (i + 1) + "] " + w).join("\n\n");
        try {
          await navigator.clipboard.writeText(text);
          const orig = copyWarningsBtn.textContent;
          copyWarningsBtn.textContent = "Copied!";
          setTimeout(() => { copyWarningsBtn.textContent = orig; }, 1500);
        } catch (e) {
          copyWarningsBtn.textContent = "Copy failed";
        }
      });
    }

    // Wire console toggle
    if (toggleConsoleBtn && !toggleConsoleBtn._wired) {
      toggleConsoleBtn._wired = true;
      toggleConsoleBtn.addEventListener("click", () => {
        const hidden = reportConsole.classList.toggle("hidden");
        toggleConsoleBtn.textContent = hidden ? "Show console" : "Hide console";
      });
    }
  } else {
    warningsWrap.classList.add("hidden");
    if (warningsCount) warningsCount.textContent = "";
  }

  // Phase 2a: refresh override hints based on the new profile
  updateOverrideHints(report.profile);

  // Generated code preview (Prism)
  if (generatedCode) {
    // Limit rendering to first 30KB for perf; show truncation notice
    const MAX_SHOW = 30000;
    const shown = generatedCode.length > MAX_SHOW
      ? generatedCode.slice(0, MAX_SHOW) + "\n\n-- ... (truncated, " + (generatedCode.length - MAX_SHOW).toLocaleString() + " chars hidden. Use Copy button for full code) --"
      : generatedCode;
    reportCodeOutput.textContent = shown;
    viewCodeChars.textContent = "(" + generatedCode.length.toLocaleString() + " chars)";
    // Trigger Prism re-highlight
    if (window.Prism && window.Prism.highlightElement) {
      try { window.Prism.highlightElement(reportCodeOutput); } catch (e) {}
    }
  } else {
    reportCodeOutput.textContent = "-- No code available --";
    viewCodeChars.textContent = "";
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

closeReportBtn?.addEventListener("click", () => reportCard.classList.add("hidden"));

viewCodeToggle?.addEventListener("click", () => {
  viewCodeToggle.classList.toggle("open");
  viewCodeBody.classList.toggle("open");
});

copyReportCodeBtn?.addEventListener("click", async () => {
  if (!lastPreviewedCode) return;
  try {
    await navigator.clipboard.writeText(lastPreviewedCode);
    const original = copyReportCodeBtn.textContent;
    copyReportCodeBtn.textContent = "Copied!";
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

  abCompareBtn.disabled = true;
  const originalText = abCompareBtn.textContent;
  abCompareBtn.textContent = "Running " + alt + "...";

  try {
    const altResult = await obfuscateCode(code, alt, { forceMaximum: false });

    abCompareResult.classList.remove("hidden");
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
    abCompareBtn.disabled = false;
    abCompareBtn.textContent = originalText;
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

  previewBtn.disabled = true;
  const originalText = previewBtn.textContent;
  previewBtn.textContent = "Generating preview...";

  try {
    const result = await obfuscateCode(code, level, { forceMaximum });
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
    previewStats.textContent = statsText;

    // Prism-highlighted preview (limit for perf)
    const MAX_SHOW = 30000;
    const shown = result.code.length > MAX_SHOW
      ? result.code.slice(0, MAX_SHOW) + "\n\n-- ... (truncated) --"
      : result.code;
    previewOutput.textContent = shown;
    if (window.Prism && window.Prism.highlightElement) {
      try { window.Prism.highlightElement(previewOutput); } catch (e) {}
    }
    previewCard.classList.remove("hidden");

    // v16: Report card (render with generated code, close preview code section by default)
    renderReport(result.report, result.code);
    // Make sure the collapsible starts closed
    viewCodeToggle.classList.remove("open");
    viewCodeBody.classList.remove("open");

    reportCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    showMessage(`Preview ready. Check the report below, then click Save Script.`, "success");
  } catch (err) {
    showMessage(err.message || "Failed to preview.", "error");
  } finally {
    previewBtn.disabled = false;
    previewBtn.textContent = originalText;
    updateUI();
  }
});

closePreviewBtn.addEventListener("click", () => {
  previewCard.classList.add("hidden");
});

copyPreviewBtn.addEventListener("click", async () => {
  if (!lastPreviewedCode) return;
  try {
    await navigator.clipboard.writeText(lastPreviewedCode);
    const original = copyPreviewBtn.textContent;
    copyPreviewBtn.textContent = "Copied!";
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

  saveBtn.disabled = true;
  const originalText = saveBtn.textContent;

  try {
    let finalCode = code;
    let sizeInfo = "";
    let report = null;
    if (level !== "none") {
      saveBtn.textContent = "Obfuscating...";
      showMessage(`Obfuscating with level: ${level}${forceMaximum ? " (forced)" : ""}...`, "info");
      const result = await obfuscateCode(code, level, { forceMaximum });
      finalCode = result.code;
      report = result.report;
      lastPreviewedCode = result.code;
      lastReport = result.report;
      lastRequestedLevel = level;
      sizeInfo = ` (${result.originalSize.toLocaleString()} -> ${result.obfuscatedSize.toLocaleString()} chars)`;
    }

    saveBtn.textContent = "Saving...";
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
    loadstringOutput.textContent = loadstring;
    resultCard.classList.remove("hidden");

    // v16: Also render report if available
    if (report) {
      renderReport(report, finalCode);
      viewCodeToggle.classList.remove("open");
      viewCodeBody.classList.remove("open");
    }

    resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

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
    saveBtn.disabled = false;
    saveBtn.textContent = originalText;
    updateUI();
  }
});

copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(loadstringOutput.textContent);
    const originalText = copyBtn.textContent;
    copyBtn.textContent = "Copied!";
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

  keyScriptSelect.innerHTML = '<option value="">-- Select a script --</option>';
  (scripts || []).forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.id;
    const mode = s.key_required === false ? " [FREE]" : "";
    opt.textContent = `${s.name || "(unnamed)"} - ${s.id}${mode}`;
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
    keysList.innerHTML = '<p class="muted">Failed to load keys.</p>';
    return;
  }
  if (!keys || keys.length === 0) {
    keysList.innerHTML = '<p class="muted">No keys generated yet. Create one above.</p>';
    return;
  }
  keysList.innerHTML = keys.map((k) => renderKeyRow(k)).join("");
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

  generateKeyBtn.disabled = true;
  const original = generateKeyBtn.textContent;
  generateKeyBtn.textContent = "Creating...";
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
    generateKeyBtn.disabled = false;
    generateKeyBtn.textContent = original;
  }
});

// ============================================================================
// UTIL
// ============================================================================
function showMessage(text, type = "info") {
  messageDiv.textContent = text;
  messageDiv.className = `message message-${type}`;
  messageDiv.classList.remove("hidden");
}
function hideMessage() { messageDiv.classList.add("hidden"); }


// ============================================================================
// LARGE SCRIPT SECTION â€” separate pipeline for 300KB+ scripts
// ============================================================================
// Isolated wiring. All DOM ids are prefixed with "large*" to avoid collisions
// with the standard small-script pipeline above. Talks to /obfuscate-large,
// which uses a conservative transform pipeline (no full AST rewrite) so
// extreme Luau scripts don't cascade parse failures across stages.
// ============================================================================

const LARGE_OBFUSCATE_ENDPOINT = "/obfuscate-large";

// ---- DOM handles ----
const largeScriptNameInput = document.getElementById("largeScriptName");
const largeScriptCodeInput = document.getElementById("largeScriptCode");
const largeCharCountEl     = document.getElementById("largeCharCount");
const largeUploadBtn       = document.getElementById("largeUploadBtn");
const largeFileUpload      = document.getElementById("largeFileUpload");
const largeFileNameEl      = document.getElementById("largeFileName");
const largeClearBtn        = document.getElementById("largeClearBtn");
const largeLevelSelect     = document.getElementById("largeObfuscationLevel");
const largeRequireKeyCheck = document.getElementById("largeRequireKey");
const largePreviewBtn      = document.getElementById("largePreviewBtn");
const largeSaveBtn         = document.getElementById("largeSaveBtn");
const largeMessageDiv      = document.getElementById("largeMessage");
const largePreviewCard     = document.getElementById("largePreviewCard");
const largePreviewStats    = document.getElementById("largePreviewStats");
const largePreviewOutput   = document.getElementById("largePreviewOutput");
const largeCopyPreviewBtn  = document.getElementById("largeCopyPreviewBtn");
const largeClosePreviewBtn = document.getElementById("largeClosePreviewBtn");
const largeResultCard      = document.getElementById("largeResultCard");
const largeLoadstringOutput= document.getElementById("largeLoadstringOutput");
const largeCopyBtn         = document.getElementById("largeCopyBtn");

let largeLastPreviewedCode = "";
let largeLastSavedScriptId = null;

// ---- Message helpers (scoped to the large-script card) ----
function showLargeMessage(text, type) {
  if (!largeMessageDiv) return;
  largeMessageDiv.textContent = text;
  largeMessageDiv.className = "message message-" + (type || "info");
  largeMessageDiv.classList.remove("hidden");
}
function hideLargeMessage() {
  if (largeMessageDiv) largeMessageDiv.classList.add("hidden");
}

// ---- UI state (enable/disable buttons based on code presence) ----
function updateLargeUI() {
  if (!largeScriptCodeInput) return;
  const len = largeScriptCodeInput.value.length;
  if (largeCharCountEl) largeCharCountEl.textContent = len.toLocaleString() + " characters";
  const hasCode = len > 0;
  if (largePreviewBtn) largePreviewBtn.disabled = !hasCode;
  if (largeSaveBtn)    largeSaveBtn.disabled    = !hasCode;
}
largeScriptCodeInput?.addEventListener("input", updateLargeUI);

// ---- File upload (10MB cap, .lua/.txt only) ----
largeUploadBtn?.addEventListener("click", () => largeFileUpload?.click());
largeFileUpload?.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > MAX_SCRIPT_SIZE) {
    showLargeMessage("File too large. Max 10MB.", "error");
    return;
  }
  const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
  if (![".lua", ".txt"].includes(ext)) {
    showLargeMessage("Only .lua or .txt files allowed.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = (ev) => {
    largeScriptCodeInput.value = ev.target.result;
    largeFileNameEl.textContent = "Loaded: " + file.name;
    if (!largeScriptNameInput.value.trim()) {
      largeScriptNameInput.value = file.name.replace(/\.(lua|txt)$/i, "");
    }
    updateLargeUI();
    showLargeMessage("Loaded \"" + file.name + "\" (" +
                     ev.target.result.length.toLocaleString() + " chars)", "success");
  };
  reader.onerror = () => showLargeMessage("Failed to read file.", "error");
  reader.readAsText(file);
});

// ---- Clear button ----
largeClearBtn?.addEventListener("click", () => {
  if (!largeScriptCodeInput.value && !largeScriptNameInput.value) return;
  if (!confirm("Clear the large script editor?")) return;
  largeScriptNameInput.value = "";
  largeScriptCodeInput.value = "";
  largeFileNameEl.textContent = "";
  largeFileUpload.value = "";
  hideLargeMessage();
  largePreviewCard?.classList.add("hidden");
  largeResultCard?.classList.add("hidden");
  updateLargeUI();
});

// ---- Obfuscation call (large pipeline) ----
async function obfuscateLarge(code, level) {
  const response = await fetch(LARGE_OBFUSCATE_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code, level,
      userId: currentUser ? currentUser.id : null,
    }),
  });

  // The large endpoint is a separate backend route; if the server hasn't been
  // updated yet, surface a clear message instead of a raw 404.
  if (response.status === 404) {
    throw new Error("Large-script endpoint not yet deployed on the server. Ask the backend to add /obfuscate-large.");
  }
  if (!response.ok) {
    let errMsg = "Large obfuscation failed";
    try { const data = await response.json(); errMsg = data.error || errMsg; } catch (e) {}
    throw new Error(errMsg);
  }
  const data = await response.json();
  if (!data.success || !data.code) throw new Error(data.error || "Large obfuscation returned no code");
  return {
    code: data.code,
    elapsed: data.elapsed_ms,
    originalSize: data.original_size,
    obfuscatedSize: data.obfuscated_size,
    profile: data.profile || null,   // e.g. "basic"|"medium"|"conservative-max"
  };
}

// ---- Preview button ----
largePreviewBtn?.addEventListener("click", async () => {
  const code = largeScriptCodeInput.value;
  if (!code) return;
  const level = largeLevelSelect ? largeLevelSelect.value : "medium";

  largePreviewBtn.disabled = true;
  const originalLabel = largePreviewBtn.textContent;
  largePreviewBtn.textContent = "Obfuscating...";
  hideLargeMessage();

  try {
    const result = await obfuscateLarge(code, level);
    largeLastPreviewedCode = result.code;

    const ratio = result.originalSize > 0
      ? (result.obfuscatedSize / result.originalSize)
      : 0;
    largePreviewStats.textContent =
      "Profile: " + (result.profile || level) + " | " +
      result.originalSize.toLocaleString() + " -> " +
      result.obfuscatedSize.toLocaleString() + " chars (" +
      ratio.toFixed(2) + "x) | " +
      (result.elapsed || 0) + "ms";
    largePreviewOutput.textContent = result.code;
    largePreviewCard.classList.remove("hidden");
    showLargeMessage("Preview ready.", "success");
  } catch (err) {
    showLargeMessage(err.message, "error");
  } finally {
    largePreviewBtn.disabled = false;
    largePreviewBtn.textContent = originalLabel;
  }
});

// ---- Copy preview ----
largeCopyPreviewBtn?.addEventListener("click", async () => {
  if (!largeLastPreviewedCode) return;
  try {
    await navigator.clipboard.writeText(largeLastPreviewedCode);
    const orig = largeCopyPreviewBtn.textContent;
    largeCopyPreviewBtn.textContent = "Copied!";
    setTimeout(() => { largeCopyPreviewBtn.textContent = orig; }, 1500);
  } catch (e) {
    showLargeMessage("Copy failed: " + e.message, "error");
  }
});

// ---- Close preview ----
largeClosePreviewBtn?.addEventListener("click", () => {
  largePreviewCard?.classList.add("hidden");
});

// ---- Save button â€” mirrors the small-script pattern (code stored in the row, no Storage upload) ----
largeSaveBtn?.addEventListener("click", async () => {
  const code = largeScriptCodeInput.value;
  const name = largeScriptNameInput.value.trim();
  if (!code) return;
  if (!name) {
    showLargeMessage("Please enter a script name.", "error");
    return;
  }

  const level = largeLevelSelect ? largeLevelSelect.value : "medium";
  const requireKey = !!(largeRequireKeyCheck && largeRequireKeyCheck.checked);

  largeSaveBtn.disabled = true;
  const originalLabel = largeSaveBtn.textContent;
  largeSaveBtn.textContent = "Obfuscating & saving...";
  hideLargeMessage();

  try {
    const result = await obfuscateLarge(code, level);
    const finalCode = result.code;

    // Retry on ID collision (up to 5 attempts) â€” same pattern as small path
    let scriptId = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = generateId(8);
      const { error } = await sb.from("scripts").insert({
        id,
        user_id: currentUser.id,
        name: name || null,
        code: finalCode,
        key_required: requireKey,
      });
      if (!error) { scriptId = id; break; }
      if (error.code !== "23505") throw new Error("DB insert failed: " + error.message);
    }
    if (!scriptId) throw new Error("Could not generate a unique ID. Try again.");

    largeLastSavedScriptId = scriptId;

    // Build loadstring (same helpers as small path)
    let loadstr;
    if (requireKey) {
      const key = generateLicenseKey();
      const { error: keyErr } = await sb.from("user_keys").insert({
        key, script_id: scriptId, owner_id: currentUser.id,
      });
      if (keyErr) throw new Error("Key insert failed: " + keyErr.message);
      loadstr = buildProtectedLoadstring(scriptId, key);
    } else {
      loadstr = buildLoadstring(scriptId);
    }

    largeLoadstringOutput.textContent = loadstr;
    largeResultCard.classList.remove("hidden");
    showLargeMessage("Saved large script \"" + name + "\" (" +
                     finalCode.length.toLocaleString() + " chars).", "success");
  } catch (err) {
    showLargeMessage(err.message, "error");
  } finally {
    largeSaveBtn.disabled = false;
    largeSaveBtn.textContent = originalLabel;
  }
});

// ---- Copy loadstring ----
largeCopyBtn?.addEventListener("click", async () => {
  const text = largeLoadstringOutput.textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const orig = largeCopyBtn.textContent;
    largeCopyBtn.textContent = "Copied!";
    setTimeout(() => { largeCopyBtn.textContent = orig; }, 1500);
  } catch (e) {
    showLargeMessage("Copy failed: " + e.message, "error");
  }
});

// Initial UI state
updateLargeUI();
