async function handleOAuthCallback() {
  const hasHash =
    window.location.hash.includes("access_token") ||
    window.location.hash.includes("error");
  const hasCode = window.location.search.includes("code=");
  if (!hasHash && !hasCode) return;

  await new Promise((resolve) => {
    let done = false;
    const {
      data: { subscription },
    } = sb.auth.onAuthStateChange((event, session) => {
      if (session && !done) {
        done = true;
        subscription.unsubscribe();
        history.replaceState(null, "", window.location.pathname);
        resolve();
      }
    });
    setTimeout(() => {
      if (!done) {
        done = true;
        subscription.unsubscribe();
        resolve();
      }
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
const clearBtn = document.getElementById("clearBtn");
const saveBtn = document.getElementById("saveBtn");
const previewBtn = document.getElementById("previewBtn");
const messageDiv = document.getElementById("message");
const obfuscationLevelSelect = document.getElementById("obfuscationLevel");

// NEW: Key requirement toggle
const requireKeyCheckbox = document.getElementById("requireKey");

const previewCard = document.getElementById("previewCard");
const previewStats = document.getElementById("previewStats");
const previewOutput = document.getElementById("previewOutput");
const closePreviewBtn = document.getElementById("closePreviewBtn");
const copyPreviewBtn = document.getElementById("copyPreviewBtn");

const resultCard = document.getElementById("resultCard");
const loadstringOutput = document.getElementById("loadstringOutput");
const copyBtn = document.getElementById("copyBtn");

// Key management elements
const keysCard = document.getElementById("keysCard");
const keysList = document.getElementById("keysList");
const generateKeyBtn = document.getElementById("generateKeyBtn");
const keyScriptSelect = document.getElementById("keyScriptSelect");
const keyPlaceIdsInput = document.getElementById("keyPlaceIds");
const keyMaxExecInput = document.getElementById("keyMaxExec");
const keyExpiresInput = document.getElementById("keyExpires");

let currentUser = null;
let lastPreviewedCode = "";
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

// FREE loadstring (no key)
function buildLoadstring(scriptId) {
  const rawUrl = `${window.location.origin}/s/${scriptId}`;
  return `loadstring(game:HttpGet("${rawUrl}"))()`;
}

// PROTECTED loadstring (with key + HWID + PlaceId)
function buildProtectedLoadstring(scriptId, key) {
  const baseUrl = `${window.location.origin}/s/${scriptId}`;
  return `local _k="${key}"
local _h=game:GetService("RbxAnalyticsService"):GetClientId()
local _p=tostring(game.PlaceId)
loadstring(game:HttpGet("${baseUrl}?key=".._k.."&hwid=".._h.."&place=".._p))()`;
}

async function obfuscateCode(code, level) {
  if (level === "none") {
    return { code, elapsed: 0, originalSize: code.length, obfuscatedSize: code.length };
  }
  const response = await fetch(OBFUSCATE_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, level }),
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
  };
}

previewBtn.addEventListener("click", async () => {
  const code = scriptCodeInput.value;
  const level = obfuscationLevelSelect.value;
  hideMessage();
  if (!code.trim()) { showMessage("Wala kang na-paste na code.", "error"); return; }
  if (code.length > MAX_SCRIPT_SIZE) { showMessage("Script too long. Max 10MB.", "error"); return; }

  previewBtn.disabled = true;
  const originalText = previewBtn.textContent;
  previewBtn.textContent = "Generating preview...";

  try {
    const result = await obfuscateCode(code, level);
    lastPreviewedCode = result.code;
    const ratio = result.obfuscatedSize / result.originalSize;
    const ratioStr = ratio.toFixed(2);
    const statsText = level === "none"
      ? `Level: none | ${result.originalSize.toLocaleString()} chars (no changes)`
      : `Level: ${level} | ${result.originalSize.toLocaleString()} chars -> ${result.obfuscatedSize.toLocaleString()} chars (${ratioStr}x) | Generated in ${result.elapsed}ms`;
    previewStats.textContent = statsText;
    previewOutput.textContent = result.code;
    previewCard.classList.remove("hidden");
    previewCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    showMessage(`Preview ready. Review below, then click Save Script.`, "success");
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
  lastPreviewedCode = "";
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

saveBtn.addEventListener("click", async () => {
  const name = scriptNameInput.value.trim();
  const code = scriptCodeInput.value;
  const level = obfuscationLevelSelect ? obfuscationLevelSelect.value : "none";
  // NEW: read the checkbox
  const requireKey = requireKeyCheckbox ? requireKeyCheckbox.checked : true;

  hideMessage();
  if (!code.trim()) { showMessage("Wala kang na-paste na code.", "error"); return; }
  if (code.length > MAX_SCRIPT_SIZE) { showMessage("Script too long. Max 10MB.", "error"); return; }

  saveBtn.disabled = true;
  const originalText = saveBtn.textContent;

  try {
    let finalCode = code;
    let sizeInfo = "";
    if (level !== "none") {
      saveBtn.textContent = "Obfuscating...";
      showMessage(`Obfuscating with level: ${level}...`, "info");
      const result = await obfuscateCode(code, level);
      finalCode = result.code;
      sizeInfo = ` (${result.originalSize.toLocaleString()} -> ${result.obfuscatedSize.toLocaleString()} chars)`;
    }

    saveBtn.textContent = "Saving...";
    showMessage("Saving to database...", "info");

    let scriptId = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = generateId(8);
      // NEW: save key_required flag with the script
      const { error } = await sb.from("scripts").insert({
        id,
        user_id: currentUser.id,
        name: name || null,
        code: finalCode,
        key_required: requireKey,
      });
      if (!error) { scriptId = id; break; }
      if (error.code !== "23505") throw error;
    }

    if (!scriptId) throw new Error("Could not generate a unique ID. Try again.");

    lastSavedScriptId = scriptId;
    // NEW: show the RIGHT loader based on protection mode
    const loadstring = buildLoadstring(scriptId);
    loadstringOutput.textContent = loadstring;
    resultCard.classList.remove("hidden");
    resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

    const modeInfo = requireKey
      ? ` Generate a key below to enable protection.`
      : ` Script is FREE (no key required) - anyone can run this loadstring.`;
    showMessage(
      `Script saved! ID: ${scriptId} | Level: ${level}${sizeInfo}.${modeInfo}`,
      "success",
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
// KEY MANAGEMENT (unchanged from previous version)
// ============================================================================

async function refreshScriptOptions() {
  if (!keyScriptSelect) return;
  const { data: scripts, error } = await sb
    .from("scripts")
    .select("id, name, created_at, key_required")
    .eq("user_id", currentUser.id)
    .order("created_at", { ascending: false });
  if (error) { console.error("Failed to load scripts:", error); return; }

  keyScriptSelect.innerHTML = '<option value="">-- Select a script --</option>';
  (scripts || []).forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.id;
    const mode = s.key_required === false ? " [FREE]" : "";
    opt.textContent = `${s.name || "(unnamed)"} - ${s.id}${mode}`;
    if (s.key_required === false) opt.disabled = true; // can't generate key for free script
    keyScriptSelect.appendChild(opt);
  });

  if (lastSavedScriptId) keyScriptSelect.value = lastSavedScriptId;
}

async function loadUserKeys() {
  if (!keysList) return;
  await refreshScriptOptions();

  const { data: keys, error } = await sb
    .from("user_keys")
    .select("*, scripts(name)")
    .eq("owner_id", currentUser.id)
    .order("created_at", { ascending: false });

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
      <div class="key-header">
        <code class="key-value">${k.key}</code>
        ${status}
      </div>
      <div class="key-details">
        <div><strong>Script:</strong> ${scriptName} (${k.script_id})</div>
        <div><strong>HWID:</strong> ${hwidInfo}</div>
        <div><strong>Allowed PlaceIds:</strong> ${placeIds}</div>
        <div><strong>Executions:</strong> ${execInfo}</div>
        <div><strong>Expires:</strong> ${expiresInfo}</div>
      </div>
      <div class="key-actions">
        <button data-action="copy-loader" data-key="${k.key}" data-script="${k.script_id}">Copy Loader</button>
        <button data-action="reset-hwid" data-key="${k.key}" ${!k.hwid ? "disabled" : ""}>Reset HWID</button>
        ${k.revoked
          ? `<button data-action="unrevoke" data-key="${k.key}">Unrevoke</button>`
          : `<button data-action="revoke" data-key="${k.key}" class="danger">Kill (Revoke)</button>`}
        <button data-action="delete" data-key="${k.key}" class="danger">Delete</button>
      </div>
    </div>
  `;
}

async function handleKeyAction(e) {
  const btn = e.currentTarget;
  const action = btn.dataset.action;
  const key = btn.dataset.key;
  const scriptId = btn.dataset.script;

  try {
    btn.disabled = true;
    switch (action) {
      case "copy-loader": {
        const loader = buildProtectedLoadstring(scriptId, key);
        await navigator.clipboard.writeText(loader);
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = orig), 1500);
        break;
      }
      case "reset-hwid": {
        if (!confirm("Reset HWID for this key? User can rebind on next use.")) break;
        const { error } = await sb.from("user_keys").update({ hwid: null, first_used_at: null })
          .eq("key", key).eq("owner_id", currentUser.id);
        if (error) throw error;
        showMessage("HWID reset. User can now rebind.", "success");
        await loadUserKeys();
        break;
      }
      case "revoke": {
        if (!confirm("KILL this key? Script will stop working for the user immediately.")) break;
        const { error } = await sb.from("user_keys").update({ revoked: true })
          .eq("key", key).eq("owner_id", currentUser.id);
        if (error) throw error;
        showMessage("Key revoked (kill switch activated).", "success");
        await loadUserKeys();
        break;
      }
      case "unrevoke": {
        const { error } = await sb.from("user_keys").update({ revoked: false })
          .eq("key", key).eq("owner_id", currentUser.id);
        if (error) throw error;
        showMessage("Key unrevoked.", "success");
        await loadUserKeys();
        break;
      }
      case "delete": {
        if (!confirm("PERMANENTLY delete this key? Cannot be undone.")) break;
        const { error } = await sb.from("user_keys").delete()
          .eq("key", key).eq("owner_id", currentUser.id);
        if (error) throw error;
        showMessage("Key deleted.", "success");
        await loadUserKeys();
        break;
      }
    }
  } catch (err) {
    showMessage(err.message || "Action failed.", "error");
  } finally {
    btn.disabled = false;
  }
}

generateKeyBtn?.addEventListener("click", async () => {
  hideMessage();
  const scriptId = keyScriptSelect?.value;
  if (!scriptId) { showMessage("Select a script first.", "error"); return; }

  let placeIds = null;
  const placeIdsRaw = (keyPlaceIdsInput?.value || "").trim();
  if (placeIdsRaw) {
    placeIds = placeIdsRaw.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n) && n > 0);
    if (placeIds.length === 0) placeIds = null;
  }

  const maxExec = parseInt(keyMaxExecInput?.value || "", 10);
  const maxExecutions = !isNaN(maxExec) && maxExec > 0 ? maxExec : null;

  const expiresRaw = keyExpiresInput?.value || "";
  const expiresAt = expiresRaw ? new Date(expiresRaw).toISOString() : null;

  generateKeyBtn.disabled = true;
  const orig = generateKeyBtn.textContent;
  generateKeyBtn.textContent = "Generating...";

  try {
    const key = generateLicenseKey();
    const { error } = await sb.from("user_keys").insert({
      key,
      owner_id: currentUser.id,
      script_id: scriptId,
      place_id_whitelist: placeIds,
      max_executions: maxExecutions,
      expires_at: expiresAt,
    });
    if (error) throw error;
    showMessage(`Key generated: ${key}`, "success");
    if (keyPlaceIdsInput) keyPlaceIdsInput.value = "";
    if (keyMaxExecInput) keyMaxExecInput.value = "";
    if (keyExpiresInput) keyExpiresInput.value = "";
    await loadUserKeys();
  } catch (err) {
    showMessage(err.message || "Failed to generate key.", "error");
  } finally {
    generateKeyBtn.disabled = false;
    generateKeyBtn.textContent = orig;
  }
});

function showMessage(text, type = "info") {
  messageDiv.textContent = text;
  messageDiv.className = `message ${type}`;
  messageDiv.classList.remove("hidden");
}
function hideMessage() {
  messageDiv.classList.add("hidden");
  messageDiv.textContent = "";
}

updateUI();
