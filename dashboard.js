// ==========================================
// Dashboard - Script Editor Logic
// ==========================================

// ---------- CONFIG ----------
// Edge Function URL that serves the raw Lua script for Roblox game:HttpGet()
const RAW_ENDPOINT =
  "https://uwxsgijolhlpnihdelrq.supabase.co/functions/v1/raw";

// ---------- DOM elements ----------
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
const messageDiv = document.getElementById("message");

const resultCard = document.getElementById("resultCard");
const loadstringOutput = document.getElementById("loadstringOutput");
const copyBtn = document.getElementById("copyBtn");

// ---------- Store current user ----------
let currentUser = null;

// ---------- Init ----------
(async function init() {
  await handleOAuthCallback();
  const user = await requireAuth();
  if (!user) return;

  currentUser = user;
  if (userEmailEl) userEmailEl.textContent = user.email;
})();

// ---------- Logout ----------
logoutBtn?.addEventListener("click", async () => {
  logoutBtn.disabled = true;
  logoutBtn.textContent = "Logging out...";

  try {
    await sb.auth.signOut();
  } catch (err) {
    console.error(err);
  } finally {
    window.location.href = "index.html";
  }
});

// ---------- Character counter + enable/disable Save button ----------
function updateUI() {
  const len = scriptCodeInput.value.length;
  charCountEl.textContent = `${len.toLocaleString()} characters`;
  saveBtn.disabled = len === 0;
}

scriptCodeInput.addEventListener("input", updateUI);

// ---------- File upload ----------
uploadBtn.addEventListener("click", () => {
  fileUpload.click();
});

fileUpload.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;

  if (file.size > 1024 * 1024) {
    showMessage("File too large. Max 1MB.", "error");
    return;
  }

  const allowedTypes = [".lua", ".txt"];
  const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
  if (!allowedTypes.includes(ext)) {
    showMessage("Only .lua or .txt files allowed.", "error");
    return;
  }

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
  reader.onerror = () => {
    showMessage("Failed to read file.", "error");
  };
  reader.readAsText(file);
});

// ---------- Clear button ----------
clearBtn.addEventListener("click", () => {
  if (!scriptCodeInput.value && !scriptNameInput.value) return;

  if (confirm("Clear the script editor?")) {
    scriptNameInput.value = "";
    scriptCodeInput.value = "";
    fileNameEl.textContent = "";
    fileUpload.value = "";
    hideMessage();
    resultCard.classList.add("hidden");
    updateUI();
  }
});

// ---------- Generate short random ID ----------
function generateId(length = 8) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id = "";
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    id += chars[array[i] % chars.length];
  }
  return id;
}

// ---------- Build loadstring using Edge Function URL ----------
function buildLoadstring(scriptId) {
  const rawUrl = `${RAW_ENDPOINT}?id=${scriptId}`;
  return `loadstring(game:HttpGet("${rawUrl}"))()`;
}

// ---------- Save script ----------
saveBtn.addEventListener("click", async () => {
  const name = scriptNameInput.value.trim();
  const code = scriptCodeInput.value;

  hideMessage();

  if (!code.trim()) {
    showMessage("Wala kang na-paste na code.", "error");
    return;
  }

  if (code.length > 500000) {
    showMessage("Script too long. Max 500,000 characters.", "error");
    return;
  }

  saveBtn.disabled = true;
  const originalText = saveBtn.textContent;
  saveBtn.textContent = "Saving...";

  try {
    let scriptId = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const id = generateId(8);
      const { error } = await sb.from("scripts").insert({
        id,
        user_id: currentUser.id,
        name: name || null,
        code,
      });

      if (!error) {
        scriptId = id;
        break;
      }

      if (error.code !== "23505") {
        throw error;
      }
    }

    if (!scriptId) {
      throw new Error("Could not generate a unique ID. Try again.");
    }

    const loadstring = buildLoadstring(scriptId);

    loadstringOutput.textContent = loadstring;
    resultCard.classList.remove("hidden");
    resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

    showMessage(`Script saved! ID: ${scriptId}`, "success");
  } catch (err) {
    console.error(err);
    showMessage(err.message || "Failed to save script.", "error");
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = originalText;
    updateUI();
  }
});

// ---------- Copy loadstring ----------
copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(loadstringOutput.textContent);
    const originalText = copyBtn.textContent;
    copyBtn.textContent = "Copied!";
    setTimeout(() => {
      copyBtn.textContent = originalText;
    }, 1500);
  } catch (err) {
    showMessage("Failed to copy. Select and copy manually.", "error");
  }
});

// ---------- Message helpers ----------
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
