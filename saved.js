// ==========================================
// Saved Scripts Page Logic - PROXY v5
// Uses /s/:id proxy route on Render (hides Supabase URL)
// ==========================================

// ---------- DOM elements ----------
const userEmailEl = document.getElementById("userEmail");
const logoutBtn = document.getElementById("logoutBtn");

const searchInput = document.getElementById("searchInput");
const loadingState = document.getElementById("loadingState");
const emptyState = document.getElementById("emptyState");
const scriptList = document.getElementById("scriptList");

// Edit modal elements
const editModal = document.getElementById("editModal");
const closeModalBtn = document.getElementById("closeModalBtn");
const cancelEditBtn = document.getElementById("cancelEditBtn");
const saveEditBtn = document.getElementById("saveEditBtn");
const editName = document.getElementById("editName");
const editCode = document.getElementById("editCode");
const editCharCount = document.getElementById("editCharCount");
const editMessage = document.getElementById("editMessage");
const notificationContainer =
  document.getElementById("notificationContainer") ||
  createNotificationContainer();

// ---------- State ----------
let currentUser = null;
let allScripts = [];
let editingScriptId = null;

function createNotificationContainer() {
  const container = document.createElement("div");
  container.id = "notificationContainer";
  container.className = "notification-container";
  container.setAttribute("aria-live", "polite");
  container.setAttribute("aria-atomic", "true");
  document.body.appendChild(container);
  return container;
}

function showNotification(text, type = "info", duration = 4200) {
  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.setAttribute("role", "status");

  const message = document.createElement("span");
  message.textContent = text;
  notification.appendChild(message);

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "notification-close";
  closeBtn.innerHTML = "&times;";
  closeBtn.addEventListener("click", () => removeNotification(notification));
  notification.appendChild(closeBtn);

  notificationContainer.appendChild(notification);

  requestAnimationFrame(() => notification.classList.add("visible"));

  const timeoutId = setTimeout(
    () => removeNotification(notification),
    duration,
  );
  notification.dataset.timeoutId = timeoutId.toString();
}

function removeNotification(notification) {
  if (!notification || !notification.parentElement) return;
  const timeoutId = Number(notification.dataset.timeoutId);
  if (timeoutId) clearTimeout(timeoutId);
  notification.classList.remove("visible");
  notification.addEventListener(
    "transitionend",
    () => {
      if (notification.parentElement) notification.remove();
    },
    { once: true },
  );
}

// ---------- Init ----------
(async function init() {
  const user = await requireAuth();
  if (!user) return;

  currentUser = user;
  if (userEmailEl) userEmailEl.textContent = user.email;

  await loadScripts();
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

// ---------- Build loadstring using PROXY URL (hides Supabase) ----------
function buildLoadstring(scriptId) {
  // Uses current origin so it works on localhost AND production
  // production: https://azurehub.onrender.com/s/xxx
  const rawUrl = `${window.location.origin}/s/${scriptId}`;
  return `loadstring(game:HttpGet("${rawUrl}"))()`;
}

// ---------- Load scripts (FILTERED by current user only) ----------
async function loadScripts() {
  loadingState.classList.remove("hidden");
  emptyState.classList.add("hidden");
  scriptList.classList.add("hidden");

  try {
    const { data, error } = await sb
      .from("scripts")
      .select("id, name, code, views, created_at, updated_at, user_id")
      .eq("user_id", currentUser.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    allScripts = data || [];
    renderScripts(allScripts);
  } catch (err) {
    console.error(err);
    loadingState.innerHTML = `<p style="color: var(--error)">Failed to load scripts: ${escapeHtml(err.message)}</p>`;
  }
}

// ---------- Render scripts ----------
function renderScripts(scripts) {
  loadingState.classList.add("hidden");

  if (scripts.length === 0) {
    emptyState.classList.remove("hidden");
    scriptList.classList.add("hidden");
    return;
  }

  emptyState.classList.add("hidden");
  scriptList.classList.remove("hidden");
  scriptList.innerHTML = "";

  scripts.forEach((script) => {
    const item = document.createElement("div");
    item.className = "script-item";

    const displayName = script.name || "(Untitled)";
    const codePreview =
      script.code.length > 60
        ? script.code.substring(0, 60) + "..."
        : script.code;
    const dateStr = formatDate(script.created_at);
    const updatedStr =
      script.updated_at !== script.created_at
        ? ` · edited ${formatDate(script.updated_at)}`
        : "";

    item.innerHTML = `
      <div class="info">
        <div class="name">${escapeHtml(displayName)}</div>
        <div class="meta">
          <code style="color: var(--accent); font-size: 0.75rem">${script.id}</code>
          · ${script.code.length.toLocaleString()} chars
          · ${script.views} views
          · ${dateStr}${updatedStr}
        </div>
        <div class="meta" style="margin-top: 4px; font-family: monospace; opacity: 0.6">
          ${escapeHtml(codePreview)}
        </div>
      </div>
      <div class="actions">
        <button type="button" class="secondary small" data-action="copy" data-id="${script.id}">Copy Loadstring</button>
        <button type="button" class="secondary small" data-action="edit" data-id="${script.id}">Edit</button>
        <button type="button" class="danger small" data-action="delete" data-id="${script.id}">Delete</button>
      </div>
    `;

    scriptList.appendChild(item);
  });
}

// ---------- Handle script action clicks (event delegation) ----------
scriptList.addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;

  const action = btn.dataset.action;
  const id = btn.dataset.id;
  const script = allScripts.find((s) => s.id === id);
  if (!script) return;

  // SECURITY: verify ownership before edit/delete
  if (
    (action === "edit" || action === "delete") &&
    script.user_id !== currentUser.id
  ) {
    showNotification("You can only modify your own scripts.", "error");
    return;
  }

  if (action === "copy") {
    await copyLoadstring(script, btn);
  } else if (action === "edit") {
    openEditModal(script);
  } else if (action === "delete") {
    await deleteScript(script);
  }
});

// ---------- Copy loadstring ----------
async function copyLoadstring(script, btn) {
  const loadstring = buildLoadstring(script.id);

  try {
    await navigator.clipboard.writeText(loadstring);
    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = original), 1500);
  } catch (err) {
    showNotification(
      `Failed to copy automatically. Manual copy: ${loadstring}`,
      "error",
    );
    console.warn("Manual loadstring:", loadstring);
  }
}

// ---------- Delete script (with owner check) ----------
async function deleteScript(script) {
  if (script.user_id !== currentUser.id) {
    showNotification("You can only delete your own scripts.", "error");
    return;
  }

  const name = script.name || "(Untitled)";
  if (!confirm(`Delete "${name}"? Can't undone after this..`)) return;

  try {
    const { error } = await sb
      .from("scripts")
      .delete()
      .eq("id", script.id)
      .eq("user_id", currentUser.id);

    if (error) throw error;

    allScripts = allScripts.filter((s) => s.id !== script.id);
    applySearch();
    showNotification(`Deleted "${name}"`, "success");
  } catch (err) {
    showNotification(`Failed to delete: ${err.message}`, "error");
  }
}

// ---------- Edit modal (with owner check) ----------
function openEditModal(script) {
  if (script.user_id !== currentUser.id) {
    showNotification("You can only edit your own scripts.", "error");
    return;
  }

  editingScriptId = script.id;
  editName.value = script.name || "";
  editCode.value = script.code;
  updateEditCharCount();
  hideEditMessage();
  editModal.classList.remove("hidden");
  editCode.focus();
}

function closeEditModal() {
  editModal.classList.add("hidden");
  editingScriptId = null;
  editName.value = "";
  editCode.value = "";
  hideEditMessage();
}

closeModalBtn.addEventListener("click", closeEditModal);
cancelEditBtn.addEventListener("click", closeEditModal);

editModal.addEventListener("click", (e) => {
  if (e.target === editModal) closeEditModal();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !editModal.classList.contains("hidden")) {
    closeEditModal();
  }
});

editCode.addEventListener("input", updateEditCharCount);

function updateEditCharCount() {
  editCharCount.textContent = `${editCode.value.length.toLocaleString()} characters`;
}

// Save edit
saveEditBtn.addEventListener("click", async () => {
  const name = editName.value.trim();
  const code = editCode.value;

  hideEditMessage();

  if (!code.trim()) {
    showEditMessage("Wala kang code.", "error");
    return;
  }

  if (code.length > 500000) {
    showEditMessage("Script too long (max 500,000 chars).", "error");
    return;
  }

  saveEditBtn.disabled = true;
  const originalText = saveEditBtn.textContent;
  saveEditBtn.textContent = "Saving...";

  try {
    const { error } = await sb
      .from("scripts")
      .update({ name: name || null, code })
      .eq("id", editingScriptId)
      .eq("user_id", currentUser.id);

    if (error) throw error;

    const script = allScripts.find((s) => s.id === editingScriptId);
    if (script) {
      script.name = name || null;
      script.code = code;
      script.updated_at = new Date().toISOString();
    }

    showEditMessage("Saved!", "success");
    setTimeout(() => {
      closeEditModal();
      applySearch();
    }, 600);
  } catch (err) {
    showEditMessage("Failed to save: " + err.message, "error");
  } finally {
    saveEditBtn.disabled = false;
    saveEditBtn.textContent = originalText;
  }
});

// ---------- Search ----------
searchInput.addEventListener("input", applySearch);

function applySearch() {
  const query = searchInput.value.trim().toLowerCase();
  if (!query) {
    renderScripts(allScripts);
    return;
  }
  const filtered = allScripts.filter((s) => {
    const name = (s.name || "").toLowerCase();
    return name.includes(query) || s.id.toLowerCase().includes(query);
  });
  renderScripts(filtered);
}

// ---------- Helpers ----------
function showEditMessage(text, type = "info") {
  editMessage.textContent = text;
  editMessage.className = `message ${type}`;
  editMessage.classList.remove("hidden");
}

function hideEditMessage() {
  editMessage.classList.add("hidden");
  editMessage.textContent = "";
}

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now - d;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
}
