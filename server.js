// ============================================================================
// server.js PATCH v1 â€” adds "nightmare" level to /obfuscate-large whitelist
//
// FIX: The /obfuscate-large endpoint had a hardcoded validLevels whitelist
//      that silently downgraded any unknown level to "medium". This meant
//      requests for the new 10-layer "nightmare" pipeline were being
//      rewritten to 8-layer conservative-max defaults on the server.
//
// CHANGE: Line ~145 (inside app.post("/obfuscate-large")):
//   OLD: const validLevels = ["basic", "medium", "conservative-max"];
//   NEW: const validLevels = ["basic", "medium", "conservative-max", "nightmare"];
//
// Drop-in replacement â€” rename to server.js when using.
// ============================================================================

const express = require("express");
const path = require("path");
const https = require("https");
const { createClient } = require("@supabase/supabase-js");
// obfuscateWithReport accepts options.referenceCode for the manifest.
const { obfuscate, obfuscateWithReport } = require("./obfuscator");
// Large-script pipeline (separate module, text-level transforms, no AST parse)
const { obfuscateLarge } = require("./obfuscator-large");

const app = express();
const PORT = process.env.PORT || 10000;

// ---------------------------------------------------------------------------
// Security hardening:
//   * SUPABASE_URL is required via env, no hardcoded fallback.
//   * HWID validated against a strict character whitelist to prevent
//     injection of weird Unicode / SQL-like chars into the DB.
//   * Rate limit falls back to IP when HWID is missing so an attacker
//     cannot bypass throttling by simply omitting the &hwid= param.
// ---------------------------------------------------------------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
if (!SUPABASE_URL) {
  console.error("[FATAL] SUPABASE_URL env var is required. Aborting startup.");
  process.exit(1);
}
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_SERVICE_KEY) {
  console.warn("[WARN] SUPABASE_SERVICE_KEY not set - key validation will fail!");
}

const supabase = SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

// Derive the raw-fetch endpoint from SUPABASE_URL so we never hardcode
// project refs. Trailing slash is normalized so both forms of the env var work.
const SUPABASE_RAW_URL =
  SUPABASE_URL.replace(/\/+$/, "") + "/functions/v1/raw";

// HWID must be alphanumeric + dash/underscore, 8-128 chars. Anything else
// gets rejected before it can touch the DB.
const HWID_PATTERN = /^[a-zA-Z0-9_-]{8,128}$/;

// 24 MB limit accommodates primary code + reference file
app.use(express.json({ limit: "24mb" }));
app.use(express.static(path.join(__dirname), { extensions: ["html"] }));

// ==========================================
// /obfuscate â€” standard pipeline (small/medium scripts)
// Body: { code, level, forceMaximum?, userId?, referenceCode?, layerOverrides? }
// Response: { success, level, original_size, obfuscated_size, elapsed_ms, code, report }
// ==========================================
app.post("/obfuscate", async (req, res) => {
  try {
    const { code, level, forceMaximum, userId, referenceCode, layerOverrides } = req.body || {};
    if (!code || typeof code !== "string") {
      res.status(400).json({ error: "Missing or invalid 'code' field" });
      return;
    }
    if (code.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: "Code too large (max 10MB)" });
      return;
    }
    if (referenceCode != null && typeof referenceCode !== "string") {
      res.status(400).json({ error: "Invalid 'referenceCode' field type" });
      return;
    }
    if (referenceCode && referenceCode.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: "Reference file too large (max 10MB)" });
      return;
    }
    const validLevels = ["none", "basic", "medium", "maximum"];
    const obfLevel = validLevels.includes(level) ? level : "medium";

    // Sanitize layerOverrides. Only 6 known keys, values must be
    // one of "auto" | "force" | "skip". Anything else is dropped silently.
    const ALLOWED_LAYERS = ["antiDebugger", "antiDump", "antiTamper", "byteLevelXor", "vmWrap", "outerVM"];
    const ALLOWED_MODES  = ["auto", "force", "skip"];
    const safeOverrides = {};
    if (layerOverrides && typeof layerOverrides === "object") {
      for (const key of ALLOWED_LAYERS) {
        const v = layerOverrides[key];
        if (typeof v === "string" && ALLOWED_MODES.includes(v)) {
          safeOverrides[key] = v;
        }
      }
    }

    const start = Date.now();

    let result;
    try {
      result = await obfuscateWithReport(code, obfLevel, userId, {
        forceMaximum: !!forceMaximum,
        referenceCode: referenceCode || null,
        layerOverrides: safeOverrides,
      });
    } catch (reportErr) {
      console.warn("obfuscateWithReport failed, falling back:", reportErr.message);
      const codeOnly = await obfuscate(code, obfLevel, userId);
      result = { code: codeOnly, report: null };
    }

    if (!result || typeof result.code !== "string") {
      throw new Error("Obfuscator returned invalid result");
    }
    const elapsed = Date.now() - start;

    if (userId && supabase && result.report) {
      supabase.from("obfuscation_history").insert({
        user_id: userId,
        requested_level: result.report.requestedLevel,
        actual_level: result.report.actualLevel,
        was_downgraded: result.report.wasDowngraded,
        downgrade_reason: result.report.downgradeReason,
        original_size: result.report.stats.originalBytes,
        obfuscated_size: result.report.stats.obfuscatedBytes,
        size_ratio: result.report.stats.sizeRatio,
        elapsed_ms: result.report.stats.elapsedMs,
        profile_json: result.report.profile,
        layers_json: result.report.layers,
        stats_json: result.report.stats,
        warnings_json: result.report.warnings,
        force_maximum_used: !!forceMaximum,
        reference_used: !!referenceCode,
      }).then(() => {}, (e) => {
        console.error("obfuscation_history insert error:", e.message);
      });
    }

    res.json({
      success: true,
      level: obfLevel,
      original_size: code.length,
      obfuscated_size: result.code.length,
      elapsed_ms: elapsed,
      code: result.code,
      report: result.report,
    });
  } catch (err) {
    console.error("Obfuscate endpoint error:", err.message);
    res.status(500).json({ error: err.message || "Obfuscation failed" });
  }
});

// ==========================================
// /obfuscate-large â€” separate pipeline for 300KB+ scripts
// Body: { code, level, userId? }
//   level: "basic" | "medium" | "conservative-max" | "nightmare"
// Response: { success, level, original_size, obfuscated_size, elapsed_ms, code, profile, report }
// ==========================================
app.post("/obfuscate-large", async (req, res) => {
  try {
    const { code, level, userId } = req.body || {};
    if (!code || typeof code !== "string") {
      res.status(400).json({ error: "Missing or invalid 'code' field" });
      return;
    }
    if (code.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: "Code too large (max 10MB)" });
      return;
    }
    // v5: added "nightmare" (10 layers â€” adds opaque predicates + control-flow flattening)
    const validLevels = ["basic", "medium", "conservative-max", "nightmare"];
    const obfLevel = validLevels.includes(level) ? level : "medium";

    const start = Date.now();
    let result;
    try {
      result = await obfuscateLarge(code, obfLevel, userId, {});
    } catch (err) {
      console.warn("obfuscateLarge threw:", err.message);
      return res.status(500).json({ error: "Large obfuscation failed: " + err.message });
    }

    if (!result || typeof result.code !== "string") {
      throw new Error("Large obfuscator returned invalid result");
    }
    const elapsed = Date.now() - start;

    res.json({
      success: true,
      level: obfLevel,
      original_size: code.length,
      obfuscated_size: result.code.length,
      elapsed_ms: elapsed,
      code: result.code,
      profile: result.report ? result.report.profile : obfLevel,
      report: result.report || null,
    });
  } catch (err) {
    console.error("Obfuscate-large endpoint error:", err.message);
    res.status(500).json({ error: err.message || "Large obfuscation failed" });
  }
});

// ==========================================
// /s/:id â€” HWID whitelist + IP-fallback rate limit
// ==========================================
app.get("/s/:id", async (req, res) => {
  const scriptId = req.params.id;
  const key = (req.query.key || "").toString().trim();
  const hwidRaw = (req.query.hwid || "").toString().trim().substring(0, 128);
  const placeId = (req.query.place || "").toString().trim();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const userAgent = req.headers["user-agent"] || "";

  const luaError = (msg, status = 403) => {
    res.status(status).type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(`error("[Loader] ${msg.replace(/"/g, "'")}")`);
  };

  // HWID sanitization: reject malformed strings before touching the DB.
  let hwid = "";
  if (hwidRaw.length > 0) {
    if (!HWID_PATTERN.test(hwidRaw)) {
      return luaError("Malformed HWID", 400);
    }
    hwid = hwidRaw;
  }

  try {
    if (!/^[a-zA-Z0-9]{4,32}$/.test(scriptId)) return luaError("Invalid script ID", 400);
    const isRoblox = userAgent.toLowerCase().includes("roblox");
    if (!isRoblox) return res.redirect(302, "/restricted.html");
    if (!supabase) return luaError("Server misconfigured (no service key)", 500);
    const { data: scriptRow, error: scriptErr } = await supabase
      .from("scripts").select("id, key_required").eq("id", scriptId).maybeSingle();
    if (scriptErr) { console.error("Script lookup error:", scriptErr.message); return luaError("Server error", 500); }
    if (!scriptRow) return luaError("Script not found", 404);
    const keyRequired = scriptRow.key_required !== false;

    if (!keyRequired) {
      await supabase.from("executions").insert({
        key: null, hwid: hwid || null, place_id: Number(placeId) || null,
        ip, user_agent: userAgent, success: true, error_reason: "free_mode",
      }).then(() => {}, (e) => console.error("Free-mode log error:", e.message));
      const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
      const scriptCode = await new Promise((resolve, reject) => {
        const request = https.get(supabaseUrl, { headers: { "User-Agent": userAgent } }, (r) => {
          if (r.statusCode !== 200) { reject(new Error(`Supabase returned ${r.statusCode}`)); return; }
          let body = ""; r.setEncoding("utf8");
          r.on("data", (c) => body += c);
          r.on("end", () => resolve(body));
        });
        request.on("error", reject);
        request.setTimeout(10000, () => { request.destroy(); reject(new Error("Timeout")); });
      });
      if (!scriptCode) return luaError("Script empty", 404);
      res.type("text/plain; charset=utf-8");
      res.set("Cache-Control", "no-store");
      return res.send(scriptCode);
    }

    if (!key) return luaError("This script requires a key. Get one from the script owner.", 401);
    if (!/^[A-Z0-9\-]{8,64}$/i.test(key)) return luaError("Malformed key", 401);

    const { data: keyRow, error: keyErr } = await supabase.from("user_keys")
      .select("*").eq("key", key).eq("script_id", scriptId).maybeSingle();
    if (keyErr) { console.error("Key lookup error:", keyErr.message); return luaError("Server error", 500); }
    if (!keyRow) return luaError("Invalid key or not authorized for this script", 403);
    if (keyRow.revoked) return luaError("Key has been revoked by the owner", 403);
    if (keyRow.expires_at && new Date(keyRow.expires_at) < new Date()) return luaError("Key expired", 403);
    if (keyRow.hwid && keyRow.hwid !== hwid) {
      await supabase.from("executions").insert({
        key, hwid: hwid || null, place_id: Number(placeId) || null,
        ip, user_agent: userAgent, success: false, error_reason: "hwid_mismatch",
      });
      return luaError("HWID mismatch. Contact the script owner to reset.", 403);
    }
    if (!keyRow.hwid && hwid) {
      await supabase.from("user_keys").update({ hwid, first_used_at: new Date().toISOString() }).eq("key", key);
    }
    if (keyRow.place_id_whitelist && keyRow.place_id_whitelist.length > 0) {
      const placeIdNum = Number(placeId);
      if (!placeIdNum || !keyRow.place_id_whitelist.includes(placeIdNum)) {
        await supabase.from("executions").insert({
          key, hwid, place_id: placeIdNum || null,
          ip, user_agent: userAgent, success: false, error_reason: "wrong_place_id",
        });
        return luaError("This script is not licensed for this game.", 403);
      }
    }
    if (keyRow.max_executions && keyRow.execution_count >= keyRow.max_executions) {
      return luaError("Execution limit reached for this key.", 429);
    }
    const fingerprints = [hwid, ip].filter(Boolean);
    if (fingerprints.length > 0) {
      const { data: bl } = await supabase.from("blacklist")
        .select("fingerprint").in("fingerprint", fingerprints).maybeSingle();
      if (bl) {
        await supabase.from("executions").insert({
          key, hwid, place_id: Number(placeId) || null,
          ip, user_agent: userAgent, success: false, error_reason: "blacklisted",
        });
        return luaError("Access denied.", 403);
      }
    }
    const rateLimitCol = hwid ? "hwid" : (ip ? "ip" : null);
    const rateLimitVal = hwid || ip;
    if (rateLimitCol) {
      const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
      const { count } = await supabase.from("executions")
        .select("*", { count: "exact", head: true })
        .eq(rateLimitCol, rateLimitVal).gte("executed_at", oneMinAgo);
      if (count && count > 30) return luaError("Rate limit exceeded. Slow down.", 429);
    }
    const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
    const scriptCode = await new Promise((resolve, reject) => {
      const request = https.get(supabaseUrl, { headers: { "User-Agent": userAgent } }, (r) => {
        if (r.statusCode !== 200) { reject(new Error(`Supabase returned ${r.statusCode}`)); return; }
        let body = ""; r.setEncoding("utf8");
        r.on("data", (c) => body += c);
        r.on("end", () => resolve(body));
      });
      request.on("error", reject);
      request.setTimeout(10000, () => { request.destroy(); reject(new Error("Timeout")); });
    });
    if (!scriptCode || scriptCode.trim().length === 0) return luaError("Script not found", 404);
    await Promise.all([
      supabase.from("executions").insert({
        key, hwid, place_id: Number(placeId) || null,
        ip, user_agent: userAgent, success: true, error_reason: null,
      }),
      supabase.rpc("increment_execution_count", { p_key: key }),
    ]).catch((e) => console.error("Log error:", e.message));
    res.type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(scriptCode);
  } catch (err) {
    console.error("/s/:id error:", err.message);
    return luaError("Internal server error", 500);
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString(), supabase_configured: !!supabase });
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, "index.html"), (err) => {
    if (err) res.status(404).type("text/plain").send("Not Found");
  });
});

process.on("uncaughtException", (err) => console.error("Uncaught:", err.message));
process.on("unhandledRejection", (r) => console.error("Unhandled:", r));

app.listen(PORT, () => {
  console.log(`Loadstring Gen server running on port ${PORT}`);
  console.log(`Supabase admin: ${supabase ? "OK" : "NOT CONFIGURED"}`);
});
