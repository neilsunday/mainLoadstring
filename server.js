const express = require("express");
const path = require("path");
const https = require("https");
const { createClient } = require("@supabase/supabase-js");
// v16.0: import both â€” obfuscate() is the legacy string API, obfuscateWithReport()
// returns { code, report } for the new dashboard flow.
const { obfuscate, obfuscateWithReport } = require("./obfuscator");

const app = express();
const PORT = process.env.PORT || 10000;

const SUPABASE_URL = process.env.SUPABASE_URL || "https://uwxsgijolhlpnihdelrq.supabase.co";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_SERVICE_KEY) {
  console.warn("[WARN] SUPABASE_SERVICE_KEY not set - key validation will fail!");
}

const supabase = SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

const SUPABASE_RAW_URL =
  "https://uwxsgijolhlpnihdelrq.supabase.co/functions/v1/raw";

app.use(express.json({ limit: "12mb" }));
app.use(express.static(path.join(__dirname), { extensions: ["html"] }));

// ==========================================
// /obfuscate â€” v2: returns { code, report } when report is available
// Backward compat: response always has `code` field, and the OLD fields
// (level, original_size, obfuscated_size, elapsed_ms) are still populated.
// NEW: `report` field with full metadata for dashboard display.
// NEW: Accepts `forceMaximum: true` in body to skip auto-downgrade.
// NEW: Accepts `userId` for optional history logging.
// ==========================================
app.post("/obfuscate", async (req, res) => {
  try {
    const { code, level, forceMaximum, userId } = req.body || {};
    if (!code || typeof code !== "string") {
      res.status(400).json({ error: "Missing or invalid 'code' field" });
      return;
    }
    if (code.length > 10 * 1024 * 1024) {
      res.status(413).json({ error: "Code too large (max 10MB)" });
      return;
    }
    const validLevels = ["none", "basic", "medium", "maximum"];
    const obfLevel = validLevels.includes(level) ? level : "medium";
    const start = Date.now();

    // Use obfuscateWithReport for the report; fall back to obfuscate() as a
    // safety net if the new API is somehow unavailable (should never happen).
    let result;
    try {
      result = await obfuscateWithReport(code, obfLevel, userId, {
        forceMaximum: !!forceMaximum,
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

    // Optional: log to obfuscation_history if userId provided AND Supabase is available
    if (userId && supabase && result.report) {
      // Fire and forget - don't block response on log write
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
      report: result.report, // NEW: full report object for dashboard
    });
  } catch (err) {
    console.error("Obfuscate endpoint error:", err.message);
    res.status(500).json({ error: err.message || "Obfuscation failed" });
  }
});

// ==========================================
// /s/:id (unchanged from v1)
// ==========================================
app.get("/s/:id", async (req, res) => {
  const scriptId = req.params.id;
  const key = (req.query.key || "").toString().trim();
  const hwid = (req.query.hwid || "").toString().trim().substring(0, 128);
  const placeId = (req.query.place || "").toString().trim();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const userAgent = req.headers["user-agent"] || "";

  const luaError = (msg, status = 403) => {
    res.status(status).type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(`error("[Loader] ${msg.replace(/"/g, "'")}")`);
  };

  try {
    if (!/^[a-zA-Z0-9]{4,32}$/.test(scriptId)) {
      return luaError("Invalid script ID", 400);
    }
    const isRoblox = userAgent.toLowerCase().includes("roblox");
    if (!isRoblox) {
      return res.redirect(302, "/restricted.html");
    }
    if (!supabase) {
      return luaError("Server misconfigured (no service key)", 500);
    }
    const { data: scriptRow, error: scriptErr } = await supabase
      .from("scripts")
      .select("id, key_required")
      .eq("id", scriptId)
      .maybeSingle();
    if (scriptErr) {
      console.error("Script lookup error:", scriptErr.message);
      return luaError("Server error", 500);
    }
    if (!scriptRow) return luaError("Script not found", 404);
    const keyRequired = scriptRow.key_required !== false;

    if (!keyRequired) {
      await supabase.from("executions").insert({
        key: null, hwid: hwid || null,
        place_id: Number(placeId) || null,
        ip, user_agent: userAgent, success: true,
        error_reason: "free_mode",
      }).then(() => {}, (e) => console.error("Free-mode log error:", e.message));

      const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
      const scriptCode = await new Promise((resolve, reject) => {
        const request = https.get(supabaseUrl, { headers: { "User-Agent": userAgent } }, (r) => {
          if (r.statusCode !== 200) { reject(new Error(`Supabase returned ${r.statusCode}`)); return; }
          let body = "";
          r.setEncoding("utf8");
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

    const { data: keyRow, error: keyErr } = await supabase
      .from("user_keys")
      .select("*")
      .eq("key", key)
      .eq("script_id", scriptId)
      .maybeSingle();
    if (keyErr) {
      console.error("Key lookup error:", keyErr.message);
      return luaError("Server error", 500);
    }
    if (!keyRow) return luaError("Invalid key or not authorized for this script", 403);
    if (keyRow.revoked) return luaError("Key has been revoked by the owner", 403);
    if (keyRow.expires_at && new Date(keyRow.expires_at) < new Date()) {
      return luaError("Key expired", 403);
    }
    if (keyRow.hwid && keyRow.hwid !== hwid) {
      await supabase.from("executions").insert({
        key, hwid: hwid || null, place_id: Number(placeId) || null,
        ip, user_agent: userAgent, success: false, error_reason: "hwid_mismatch",
      });
      return luaError("HWID mismatch. Contact the script owner to reset.", 403);
    }
    if (!keyRow.hwid && hwid) {
      await supabase.from("user_keys")
        .update({ hwid, first_used_at: new Date().toISOString() })
        .eq("key", key);
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
    if (hwid) {
      const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
      const { count } = await supabase.from("executions")
        .select("*", { count: "exact", head: true })
        .eq("hwid", hwid).gte("executed_at", oneMinAgo);
      if (count && count > 30) return luaError("Rate limit exceeded. Slow down.", 429);
    }
    const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
    const scriptCode = await new Promise((resolve, reject) => {
      const request = https.get(supabaseUrl, { headers: { "User-Agent": userAgent } }, (r) => {
        if (r.statusCode !== 200) { reject(new Error(`Supabase returned ${r.statusCode}`)); return; }
        let body = "";
        r.setEncoding("utf8");
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
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    supabase_configured: !!supabase,
  });
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
