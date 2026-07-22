const express = require("express");
const path = require("path");
const https = require("https");
const { createClient } = require("@supabase/supabase-js");
// v25.0: obfuscateWithStream added for live per-stage skip/continue UI.
const { obfuscate, obfuscateWithReport, obfuscateWithStream } = require("./obfuscator");
const crypto = require("crypto");

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

// v24.0: bumped limit to 24mb to accommodate primary code + reference file
app.use(express.json({ limit: "24mb" }));
app.use(express.static(path.join(__dirname), { extensions: ["html"] }));

// ==========================================
// /obfuscate - v24.0 (unchanged, one-shot obfuscation)
// Body: { code, level, forceMaximum?, userId?, referenceCode? }
// Response: { success, level, original_size, obfuscated_size, elapsed_ms, code, report }
// ==========================================
app.post("/obfuscate", async (req, res) => {
  try {
    const { code, level, forceMaximum, userId, referenceCode } = req.body || {};
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
    const start = Date.now();

    let result;
    try {
      result = await obfuscateWithReport(code, obfLevel, userId, {
        forceMaximum: !!forceMaximum,
        referenceCode: referenceCode || null,
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
// v25.0 STREAMING API
// ==========================================
// Two-endpoint dance:
//
//   1. Client POSTs to /obfuscate/stream/start with {code, level, ...}.
//      Server holds the run in memory keyed by a fresh sessionId and returns
//      { sessionId } without doing any work yet.
//
//   2. Client opens an EventSource on /obfuscate/stream/:sessionId.
//      Server starts the pipeline and pushes SSE events for every stage.
//      When a stage requests a decision, the run awaits inside a Promise.
//
//   3. Client POSTs to /obfuscate/stream/:sessionId/decision with
//      { stage, skip } to resolve the pending Promise. The pipeline continues.
//
//   4. On session-complete, server sends a final event with the code + report
//      and closes the SSE stream. Client can then save/preview normally.
//
// Sessions self-expire after 5 minutes of inactivity so a rage-quit browser
// tab does not leak memory on the server.
// ==========================================

const streamSessions = new Map(); // sessionId -> session state
const SESSION_TTL_MS = 5 * 60 * 1000;

function _newSessionId() {
  return crypto.randomBytes(12).toString("hex");
}

function _touchSession(session) {
  session.lastActivity = Date.now();
}

function _sweepSessions() {
  const now = Date.now();
  for (const [id, s] of streamSessions.entries()) {
    if (now - s.lastActivity > SESSION_TTL_MS) {
      try { s.abort && s.abort(); } catch (_) {}
      streamSessions.delete(id);
    }
  }
}
setInterval(_sweepSessions, 60 * 1000).unref();

// Step 1: reserve a session and validate the payload.
app.post("/obfuscate/stream/start", (req, res) => {
  try {
    const { code, level, forceMaximum, userId, referenceCode } = req.body || {};
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
    const sessionId = _newSessionId();
    streamSessions.set(sessionId, {
      id: sessionId,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      payload: {
        code, level: obfLevel,
        forceMaximum: !!forceMaximum,
        referenceCode: referenceCode || null,
        userId: userId || null,
      },
      // SSE state -- populated when the client connects.
      res: null,
      eventQueue: [],       // events emitted before the SSE connects
      pendingDecision: null,// { stage, resolve } while a stage awaits
      finished: false,
    });
    res.json({ sessionId });
  } catch (err) {
    console.error("stream/start error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Step 2: SSE stream. Starts the pipeline on connect and pushes stage events.
app.get("/obfuscate/stream/:sessionId", (req, res) => {
  const session = streamSessions.get(req.params.sessionId);
  if (!session) {
    res.status(404).json({ error: "Unknown session" });
    return;
  }
  if (session.res) {
    res.status(409).json({ error: "Session already has an open stream" });
    return;
  }
  _touchSession(session);

  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no", // disable nginx buffering if in front
  });
  res.flushHeaders && res.flushHeaders();

  session.res = res;
  const sendSSE = (evt, data) => {
    try {
      res.write("event: " + evt + "\n");
      res.write("data: " + JSON.stringify(data || {}) + "\n\n");
    } catch (_) { /* client hung up */ }
  };

  // Flush any events queued before the stream opened.
  for (const q of session.eventQueue) sendSSE(q.event, q.data);
  session.eventQueue = [];

  req.on("close", () => {
    if (session.pendingDecision) {
      // Resolve as skip so the pipeline unwinds cleanly.
      try { session.pendingDecision.resolve({ skip: true }); } catch (_) {}
      session.pendingDecision = null;
    }
    session.res = null;
  });

  // Heartbeat every 15s so proxies don't drop idle connections.
  const heartbeat = setInterval(() => {
    try { res.write(": ping\n\n"); } catch (_) {}
  }, 15000);
  heartbeat.unref();
  req.on("close", () => clearInterval(heartbeat));

  // Fire the pipeline.
  const emit = (evt, data) => {
    _touchSession(session);
    if (session.res) sendSSE(evt, data);
    else session.eventQueue.push({ event: evt, data });
  };
  const awaitDecision = (stage) => new Promise((resolve) => {
    _touchSession(session);
    session.pendingDecision = { stage, resolve };
  });

  const { code, level, forceMaximum, referenceCode, userId } = session.payload;

  obfuscateWithStream(code, level, userId, {
    forceMaximum, referenceCode,
    emit, awaitDecision,
  }).then((result) => {
    session.finished = true;
    emit("session-complete", {
      code: result.code,
      report: result.report,
      original_size: code.length,
      obfuscated_size: (result.code || "").length,
    });
    // Log to Supabase (best effort, same shape as /obfuscate).
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
      }).then(() => {}, (e) => console.error("history insert:", e.message));
    }
    try { session.res && session.res.end(); } catch (_) {}
    // Keep session for 30s so the client can retrieve if it reconnects.
    setTimeout(() => streamSessions.delete(session.id), 30 * 1000);
  }).catch((err) => {
    console.error("stream pipeline error:", err.message);
    emit("session-error", { error: err.message });
    try { session.res && session.res.end(); } catch (_) {}
    streamSessions.delete(session.id);
  });
});

// Step 3: decision callback. Resolves the awaiting stage.
app.post("/obfuscate/stream/:sessionId/decision", (req, res) => {
  const session = streamSessions.get(req.params.sessionId);
  if (!session) {
    res.status(404).json({ error: "Unknown session" });
    return;
  }
  _touchSession(session);
  const { stage, skip } = req.body || {};
  if (!session.pendingDecision) {
    res.status(409).json({ error: "No stage awaiting decision" });
    return;
  }
  if (stage && session.pendingDecision.stage !== stage) {
    res.status(409).json({ error: "Decision stage mismatch (expected " + session.pendingDecision.stage + ")" });
    return;
  }
  const resolve = session.pendingDecision.resolve;
  session.pendingDecision = null;
  try { resolve({ skip: !!skip }); } catch (_) {}
  res.json({ ok: true });
});

// ==========================================
// /s/:id - unchanged from v1 (loadstring loader endpoint)
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
