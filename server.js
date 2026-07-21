const express = require("express");
const path = require("path");
const https = require("https");
const { createClient } = require("@supabase/supabase-js");
const { obfuscate } = require("./obfuscator");

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// Supabase Admin Client (server-side, uses service_role key)
// Set these in your hosting env vars (Render/Railway/etc.)
// ==========================================
const SUPABASE_URL = process.env.SUPABASE_URL || "https://uwxsgijolhlpnihdelrq.supabase.co";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY; // <-- ADD THIS TO ENV VARS

if (!SUPABASE_SERVICE_KEY) {
  console.warn("[WARN] SUPABASE_SERVICE_KEY not set â€” key validation will fail!");
}

const supabase = SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

const SUPABASE_RAW_URL =
  "https://uwxsgijolhlpnihdelrq.supabase.co/functions/v1/raw";

app.use(express.json({ limit: "12mb" }));

app.use(
  express.static(path.join(__dirname), {
    extensions: ["html"],
  }),
);

// ==========================================
// /obfuscate (existing endpoint, unchanged)
// ==========================================
app.post("/obfuscate", async (req, res) => {
  try {
    const { code, level } = req.body || {};

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
    const obfuscated = await obfuscate(code, obfLevel);
    const elapsed = Date.now() - start;

    if (typeof obfuscated !== "string") {
      throw new Error("Obfuscator returned invalid result");
    }

    res.json({
      success: true,
      level: obfLevel,
      original_size: code.length,
      obfuscated_size: obfuscated.length,
      elapsed_ms: elapsed,
      code: obfuscated,
    });
  } catch (err) {
    console.error("Obfuscate endpoint error:", err.message);
    res.status(500).json({
      error: err.message || "Obfuscation failed",
    });
  }
});

// ==========================================
// /s/:id â€” NEW: full validation pipeline
// key/HWID/PlaceId/killswitch/blacklist + fresh obfuscation per request
// ==========================================
app.get("/s/:id", async (req, res) => {
  const scriptId = req.params.id;
  const key = (req.query.key || "").toString().trim();
  const hwid = (req.query.hwid || "").toString().trim().substring(0, 128);
  const placeId = (req.query.place || "").toString().trim();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const userAgent = req.headers["user-agent"] || "";

  // Send Lua-safe error and exit
  const luaError = (msg, status = 403) => {
    res.status(status).type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(`error("[Loader] ${msg.replace(/"/g, "'")}")`);
  };

  try {
    // 1. Basic script ID validation
    if (!/^[a-zA-Z0-9]{4,32}$/.test(scriptId)) {
      return luaError("Invalid script ID", 400);
    }

    // 2. Roblox User-Agent check (basic sandbox)
    const isRoblox = userAgent.toLowerCase().includes("roblox");
    if (!isRoblox) {
      return res.redirect(302, "/restricted.html");
    }

    // 3. Supabase available?
    if (!supabase) {
      return luaError("Server misconfigured (no service key)", 500);
    }

    // 4. Key required
    if (!key) {
      return luaError("No key provided. Get one from the script owner.", 401);
    }

    if (!/^[A-Z0-9\-]{8,64}$/i.test(key)) {
      return luaError("Malformed key", 401);
    }

    // 5. Fetch key record
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

    if (!keyRow) {
      return luaError("Invalid key or not authorized for this script", 403);
    }

    // 6. Kill switch check
    if (keyRow.revoked) {
      return luaError("Key has been revoked by the owner", 403);
    }

    // 7. Expiration check
    if (keyRow.expires_at && new Date(keyRow.expires_at) < new Date()) {
      return luaError("Key expired", 403);
    }

    // 8. HWID lock â€” bind on first use, then enforce
    if (keyRow.hwid && keyRow.hwid !== hwid) {
      // Log tampering attempt
      await supabase.from("executions").insert({
        key,
        hwid: hwid || null,
        place_id: placeId ? Number(placeId) || null : null,
        ip,
        user_agent: userAgent,
        success: false,
        error_reason: "hwid_mismatch",
      });
      return luaError("HWID mismatch. Contact the script owner to reset.", 403);
    }

    if (!keyRow.hwid && hwid) {
      // First-time bind
      await supabase
        .from("user_keys")
        .update({ hwid, first_used_at: new Date().toISOString() })
        .eq("key", key);
    }

    // 9. Domain lock (PlaceId whitelist)
    if (keyRow.place_id_whitelist && keyRow.place_id_whitelist.length > 0) {
      const placeIdNum = Number(placeId);
      if (!placeIdNum || !keyRow.place_id_whitelist.includes(placeIdNum)) {
        await supabase.from("executions").insert({
          key,
          hwid,
          place_id: placeIdNum || null,
          ip,
          user_agent: userAgent,
          success: false,
          error_reason: "wrong_place_id",
        });
        return luaError("This script is not licensed for this game.", 403);
      }
    }

    // 10. Execution cap check
    if (
      keyRow.max_executions &&
      keyRow.execution_count >= keyRow.max_executions
    ) {
      return luaError("Execution limit reached for this key.", 429);
    }

    // 11. Blacklist check (HWID or IP)
    const fingerprints = [hwid, ip].filter(Boolean);
    if (fingerprints.length > 0) {
      const { data: blacklisted } = await supabase
        .from("blacklist")
        .select("fingerprint")
        .in("fingerprint", fingerprints)
        .maybeSingle();

      if (blacklisted) {
        await supabase.from("executions").insert({
          key,
          hwid,
          place_id: Number(placeId) || null,
          ip,
          user_agent: userAgent,
          success: false,
          error_reason: "blacklisted",
        });
        return luaError("Access denied.", 403);
      }
    }

    // 12. Rate limit (basic â€” 30 executions per minute per HWID)
    if (hwid) {
      const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
      const { count } = await supabase
        .from("executions")
        .select("*", { count: "exact", head: true })
        .eq("hwid", hwid)
        .gte("executed_at", oneMinAgo);

      if (count && count > 30) {
        return luaError("Rate limit exceeded. Slow down.", 429);
      }
    }

    // 13. Fetch script from Supabase (existing proxy logic)
    const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;

    const scriptCode = await new Promise((resolve, reject) => {
      const request = https.get(
        supabaseUrl,
        { headers: { "User-Agent": userAgent } },
        (supabaseRes) => {
          if (supabaseRes.statusCode !== 200) {
            reject(new Error(`Supabase returned ${supabaseRes.statusCode}`));
            return;
          }
          let body = "";
          supabaseRes.setEncoding("utf8");
          supabaseRes.on("data", (chunk) => (body += chunk));
          supabaseRes.on("end", () => resolve(body));
        },
      );
      request.on("error", reject);
      request.setTimeout(10000, () => {
        request.destroy();
        reject(new Error("Timeout fetching script"));
      });
    });

    if (!scriptCode || scriptCode.trim().length === 0) {
      return luaError("Script not found", 404);
    }

    // 14. Log successful execution + increment counter
    await Promise.all([
      supabase.from("executions").insert({
        key,
        hwid,
        place_id: Number(placeId) || null,
        ip,
        user_agent: userAgent,
        success: true,
        error_reason: null,
      }),
      supabase.rpc("increment_execution_count", { p_key: key }),
    ]).catch((e) => console.error("Log/increment error:", e.message));

    // 15. Return script (already obfuscated when saved; skip re-obfuscation
    //     for speed â€” enable "fresh obf per request" later if desired)
    res.type("text/plain; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(scriptCode);
  } catch (err) {
    console.error("/s/:id error:", err.message);
    return luaError("Internal server error", 500);
  }
});

// ==========================================
// /health
// ==========================================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    supabase_configured: !!supabase,
  });
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, "index.html"), (err) => {
    if (err) {
      res.status(404).type("text/plain").send("Not Found");
    }
  });
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err.message);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});

app.listen(PORT, () => {
  console.log(`Loadstring Gen server running on port ${PORT}`);
  console.log(`Supabase admin: ${supabase ? "OK" : "NOT CONFIGURED"}`);
});
