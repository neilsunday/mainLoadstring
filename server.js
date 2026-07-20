// ==========================================
// Loadstring Gen - Node.js Server (Render Web Service)
// Serves static frontend + proxies loadstring endpoint + obfuscation API
// ==========================================

const express = require("express");
const path = require("path");
const https = require("https");
const { obfuscate } = require("./obfuscator");

const app = express();
const PORT = process.env.PORT || 10000;

// Supabase Edge Function URL (hidden from users)
const SUPABASE_RAW_URL =
  "https://uwxsgijolhlpnihdelrq.supabase.co/functions/v1/raw";

// ---------- JSON body parser (for /obfuscate endpoint) ----------
// 12MB limit to support up to 10MB scripts + overhead
app.use(express.json({ limit: "12mb" }));

// ---------- Static file serving ----------
app.use(
  express.static(path.join(__dirname), {
    extensions: ["html"],
  }),
);

// ==========================================
// POST /obfuscate - Backend Obfuscator API
// ==========================================
app.post("/obfuscate", (req, res) => {
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
    const obfuscated = obfuscate(code, obfLevel);
    const elapsed = Date.now() - start;

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
// GET /s/:id - Loadstring proxy
// ==========================================
app.get("/s/:id", (req, res) => {
  const scriptId = req.params.id;

  if (!/^[a-zA-Z0-9]{4,32}$/.test(scriptId)) {
    res.status(400).type("text/plain").send("-- Invalid script ID");
    return;
  }

  const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
  const userAgent = req.headers["user-agent"] || "";
  const isRoblox = userAgent.toLowerCase().includes("roblox");

  if (!isRoblox) {
    res.redirect(302, "/restricted.html");
    return;
  }

  const request = https.get(
    supabaseUrl,
    {
      headers: {
        "User-Agent": userAgent,
      },
    },
    (supabaseRes) => {
      res.status(supabaseRes.statusCode || 500);
      res.type("text/plain; charset=utf-8");
      res.set("Cache-Control", "no-store");
      supabaseRes.pipe(res);
    },
  );

  request.on("error", (err) => {
    console.error("Proxy error:", err.message);
    res.status(500).type("text/plain").send("-- Server error");
  });

  request.setTimeout(10000, () => {
    request.destroy();
    if (!res.headersSent) {
      res.status(504).type("text/plain").send("-- Timeout");
    }
  });
});

// ---------- Health check ----------
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ---------- Catch-all ----------
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "index.html"), (err) => {
    if (err) {
      res.status(404).type("text/plain").send("Not Found");
    }
  });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`Loadstring Gen server running on port ${PORT}`);
});
