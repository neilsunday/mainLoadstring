// ==========================================
// Loadstring Gen - Node.js Server (Render Web Service)
// Serves static frontend + proxies loadstring endpoint
// ==========================================

const express = require("express");
const path = require("path");
const https = require("https");

const app = express();
const PORT = process.env.PORT || 10000;

// Supabase Edge Function URL (hidden from users)
const SUPABASE_RAW_URL =
  "https://uwxsgijolhlpnihdelrq.supabase.co/functions/v1/raw";

// ---------- Static file serving ----------
// Serves index.html, dashboard.html, saved.html, style.css, all .js files, etc.
app.use(
  express.static(path.join(__dirname), {
    extensions: ["html"],
  }),
);

// ---------- Loadstring proxy: /s/:id ----------
// Roblox calls this URL, we proxy it to Supabase Edge Function
app.get("/s/:id", (req, res) => {
  const scriptId = req.params.id;

  // Validate ID format
  if (!/^[a-zA-Z0-9]{4,32}$/.test(scriptId)) {
    res.status(400).type("text/plain").send("-- Invalid script ID");
    return;
  }

  const supabaseUrl = `${SUPABASE_RAW_URL}?id=${encodeURIComponent(scriptId)}`;
  const userAgent = req.headers["user-agent"] || "";

  // Detect if this is a Roblox request
  const isRoblox = userAgent.toLowerCase().includes("roblox");

  // If NOT Roblox (i.e., browser opening the URL) -> redirect to restricted page
  if (!isRoblox) {
    res.redirect(302, "/restricted.html");
    return;
  }

  // Roblox request -> proxy to Supabase
  const request = https.get(
    supabaseUrl,
    {
      headers: {
        // Pass Roblox User-Agent through so Supabase Edge Function serves script
        "User-Agent": userAgent,
      },
    },
    (supabaseRes) => {
      // Forward status code
      res.status(supabaseRes.statusCode || 500);
      res.type("text/plain; charset=utf-8");
      res.set("Cache-Control", "no-store");

      // Pipe Supabase response body to Roblox
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

// ---------- Health check (for uptime monitoring) ----------
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ---------- Catch-all for SPA-style routing ----------
// If someone visits a path na hindi file, serve index.html
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
