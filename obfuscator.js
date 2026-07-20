const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const LEVEL_PRESET = {
  none: null,
  basic: "Minify",
  medium: "Weak",
  maximum: "custom-max",
};

const CUSTOM_MAX_CONFIG = {
  LuaVersion: "Lua51",
  PrettyPrint: false,
  VarNamePrefix: "",
  NameGenerator: "MangledShuffled",
  Seed: 0,
  Steps: [
    {
      Name: "EncryptStrings",
      Settings: {}
    },
    {
      Name: "WrapInFunction",
      Settings: {}
    },
    {
      Name: "ProxifyLocals",
      Settings: {
        LiteralType: "any",
        Treshold: 1
      }
    }
  ]
};

function preprocess(code) {
  code = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return code.trim();
}

function findPrometheusExecutable() {
  const candidates = [
    path.join(__dirname, "node_modules", ".bin", "prometheus-cli"),
    path.join(__dirname, "node_modules", "@gamely", "prometheus-cli", "index.js"),
    path.join(__dirname, "node_modules", "@gamely", "prometheus-cli", "bin", "prometheus-cli.js"),
    path.join(__dirname, "node_modules", "@gamely", "prometheus-cli", "bin", "cli.js"),
  ];

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch (e) {}
  }
  return null;
}

function runPrometheus(code, preset) {
  return new Promise((resolve, reject) => {
    const tmpDir = os.tmpdir();
    const uniqueId = crypto.randomBytes(8).toString("hex");
    const inputPath = path.join(tmpDir, `prom-in-${uniqueId}.lua`);
    const outputPath = path.join(tmpDir, `prom-out-${uniqueId}.lua`);
    const configPath = path.join(tmpDir, `prom-cfg-${uniqueId}.json`);

    let usingConfig = false;

    try {
      fs.writeFileSync(inputPath, code, "utf8");
      if (preset === "custom-max") {
        fs.writeFileSync(configPath, JSON.stringify(CUSTOM_MAX_CONFIG, null, 2), "utf8");
        usingConfig = true;
      }
    } catch (err) {
      cleanup();
      reject(new Error("Failed to write temp file: " + err.message));
      return;
    }

    const executable = findPrometheusExecutable();
    if (!executable) {
      cleanup();
      reject(new Error("Prometheus executable not found in node_modules"));
      return;
    }

    let args;
    if (usingConfig) {
      args = [executable, "--config", configPath, "--out", outputPath, inputPath];
    } else {
      args = [executable, "--preset", preset, "--out", outputPath, inputPath];
    }

    const proc = spawn("node", args, {
      timeout: 60000,
      env: { ...process.env, PROMETHEUS_NO_COLOR: "1" },
    });

    let stderr = "";
    let stdout = "";
    let settled = false;

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("Prometheus process error: " + err.message));
    });

    proc.on("close", (exitCode) => {
      if (settled) return;
      settled = true;

      if (exitCode !== 0) {
        cleanup();
        const errMsg = (stderr || stdout || "no output").substring(0, 500);
        reject(new Error(`Prometheus exited with code ${exitCode}: ${errMsg}`));
        return;
      }

      let result = null;
      try {
        result = fs.readFileSync(outputPath, "utf8");
      } catch (err) {
        cleanup();
        reject(new Error("Failed to read output: " + err.message));
        return;
      }

      cleanup();
      resolve(result);
    });

    function cleanup() {
      try { fs.unlinkSync(inputPath); } catch (e) {}
      try { fs.unlinkSync(outputPath); } catch (e) {}
      if (usingConfig) {
        try { fs.unlinkSync(configPath); } catch (e) {}
      }
    }
  });
}

async function obfuscate(luaCode, level = "medium") {
  const code = preprocess(luaCode);

  if (level === "none") {
    return code;
  }

  const preset = LEVEL_PRESET[level];
  if (!preset) {
    throw new Error("Unknown obfuscation level: " + level);
  }

  try {
    const result = await runPrometheus(code, preset);
    if (!result || result.trim().length === 0) {
      throw new Error("Prometheus returned empty output");
    }
    return result;
  } catch (err) {
    throw new Error("Obfuscation failed: " + err.message);
  }
}

process.on("uncaughtException", (err) => {
  console.error("[obfuscator] Uncaught:", err.message);
});
process.on("unhandledRejection", (reason) => {
  console.error("[obfuscator] Unhandled rejection:", reason);
});

module.exports = { obfuscate };
