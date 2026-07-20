const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const PROMETHEUS_BIN = require.resolve("@gamely/prometheus-cli/bin/prometheus-cli.js");

const LEVEL_PRESET = {
  none: null,
  basic: "Minify",
  medium: "Weak",
  maximum: "Strong",
};

function preprocess(code) {
  code = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return code.trim();
}

function runPrometheus(code, preset) {
  return new Promise((resolve, reject) => {
    const tmpDir = os.tmpdir();
    const uniqueId = crypto.randomBytes(8).toString("hex");
    const inputPath = path.join(tmpDir, `prom-in-${uniqueId}.lua`);
    const outputPath = path.join(tmpDir, `prom-out-${uniqueId}.lua`);

    try {
      fs.writeFileSync(inputPath, code, "utf8");
    } catch (err) {
      reject(new Error("Failed to write temp file: " + err.message));
      return;
    }

    const args = [
      PROMETHEUS_BIN,
      "--preset",
      preset,
      "--out",
      outputPath,
      inputPath,
    ];

    const proc = spawn("node", args, {
      timeout: 60000,
      env: { ...process.env, PROMETHEUS_NO_COLOR: "1" },
    });

    let stderr = "";
    let stdout = "";

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("error", (err) => {
      cleanup();
      reject(new Error("Prometheus process error: " + err.message));
    });

    proc.on("close", (exitCode) => {
      if (exitCode !== 0) {
        cleanup();
        reject(
          new Error(
            `Prometheus exited with code ${exitCode}. ${stderr || stdout || "no output"}`,
          ),
        );
        return;
      }

      try {
        const result = fs.readFileSync(outputPath, "utf8");
        cleanup();
        resolve(result);
      } catch (err) {
        cleanup();
        reject(new Error("Failed to read obfuscated output: " + err.message));
      }
    });

    function cleanup() {
      try { fs.unlinkSync(inputPath); } catch (e) {}
      try { fs.unlinkSync(outputPath); } catch (e) {}
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
    throw new Error(`Unknown obfuscation level: ${level}`);
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

module.exports = { obfuscate };
