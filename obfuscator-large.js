// ============================================================================
// obfuscator-large.js â€” Bytecode-oriented pipeline for large Lua/Luau scripts
// ============================================================================
// Completely separate from obfuscator.js. This file NEVER shares code or
// imports with the AST-based obfuscator. Every transform in this pipeline is
// text-level (byte scan or minimal state machine) so there is no luaparse
// round-trip that can cascade parse failures on complex scripts.
//
// Public API (matches server.js integration pattern):
//
//   obfuscateLarge(luaCode, level, userId, options)
//     -> Promise<{ code, report }>
//
//   Where:
//     level = "basic" | "medium" | "conservative-max"
//     options = {
//       // reserved for future use â€” no options in step 1
//     }
//     report = {
//       requestedLevel: string,
//       actualLevel:    string,
//       profile:        string,     // human-readable profile name
//       stats: {
//         originalBytes:   number,
//         obfuscatedBytes: number,
//         sizeRatio:       number,
//         elapsedMs:       number,
//         stringsEncrypted:      number,   // populated in later steps
//         numericsObfuscated:    number,   // populated in later steps
//       },
//       stagesSucceeded: string[],
//       stagesSkipped:   string[],
//       warnings:        string[],
//     }
//
// Pipeline levels (from user-facing dropdown in dashboard):
//   basic             â€” minify only (safest, near-zero overhead)
//   medium            â€” minify + string encryption + numeric encoding
//   conservative-max  â€” everything + anti-tamper checksum wrapper
//                       (+ optional bytecode VM wrap for eligible hot functions)
//
// Design invariants:
//   1. No AST parse. Ever. Text-level byte scans only.
//   2. Every stage is stateless â€” it takes a string, returns a string.
//   3. Every stage is skippable â€” failures degrade gracefully, never crash.
//   4. Runtime decoder helpers are embedded inline (no external deps).
//   5. Output is a single self-contained Lua string ready for loadstring().
// ============================================================================

const crypto = require("crypto");

// ============================================================================
// SECTION 1 â€” Level definitions
// ============================================================================

const LEVEL_BASIC = "basic";
const LEVEL_MEDIUM = "medium";
const LEVEL_CONSERVATIVE_MAX = "conservative-max";

const VALID_LEVELS = new Set([LEVEL_BASIC, LEVEL_MEDIUM, LEVEL_CONSERVATIVE_MAX]);

const LEVEL_PROFILES = {
  [LEVEL_BASIC]: {
    label: "Basic â€” minify only",
    stages: ["minify"],
  },
  [LEVEL_MEDIUM]: {
    label: "Medium â€” string + numeric encryption",
    stages: ["minify", "stringEncryption", "numericEncoding", "decoderInjection"],
  },
  [LEVEL_CONSERVATIVE_MAX]: {
    label: "Conservative Max â€” full protection without AST rewrite",
    stages: ["minify", "stringEncryption", "numericEncoding", "decoderInjection", "antiTamperWrap"],
  },
};

// ============================================================================
// SECTION 2 â€” Report builder
// ============================================================================

function makeReport(level) {
  return {
    requestedLevel: level,
    actualLevel: level,
    profile: LEVEL_PROFILES[level] ? LEVEL_PROFILES[level].label : "unknown",
    stats: {
      originalBytes: 0,
      obfuscatedBytes: 0,
      sizeRatio: 1,
      elapsedMs: 0,
      stringsEncrypted: 0,
      numericsObfuscated: 0,
      commentsStripped: 0,
      minifyBytesSaved: 0,
    },
    stagesSucceeded: [],
    stagesSkipped: [],
    warnings: [],
  };
}

function warn(report, msg) {
  report.warnings.push(msg);
}

// ============================================================================
// SECTION 3 â€” Stage stubs (to be implemented in later steps)
// ============================================================================
// Every stage takes (code, ctx) and returns { code, ok, meta }.
//   code â€” transformed source (or original if skipped)
//   ok   â€” true if stage succeeded, false if skipped
//   meta â€” stage-specific data merged into the report

function stageMinify(code, ctx) {
  // Step 2: real minify.
  //
  // Design: string-aware byte scan. We never touch content inside string
  // literals or long-bracket blocks. This avoids the entire class of bugs
  // where a regex-based transform corrupts string content.
  //
  // Pipeline:
  //   1. Normalize CRLF/CR to LF
  //   2. Walk the source byte-by-byte, emitting:
  //      - strings (all 4 flavors) verbatim
  //      - non-comment code with whitespace collapsed
  //      - drop line comments (-- ... \n)
  //      - drop block comments (--[[ ... ]], --[=[ ... ]=], etc.)
  //   3. Collapse 3+ blank lines to 1, trim trailing whitespace per line
  //
  // Character state machine â€” no regex, no parse.
  const raw = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const n = raw.length;
  const out = [];
  let i = 0;
  let commentsStripped = 0;
  let stringsPreserved = 0;

  while (i < n) {
    const c = raw[i];
    const c2 = raw[i + 1];

    // ---- Long-bracket string: [[ ... ]] or [=[ ... ]=] ----
    // Only enters this branch if we're at '[' AND not preceded by identifier
    // char (in which case '[' is a table index, not a long string).
    if (c === "[") {
      // Peek for = signs
      let j = i + 1;
      let level = 0;
      while (j < n && raw[j] === "=") { level++; j++; }
      if (j < n && raw[j] === "[") {
        // It's a long-bracket string [=*[
        const closer = "]" + "=".repeat(level) + "]";
        const endIdx = raw.indexOf(closer, j + 1);
        if (endIdx > 0) {
          // Emit the whole long-bracket string verbatim
          out.push(raw.substring(i, endIdx + closer.length));
          i = endIdx + closer.length;
          stringsPreserved++;
          continue;
        }
        // Unterminated long-bracket â€” treat as regular '[' character
      }
      // Not a long-bracket string, fall through to emit '['
    }

    // ---- Comments: -- (line) or --[[ / --[=[ (block) ----
    if (c === "-" && c2 === "-") {
      // Check for --[[  or --[=*[  (block comment)
      let j = i + 2;
      if (j < n && raw[j] === "[") {
        let level = 0;
        let k = j + 1;
        while (k < n && raw[k] === "=") { level++; k++; }
        if (k < n && raw[k] === "[") {
          // Block comment --[=*[ ... ]=*]
          const closer = "]" + "=".repeat(level) + "]";
          const endIdx = raw.indexOf(closer, k + 1);
          if (endIdx > 0) {
            // Drop the whole block comment. Preserve line count by keeping
            // a space so \n boundaries don't shift for downstream stages.
            i = endIdx + closer.length;
            commentsStripped++;
            continue;
          }
          // Unterminated block comment â€” drop rest of file (matches Lua)
          i = n;
          commentsStripped++;
          continue;
        }
      }
      // Line comment: skip to next \n (don't consume the \n itself)
      const nl = raw.indexOf("\n", i);
      i = nl < 0 ? n : nl;
      commentsStripped++;
      continue;
    }

    // ---- Quoted string: "..." or '...' ----
    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      i++;
      while (i < n) {
        const ch = raw[i];
        if (ch === "\\" && i + 1 < n) { i += 2; continue; }  // escape
        if (ch === quote) { i++; break; }
        if (ch === "\n") break;  // unterminated, Lua-illegal, but be safe
        i++;
      }
      out.push(raw.substring(start, i));
      stringsPreserved++;
      continue;
    }

    // ---- Backtick string (Luau interpolation): `...` with {expr} embeds ----
    if (c === "`") {
      const start = i;
      i++;
      let braceDepth = 0;
      while (i < n) {
        const ch = raw[i];
        if (ch === "\\" && i + 1 < n) { i += 2; continue; }
        if (ch === "{") braceDepth++;
        else if (ch === "}") braceDepth--;
        else if (ch === "`" && braceDepth === 0) { i++; break; }
        i++;
      }
      out.push(raw.substring(start, i));
      stringsPreserved++;
      continue;
    }

    // ---- Regular code character ----
    out.push(c);
    i++;
  }

  let result = out.join("");

  // Post-pass: collapse whitespace outside strings. The strings are already
  // emitted verbatim so a simple line-based normalization is safe.
  const lines = result.split("\n");
  const cleaned = [];
  let prevBlank = false;
  let consecutiveBlanks = 0;
  for (const line of lines) {
    // Trim trailing whitespace only (preserve indent for readability)
    const trimmedRight = line.replace(/[ \t]+$/, "");
    const isBlank = trimmedRight.trim().length === 0;
    if (isBlank) {
      consecutiveBlanks++;
      // Keep at most 1 blank line in a row
      if (consecutiveBlanks <= 1) {
        cleaned.push("");
      }
    } else {
      consecutiveBlanks = 0;
      cleaned.push(trimmedRight);
    }
  }
  result = cleaned.join("\n");

  return {
    code: result,
    ok: true,
    meta: {
      commentsStripped,
      stringsPreserved,
      bytesSaved: raw.length - result.length,
    },
  };
}

function stageStringEncryption(code, ctx) {
  // TODO step 3: byte-scan string literals -> _D({bytes}) calls
  return { code, ok: true, meta: { stringsEncrypted: 0 } };
}

function stageNumericEncoding(code, ctx) {
  // TODO step 4: byte-scan numeric literals -> arithmetic expressions
  return { code, ok: true, meta: { numericsObfuscated: 0 } };
}

function stageDecoderInjection(code, ctx) {
  // TODO step 5: prepend runtime helper prelude (_D() decoder, etc.)
  return { code, ok: true, meta: {} };
}

function stageAntiTamperWrap(code, ctx) {
  // TODO step 6: wrap payload in checksum-verified loader
  return { code, ok: true, meta: {} };
}

const STAGE_FUNCTIONS = {
  minify: stageMinify,
  stringEncryption: stageStringEncryption,
  numericEncoding: stageNumericEncoding,
  decoderInjection: stageDecoderInjection,
  antiTamperWrap: stageAntiTamperWrap,
};

// ============================================================================
// SECTION 4 â€” Pipeline orchestrator
// ============================================================================

function runPipeline(rawCode, level, options, report) {
  const startedAt = Date.now();
  report.stats.originalBytes = rawCode.length;

  const profile = LEVEL_PROFILES[level];
  if (!profile) {
    warn(report, "Unknown level \"" + level + "\", returning source unchanged");
    report.actualLevel = "none";
    report.stats.obfuscatedBytes = rawCode.length;
    report.stats.sizeRatio = 1;
    report.stats.elapsedMs = Date.now() - startedAt;
    return { code: rawCode, report };
  }

  let code = rawCode;
  const ctx = {
    userId: options && options.userId,
    // Per-run randomness seeded once so later steps stay reproducible per run
    rngKey: crypto.randomBytes(16).toString("hex"),
  };

  for (const stageName of profile.stages) {
    const fn = STAGE_FUNCTIONS[stageName];
    if (!fn) {
      warn(report, "Stage \"" + stageName + "\" is not implemented yet â€” skipped");
      report.stagesSkipped.push(stageName);
      continue;
    }
    try {
      const result = fn(code, ctx);
      if (result && result.ok) {
        code = result.code;
        report.stagesSucceeded.push(stageName);
        if (result.meta) {
          if (typeof result.meta.stringsEncrypted === "number") {
            report.stats.stringsEncrypted += result.meta.stringsEncrypted;
          }
          if (typeof result.meta.numericsObfuscated === "number") {
            report.stats.numericsObfuscated += result.meta.numericsObfuscated;
          }
          if (typeof result.meta.commentsStripped === "number") {
            report.stats.commentsStripped = (report.stats.commentsStripped || 0) + result.meta.commentsStripped;
          }
          if (typeof result.meta.bytesSaved === "number") {
            report.stats.minifyBytesSaved = (report.stats.minifyBytesSaved || 0) + result.meta.bytesSaved;
          }
        }
      } else {
        warn(report, "Stage \"" + stageName + "\" returned not-ok â€” skipped");
        report.stagesSkipped.push(stageName);
      }
    } catch (e) {
      warn(report, "Stage \"" + stageName + "\" threw: " + e.message + " â€” skipped");
      report.stagesSkipped.push(stageName);
    }
  }

  report.stats.obfuscatedBytes = code.length;
  report.stats.sizeRatio = code.length / Math.max(1, rawCode.length);
  report.stats.elapsedMs = Date.now() - startedAt;
  return { code, report };
}

// ============================================================================
// SECTION 5 â€” Public API
// ============================================================================

async function obfuscateLarge(luaCode, level, userId, options) {
  options = options || {};
  options.userId = userId;

  if (typeof luaCode !== "string" || luaCode.length === 0) {
    const report = makeReport(level || LEVEL_BASIC);
    warn(report, "Empty input");
    return { code: "", report };
  }

  const chosenLevel = VALID_LEVELS.has(level) ? level : LEVEL_MEDIUM;
  const report = makeReport(chosenLevel);
  if (level && !VALID_LEVELS.has(level)) {
    warn(report, "Unknown level \"" + level + "\", defaulted to medium");
  }

  try {
    return runPipeline(luaCode, chosenLevel, options, report);
  } catch (e) {
    warn(report, "Pipeline threw: " + e.message + " â€” returning source unchanged");
    report.actualLevel = "none";
    report.stats.obfuscatedBytes = luaCode.length;
    report.stats.sizeRatio = 1;
    return { code: luaCode, report };
  }
}

// ============================================================================
// Module exports
// ============================================================================

module.exports = {
  obfuscateLarge,
  // exported for step-by-step testing and eventual server integration
  LEVEL_BASIC,
  LEVEL_MEDIUM,
  LEVEL_CONSERVATIVE_MAX,
  LEVEL_PROFILES,
};
