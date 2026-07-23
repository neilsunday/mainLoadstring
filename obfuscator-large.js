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
      stringsSkipped: 0,
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
  // Step 3: byte-scan string literals, encrypt each with XOR+shift, emit
  // as _D({byte-table}) call. Decoder function is injected in step 5.
  //
  // Whitelist strategy â€” conservative. We skip:
  //   * Short strings (< 4 chars) â€” decoder call is longer than the string
  //   * Roblox service/method names â€” reflection breaks if renamed
  //   * URI patterns (rbxassetid://, http://, https://)
  //   * Short PascalCase (likely class names)
  //   * Long-bracket [[..]] and backtick `..` strings (complex, skipped)
  //
  // Encryption is deterministic per-run: key + shift + mask4 seeded from
  // ctx.rngKey (set once per pipeline invocation). The decoder function
  // name is fixed as _D so step 5 knows what to inject.

  // Derive per-run encryption params from ctx.rngKey (32 hex chars = 16 bytes)
  const seedBytes = [];
  for (let i = 0; i < ctx.rngKey.length; i += 2) {
    seedBytes.push(parseInt(ctx.rngKey.substring(i, i + 2), 16));
  }
  const key0 = seedBytes[0] || 137;
  const key1 = seedBytes[1] || 211;
  const key2 = seedBytes[2] || 47;
  const key3 = seedBytes[3] || 199;
  const shift = ((seedBytes[4] || 13) % 15) + 3;  // 3..17

  // Persist keys on ctx so step 5 (decoder injection) can regenerate the
  // matching _D function.
  ctx.stringEncKeys = { key0, key1, key2, key3, shift };

  // ---- Reserved strings that must never be encrypted (reflection surface) ----
  const RESERVED = new Set([
    // Roblox services
    "Players","ReplicatedStorage","ReplicatedFirst","ServerStorage","ServerScriptService",
    "Workspace","Lighting","StarterGui","StarterPack","StarterPlayer","StarterPlayerScripts",
    "StarterCharacterScripts","SoundService","Chat","TextChatService","Teams","Debris",
    "TweenService","RunService","UserInputService","CoreGui","GuiService","ContextActionService",
    "HttpService","DataStoreService","MessagingService","MemoryStoreService","PathfindingService",
    "PhysicsService","CollectionService","MarketplaceService","TeleportService","PolicyService",
    "LocalizationService","BadgeService","GamePassService","GroupService","FriendsService",
    "SocialService","AnalyticsService","AssetService","InsertService","ContentProvider",
    "TextService","VoiceChatService","Stats","LogService","VirtualUser","VirtualInputManager",
    "HapticService","VRService","NotificationService","AdService","RbxAnalyticsService",
    // Common method names called by name string
    "GetService","FindFirstChild","FindFirstChildOfClass","FindFirstChildWhichIsA",
    "FindFirstAncestor","FindFirstAncestorOfClass","FindFirstAncestorWhichIsA",
    "WaitForChild","GetChildren","GetDescendants","IsA","IsDescendantOf","Destroy","Clone",
    "GetPropertyChangedSignal","GetAttribute","SetAttribute","GetAttributes",
    "FireServer","FireClient","FireAllClients","InvokeServer","InvokeClient","Fire",
    "Connect","Disconnect","Wait","Once","ConnectParallel",
    "OnClientEvent","OnServerEvent","OnClientInvoke","OnServerInvoke","OnInvoke",
    "HttpGet","HttpGetAsync","HttpPost","HttpPostAsync",
    "JSONEncode","JSONDecode","PostAsync","RequestAsync","GetAsync","SetAsync",
    "UpdateAsync","RemoveAsync",
    // Character parts
    "Humanoid","HumanoidRootPart","Head","Torso","UpperTorso","LowerTorso",
    "LeftArm","RightArm","LeftLeg","RightLeg","Character","Backpack",
    "PlayerGui","PlayerScripts","Camera","Terrain","Animator",
    // Type names
    "boolean","number","string","table","function","userdata","thread","nil",
  ]);

  function shouldEncrypt(value) {
    if (typeof value !== "string") return false;
    if (value.length < 4) return false;
    if (value.length > 8000) return false;
    if (RESERVED.has(value)) return false;
    // Roblox asset URIs
    if (/^rbxass?et/i.test(value)) return false;
    if (/^rbxthumb/i.test(value)) return false;
    // HTTP URLs
    if (/^https?:\/\//.test(value)) return false;
    // Metamethods (__index, __newindex, etc.)
    if (/^__[a-z]/.test(value) && value.length <= 20) return false;
    // Short PascalCase (class names)
    if (/^[A-Z][a-z]/.test(value) && value.length < 8) return false;
    // Short ALL_CAPS (enums)
    if (/^[A-Z0-9_]+$/.test(value) && value.length < 8) return false;
    // Package versioning like "sleitnick_net@0.1.0"
    if (/^[A-Za-z_][A-Za-z0-9_]*@[0-9]/.test(value)) return false;
    // Class-name suffixes commonly reflected
    if (/(Service|Controller|Handler|Manager|Remote|Event|Signal|Module)$/.test(value)
        && value.length < 40) return false;
    return true;
  }

  // Encrypt a JS string to a Lua byte-table literal.
  function encryptToTable(value) {
    const bytes = [];
    const mask = [key0, key1, key2, key3];
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i) & 0xff;
      const k = (mask[i & 3] + ((i + shift) % 11)) & 0xff;
      const enc = ((c ^ k) - shift) & 0xff;
      bytes.push(enc);
    }
    return "_D({" + bytes.join(",") + "})";
  }

  // Unescape a Lua single/double-quoted string literal to its runtime value.
  // We need this to know what to encrypt.
  function unescapeLuaString(raw) {
    // raw includes outer quotes
    const inner = raw.slice(1, -1);
    let result = "";
    let i = 0;
    while (i < inner.length) {
      const c = inner[i];
      if (c === "\\" && i + 1 < inner.length) {
        const next = inner[i + 1];
        // Common escapes
        if (next === "n") { result += "\n"; i += 2; continue; }
        if (next === "t") { result += "\t"; i += 2; continue; }
        if (next === "r") { result += "\r"; i += 2; continue; }
        if (next === "a") { result += "\x07"; i += 2; continue; }
        if (next === "b") { result += "\b"; i += 2; continue; }
        if (next === "f") { result += "\f"; i += 2; continue; }
        if (next === "v") { result += "\x0b"; i += 2; continue; }
        if (next === "\\" || next === "\"" || next === "'") { result += next; i += 2; continue; }
        // \ddd (decimal escape, up to 3 digits)
        if (/[0-9]/.test(next)) {
          let j = i + 1;
          let digits = "";
          while (j < inner.length && digits.length < 3 && /[0-9]/.test(inner[j])) {
            digits += inner[j];
            j++;
          }
          const code = parseInt(digits, 10);
          if (code <= 255) {
            result += String.fromCharCode(code);
            i = j;
            continue;
          }
        }
        // \xHH hex escape
        if (next === "x" && i + 3 < inner.length) {
          const hex = inner.substring(i + 2, i + 4);
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            result += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            continue;
          }
        }
        // Unknown escape â€” keep as-is
        result += c + next;
        i += 2;
        continue;
      }
      result += c;
      i++;
    }
    return result;
  }

  // Now the byte scan: same shape as step 2's minify but instead of emitting
  // strings verbatim, we run each through shouldEncrypt + encryptToTable.
  const raw = code;
  const n = raw.length;
  const out = [];
  let i = 0;
  let stringsEncrypted = 0;
  let stringsSkipped = 0;

  while (i < n) {
    const c = raw[i];
    const c2 = raw[i + 1];

    // Long-bracket string [[..]] or [=[..]=] â€” skip encryption, emit verbatim
    if (c === "[") {
      let j = i + 1;
      let level = 0;
      while (j < n && raw[j] === "=") { level++; j++; }
      if (j < n && raw[j] === "[") {
        const closer = "]" + "=".repeat(level) + "]";
        const endIdx = raw.indexOf(closer, j + 1);
        if (endIdx > 0) {
          out.push(raw.substring(i, endIdx + closer.length));
          i = endIdx + closer.length;
          continue;
        }
      }
    }

    // Comments already stripped in step 2, but be defensive: skip if seen
    if (c === "-" && c2 === "-") {
      let j = i + 2;
      if (j < n && raw[j] === "[") {
        let level = 0;
        let k = j + 1;
        while (k < n && raw[k] === "=") { level++; k++; }
        if (k < n && raw[k] === "[") {
          const closer = "]" + "=".repeat(level) + "]";
          const endIdx = raw.indexOf(closer, k + 1);
          if (endIdx > 0) { i = endIdx + closer.length; continue; }
          i = n; continue;
        }
      }
      const nl = raw.indexOf("\n", i);
      i = nl < 0 ? n : nl;
      continue;
    }

    // Quoted string "..." or '...' â€” CANDIDATE FOR ENCRYPTION
    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      i++;
      while (i < n) {
        const ch = raw[i];
        if (ch === "\\" && i + 1 < n) { i += 2; continue; }
        if (ch === quote) { i++; break; }
        if (ch === "\n") break;
        i++;
      }
      const literalRaw = raw.substring(start, i);
      const value = unescapeLuaString(literalRaw);

      if (shouldEncrypt(value)) {
        out.push(encryptToTable(value));
        stringsEncrypted++;
      } else {
        out.push(literalRaw);
        stringsSkipped++;
      }
      continue;
    }

    // Backtick string â€” skip encryption (interpolation is complex)
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
      continue;
    }

    // Regular code character
    out.push(c);
    i++;
  }

  return {
    code: out.join(""),
    ok: true,
    meta: {
      stringsEncrypted,
      stringsSkipped,
    },
  };
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
          if (typeof result.meta.stringsSkipped === "number") {
            report.stats.stringsSkipped = (report.stats.stringsSkipped || 0) + result.meta.stringsSkipped;
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
