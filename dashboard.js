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
    stages: ["minify", "stringEncryption", "numericEncoding", "decoderInjection", "bytecodeVMWrap", "antiTamperWrap"],
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
      numericsSkipped: 0,
      commentsStripped: 0,
      minifyBytesSaved: 0,
      decoderInjected: false,
      antiTamperApplied: false,
      vmCallsWrapped: 0,
      vmBytecodeBytes: 0,
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
  // Step 4: byte-scan numeric literals, replace with equivalent arithmetic.
  //
  // Design:
  //   * Only encode PLAIN integer literals (0-9)+ â€” skip floats, hex, scientific.
  //   * Skip when the number appears inside a _D({...}) byte table (step 3
  //     output) â€” we detect this by tracking depth of _D( braces.
  //   * Skip small numbers (< 2 chars) â€” not worth the overhead.
  //   * Randomize which strategy per number: add, sub, xor, mul.
  //   * Never touch numbers inside string literals or backticks.
  //
  // Character state machine â€” same shape as step 2/3.

  const seedBytes = [];
  for (let i = 0; i < ctx.rngKey.length; i += 2) {
    seedBytes.push(parseInt(ctx.rngKey.substring(i, i + 2), 16));
  }
  let rngIdx = 0;
  function nextRand() {
    const v = seedBytes[rngIdx % seedBytes.length];
    rngIdx++;
    return v || 42;
  }

  function encodeInt(n) {
    // Choose strategy based on next random byte
    const strategy = nextRand() % 4;
    if (strategy === 0) {
      // add: n = a + b
      const a = 1 + (nextRand() % Math.max(1, n));
      return "(" + a + "+" + (n - a) + ")";
    }
    if (strategy === 1) {
      // sub: n = a - b
      const a = n + (nextRand() % 100) + 1;
      return "(" + a + "-" + (a - n) + ")";
    }
    if (strategy === 2) {
      // xor: n = a XOR b, where b = a XOR n
      const a = (nextRand() * 3 + 17) & 0xff;
      const b = a ^ n;
      return "bit32.bxor(" + a + "," + b + ")";
    }
    // mul when divisible, else fallback to add
    for (let d = 2; d <= 12; d++) {
      if (n % d === 0 && n / d > 0) {
        return "(" + d + "*" + (n / d) + ")";
      }
    }
    const a = 1 + (nextRand() % Math.max(1, n));
    return "(" + a + "+" + (n - a) + ")";
  }

  const raw = code;
  const n = raw.length;
  const out = [];
  let i = 0;
  let numericsObfuscated = 0;
  let numericsSkipped = 0;

  while (i < n) {
    const c = raw[i];
    const c2 = raw[i + 1];

    // Skip long-bracket strings verbatim
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

    // Skip -- comments (defensive)
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

    // Skip string literals verbatim
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
      out.push(raw.substring(start, i));
      continue;
    }

    // Skip backtick strings verbatim
    if (c === "`") {
      const start = i;
      i++;
      let bd = 0;
      while (i < n) {
        const ch = raw[i];
        if (ch === "\\" && i + 1 < n) { i += 2; continue; }
        if (ch === "{") bd++;
        else if (ch === "}") bd--;
        else if (ch === "`" && bd === 0) { i++; break; }
        i++;
      }
      out.push(raw.substring(start, i));
      continue;
    }

    // Skip _D({...}) byte tables â€” the numbers inside are our own encrypted
    // bytes and must not be re-encoded. Detect the pattern "_D({" and skip
    // to the matching "})".
    if (c === "_" && raw.substring(i, i + 4) === "_D({") {
      const closeIdx = raw.indexOf("})", i + 4);
      if (closeIdx > 0) {
        out.push(raw.substring(i, closeIdx + 2));
        i = closeIdx + 2;
        continue;
      }
    }

    // Numeric literal detection: digit not preceded by identifier char
    if (c >= "0" && c <= "9") {
      const prev = i > 0 ? raw[i - 1] : " ";
      const isIdentPrefix = /[A-Za-z_0-9]/.test(prev);
      if (isIdentPrefix) {
        // e.g. `_0xabc123` or `var123` â€” this digit is part of an identifier,
        // not a numeric literal. Emit as-is.
        out.push(c);
        i++;
        continue;
      }
      // Scan the full numeric literal
      let j = i;
      // Handle hex prefix: 0x... or 0X... â€” skip these (leave as-is)
      if (raw[j] === "0" && (raw[j + 1] === "x" || raw[j + 1] === "X")) {
        while (j < n && /[0-9a-fA-F]/.test(raw[j + 2] ? raw[j] : raw[j])) {
          if (j < i + 2) { j++; continue; }
          if (!/[0-9a-fA-F]/.test(raw[j])) break;
          j++;
        }
        // Actually simpler: scan until non-hexdigit
        j = i + 2;
        while (j < n && /[0-9a-fA-F]/.test(raw[j])) j++;
        out.push(raw.substring(i, j));
        i = j;
        numericsSkipped++;
        continue;
      }
      // Scan integer digits
      while (j < n && raw[j] >= "0" && raw[j] <= "9") j++;
      // Check for decimal point or scientific notation â€” skip if present
      if (j < n && (raw[j] === "." || raw[j] === "e" || raw[j] === "E")) {
        // Consume the whole float/scientific
        while (j < n && /[0-9.eE+\-]/.test(raw[j])) {
          // stop at unary +/- unless right after e/E
          if ((raw[j] === "+" || raw[j] === "-") &&
              !(raw[j - 1] === "e" || raw[j - 1] === "E")) break;
          j++;
        }
        out.push(raw.substring(i, j));
        i = j;
        numericsSkipped++;
        continue;
      }

      const numStr = raw.substring(i, j);
      const num = parseInt(numStr, 10);
      // Only encode integers with 2+ digits and value >= 10
      if (numStr.length >= 2 && num >= 10 && num < 1000000) {
        out.push(encodeInt(num));
        numericsObfuscated++;
      } else {
        out.push(numStr);
        numericsSkipped++;
      }
      i = j;
      continue;
    }

    out.push(c);
    i++;
  }

  return {
    code: out.join(""),
    ok: true,
    meta: { numericsObfuscated, numericsSkipped },
  };
}

function stageDecoderInjection(code, ctx) {
  // Step 5: prepend the runtime _D() decoder that reverses step 3 encryption.
  //
  // Encryption formula (from step 3):
  //   enc = ((original XOR (key[i%4] + (i+shift)%11)) - shift) mod 256
  // Decryption (this function):
  //   b = (enc + shift) mod 256
  //   original = b XOR (key[i%4] + (i+shift)%11)
  //
  // If no strings were encrypted in step 3, we skip injection entirely.
  // Detection: presence of ctx.stringEncKeys.

  if (!ctx.stringEncKeys) {
    // No string encryption happened â€” no need for a decoder.
    return { code, ok: true, meta: { decoderInjected: false } };
  }

  const k = ctx.stringEncKeys;
  const key0 = k.key0, key1 = k.key1, key2 = k.key2, key3 = k.key3;
  const shift = k.shift;

  // Build the decoder. Emitted as a single expression so we don't clutter the
  // global namespace. Uses bit32.bxor which is available in Roblox Lua.
  const decoder =
    "local _D=(function() " +
    "local k={" + key0 + "," + key1 + "," + key2 + "," + key3 + "} " +
    "local s=" + shift + " " +
    "return function(t) " +
    "local r={} " +
    "for i=1,#t do " +
    "local b=(t[i]+s)%256 " +
    "b=bit32.bxor(b,(k[((i-1)%4)+1]+((i-1+s)%11))%256) " +
    "r[i]=string.char(b) " +
    "end " +
    "return table.concat(r) " +
    "end " +
    "end)();\n";

  return {
    code: decoder + code,
    ok: true,
    meta: { decoderInjected: true, decoderBytes: decoder.length },
  };
}

function stageAntiTamperWrap(code, ctx) {
  // Step 6: wrap the entire payload in a checksum-verified loader.
  //
  // The obfuscated code becomes a Lua string literal. A small loader
  // computes a Fletcher-16 checksum at runtime and compares it against
  // embedded expected values. Any modification of the payload string
  // (even a single byte) triggers an error before execution.
  //
  // Escaping: we use decimal escapes for control characters and quotes
  // so the payload string is safe regardless of what bytes it contains.
  // This is bulletproof â€” no chance of quote/backslash confusion.

  // Compute Fletcher-16 checksum of the payload bytes.
  function fletcher16(str) {
    let a = 0, b = 0;
    for (let i = 0; i < str.length; i++) {
      a = (a + str.charCodeAt(i)) % 65535;
      b = (b + a) % 65535;
    }
    return { a, b };
  }

  // Escape a JS string into a Lua string literal. Uses double quotes and
  // decimal \ddd escapes for non-printable/quote/backslash characters.
  function escapeLuaString(str) {
    const out = [];
    out.push('"');
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      // Printable ASCII except quote and backslash
      if (c >= 0x20 && c <= 0x7E && c !== 0x22 && c !== 0x5C) {
        out.push(String.fromCharCode(c));
      } else {
        // Decimal escape â€” always 3 digits when the next char is a digit,
        // otherwise minimal digits. Safest: always 3 digits.
        out.push("\\" + c.toString().padStart(3, "0"));
      }
    }
    out.push('"');
    return out.join("");
  }

  const checksum = fletcher16(code);
  const payloadLiteral = escapeLuaString(code);

  const loader =
    "local _P=" + payloadLiteral + ";" +
    "local function _V(s) " +
      "local a,b=0,0 " +
      "for i=1,#s do " +
        "a=(a+string.byte(s,i))%65535 " +
        "b=(b+a)%65535 " +
      "end " +
      "return a,b " +
    "end;" +
    "local _a,_b=_V(_P);" +
    "if _a~=" + checksum.a + " or _b~=" + checksum.b + " then " +
      "error(\"[tamper] payload integrity check failed\") " +
    "end;" +
    "local _f=loadstring or load;" +
    "local _fn,_err=_f(_P);" +
    "if not _fn then error(\"[loader] \"..tostring(_err)) end;" +
    "_fn()";

  return {
    code: loader,
    ok: true,
    meta: {
      antiTamperApplied: true,
      checksumA: checksum.a,
      checksumB: checksum.b,
      loaderBytes: loader.length - code.length,
      payloadBytes: code.length,
    },
  };
}

// ============================================================================
// SECTION 4 (Step 9) â€” Bytecode-level VM wrap for eligible call statements
// ============================================================================
// Detects simple call patterns `ident(literal, literal, ...)` at line
// boundaries and rewrites them into VM bytecode dispatches. The VM interpreter
// is embedded at the top of the output. This is Option A scope â€” literal
// arguments only, no variables. Coverage is intentionally small (~1-5% of
// statements) so we never risk syntax breakage on complex expressions.
//
// Opcodes (1 byte each):
//   1  LOADK <num>     â€” push literal number (uint16 next 2 bytes)
//   2  LOADS <idx>     â€” push string from pool (uint8 next byte)
//   3  GETG  <idx>     â€” push global by name (from string pool)
//   4  CALL  <nargs>   â€” call top-of-stack fn with N args, discard result
//  10  HALT            â€” end of program for this dispatch
// ============================================================================

function stageBytecodeVMWrap(code, ctx) {
  // We collect eligible call patterns into a "programs" array, each entry
  // being a bytecode sequence + string pool. At the end, we emit a single
  // combined bytecode blob with entry points, and a shared VM interpreter.
  const stringPool = [];
  const stringPoolMap = new Map();
  function poolIndex(s) {
    if (stringPoolMap.has(s)) return stringPoolMap.get(s);
    const idx = stringPool.length;
    if (idx > 255) return -1;  // pool overflow â€” skip this wrap
    stringPool.push(s);
    stringPoolMap.set(s, idx);
    return idx;
  }

  // Program bytecode segments; each segment is a byte array
  const programs = [];
  function addProgram(bytes) {
    const entry = programs.reduce((n, p) => n + p.length, 0);
    programs.push(bytes);
    return entry;
  }

  // Regex to find simple call statements: ident(literal-args-only) at line
  // boundaries. This is deliberately narrow â€” only literal numbers and
  // simple double-quoted strings, single-line only.
  //
  // Example matches:
  //   print("hello")
  //   warn("error", 42)
  //   print(1, 2, 3)
  //
  // NOT matched (safely skipped):
  //   x = print("hi")            â€” assignment
  //   print(x)                   â€” variable arg
  //   obj.method("x")            â€” member access
  //   print("multi\nline")       â€” hard escapes (skip for simplicity)

  const IDENT = "[A-Za-z_][A-Za-z0-9_]*";
  const LITERAL = '(?:"[^"\n\\]{0,120}"|\d+)';
  const CALL_RE = new RegExp(
    "(^|\n)(\s*)(" + IDENT + ")\((" + LITERAL + "(?:\s*,\s*" + LITERAL + ")*)\)(?=\s*(?:\n|;|$))",
    "g"
  );

  let vmCallsWrapped = 0;
  let vmProgramsBuilt = 0;

  const result = code.replace(CALL_RE, (match, leading, indent, fnName, argsStr) => {
    // Skip if the ident is a Lua keyword or common local name
    const RESERVED = new Set(["if","then","else","elseif","end","for","do","while","repeat",
      "until","function","local","return","break","in","and","or","not","true","false","nil"]);
    if (RESERVED.has(fnName)) return match;

    // Parse args
    const args = [];
    let ok = true;
    let i = 0;
    const s = argsStr;
    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++;
      if (i >= s.length) break;
      if (s[i] === '"') {
        // String literal
        let j = i + 1;
        while (j < s.length && s[j] !== '"' && s[j] !== "\\") j++;
        if (j >= s.length || s[j] !== '"') { ok = false; break; }
        args.push({ type: "string", value: s.substring(i + 1, j) });
        i = j + 1;
      } else if (/\d/.test(s[i])) {
        let j = i;
        while (j < s.length && /\d/.test(s[j])) j++;
        const n = parseInt(s.substring(i, j), 10);
        if (n > 65535) { ok = false; break; }
        args.push({ type: "number", value: n });
        i = j;
      } else {
        ok = false;
        break;
      }
      while (i < s.length && /\s/.test(s[i])) i++;
      if (i < s.length && s[i] === ",") i++;
    }
    if (!ok) return match;

    // Build bytecode: GETG fnName, LOADK/LOADS args..., CALL nargs, HALT
    const bytes = [];
    // GETG
    const fnPoolIdx = poolIndex(fnName);
    if (fnPoolIdx < 0) return match;  // pool overflow
    bytes.push(3, fnPoolIdx);  // GETG
    // Arguments
    for (const arg of args) {
      if (arg.type === "string") {
        const idx = poolIndex(arg.value);
        if (idx < 0) return match;
        bytes.push(2, idx);  // LOADS
      } else {
        // LOADK <uint16>
        bytes.push(1, (arg.value >> 8) & 0xff, arg.value & 0xff);
      }
    }
    // CALL <nargs>
    bytes.push(4, args.length & 0xff);
    // HALT
    bytes.push(10);

    const entry = addProgram(bytes);
    vmCallsWrapped++;
    vmProgramsBuilt++;

    // Replace the call statement with a VM dispatch
    return leading + indent + "_VM(" + entry + ")";
  });

  if (vmCallsWrapped === 0) {
    return { code, ok: true, meta: { vmCallsWrapped: 0, vmBytecodeBytes: 0 } };
  }

  // Concatenate all program segments into a single bytecode blob
  const combined = [];
  for (const p of programs) {
    for (const b of p) combined.push(b);
  }

  // Emit the bytecode table
  const bcTable = "{" + combined.join(",") + "}";

  // Emit the string pool (using our existing _D if strings are encrypted,
  // else plain strings). For simplicity in this toy VM, plain strings.
  const escapedPool = stringPool.map(s => {
    // Escape for a Lua double-quoted string
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r") + '"';
  });
  const poolTable = "{" + escapedPool.join(",") + "}";

  // The VM interpreter â€” 10 opcodes as designed
  const vm =
    "local _BC=" + bcTable + ";\n" +
    "local _SP=" + poolTable + ";\n" +
    "local function _VM(pc) " +
      "local stk={} " +
      "local sp=0 " +
      "while true do " +
        "local op=_BC[pc] " +
        "if op==1 then " +
          "local hi=_BC[pc+1] " +
          "local lo=_BC[pc+2] " +
          "sp=sp+1 stk[sp]=hi*256+lo " +
          "pc=pc+3 " +
        "elseif op==2 then " +
          "sp=sp+1 stk[sp]=_SP[_BC[pc+1]+1] " +
          "pc=pc+2 " +
        "elseif op==3 then " +
          "sp=sp+1 stk[sp]=_G[_SP[_BC[pc+1]+1]] " +
          "pc=pc+2 " +
        "elseif op==4 then " +
          "local n=_BC[pc+1] " +
          "local args={} " +
          "for i=1,n do args[i]=stk[sp-n+i] end " +
          "local fn=stk[sp-n] " +
          "sp=sp-n-1 " +
          "if type(fn)==\"function\" then fn(table.unpack(args,1,n)) end " +
          "pc=pc+2 " +
        "elseif op==10 then return " +
        "else return " +
        "end " +
      "end " +
    "end;\n";

  return {
    code: vm + result,
    ok: true,
    meta: {
      vmCallsWrapped,
      vmProgramsBuilt,
      vmBytecodeBytes: combined.length,
      vmStringPoolSize: stringPool.length,
      vmInterpreterBytes: vm.length,
    },
  };
}

const STAGE_FUNCTIONS = {
  minify: stageMinify,
  stringEncryption: stageStringEncryption,
  numericEncoding: stageNumericEncoding,
  decoderInjection: stageDecoderInjection,
  bytecodeVMWrap: stageBytecodeVMWrap,
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
          if (typeof result.meta.numericsSkipped === "number") {
            report.stats.numericsSkipped = (report.stats.numericsSkipped || 0) + result.meta.numericsSkipped;
          }
          if (typeof result.meta.commentsStripped === "number") {
            report.stats.commentsStripped = (report.stats.commentsStripped || 0) + result.meta.commentsStripped;
          }
          if (typeof result.meta.bytesSaved === "number") {
            report.stats.minifyBytesSaved = (report.stats.minifyBytesSaved || 0) + result.meta.bytesSaved;
          }
          if (typeof result.meta.decoderInjected === "boolean") {
            report.stats.decoderInjected = result.meta.decoderInjected;
          }
          if (typeof result.meta.antiTamperApplied === "boolean") {
            report.stats.antiTamperApplied = result.meta.antiTamperApplied;
          }
          if (typeof result.meta.vmCallsWrapped === "number") {
            report.stats.vmCallsWrapped = (report.stats.vmCallsWrapped || 0) + result.meta.vmCallsWrapped;
          }
          if (typeof result.meta.vmBytecodeBytes === "number") {
            report.stats.vmBytecodeBytes = (report.stats.vmBytecodeBytes || 0) + result.meta.vmBytecodeBytes;
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
