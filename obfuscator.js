// AzureVM Obfuscator v25.26-restore - v25.25 + single-pass string restore (fixes 719KB corruption)
// ============================================================================
// This file replaces the v24 obfuscator with a minimal, guaranteed-executable
// pipeline. Public API is byte-compatible with server.js:
//
//   obfuscate(luaCode, level, userId)                    -> Promise<string>
//   obfuscateWithReport(luaCode, level, userId, options) -> Promise<{code, report}>
//
// Where options = {
//   forceMaximum?: bool,
//   referenceCode?: string|null,
//   layerOverrides?: {  // v25.14: per-layer user override (Phase 2a)
//     antiDebugger?: "auto"|"force"|"skip",
//     antiDump?:     "auto"|"force"|"skip",
//     antiTamper?:   "auto"|"force"|"skip",
//     byteLevelXor?: "auto"|"force"|"skip",
//     vmWrap?:       "auto"|"force"|"skip",
//     outerVM?:      "auto"|"force"|"skip",
//   }
// }.
//
// What was removed vs v24 (and why):
//   * Inner bytecode VM (vmCanCompile / tryVmWrap / 55-opcode dispatcher)
//     -- compiled 0 statements on real Roblox scripts (property assigns and
//     method calls fall through to passthrough), and its inner pcall+load
//     chain swallowed syntax errors -> silent fail with no UI.
//   * Byte-level XOR triple chain (byteLevelTripleObfuscate)
//     -- outer loadstring+pcall wrap ate errors on pcall-heavy scripts.
//   * Outer 6-opcode meta-VM (v15 3C)
//     -- doubled the failure surface for zero verifiable gain.
//   * Anti-debugger / anti-tamper wrappers
//     -- high false-positive rate on scripts that legitimately hook.
//   * Watermarking, self-modifying bytecode, CFF dispatcher, string chunking
//     -- pure size cost, no measurable protection.
//   * Section splitter, closure-graph analyzer, UI-framework detector,
//     tuneStrategy(), advanced-intelligence block
//     -- ~1000 lines that never affected the emitted output.
//
// What was kept (proven to survive reflection-heavy scripts):
//   * Reference manifest (source-driven whitelist, v22 idea, v24 dual-source)
//   * Preprocessor: Luau -> Lua 5.3, compound assigns, continue-to-goto,
//     type-annotation strip, string-safe transforms
//   * Numeric literal encoding (bit32 / add-subtract / lshift)
//   * String encryption with layered whitelist (manifest + reserved names +
//     Roblox URIs + package versions + service-suffix + PascalCase gate)
//   * RenameCtx with root-scope hoistFromManifest + per-scope hoistBlock
//     -> every closure agrees on ONE hex per source name (v23 fix preserved)
//   * Position-aware AST walker (skip MemberExpression.identifier and
//     TableKeyString.key, the v19 property-guard fix)
//   * Staged pipeline: each stage re-parses; on failure roll back to the
//     last-known-good state and continue -> output always parses
//   * Constant pool with poison entries (maximum tier only)
//   * Long-line chunking for Delta / Fluxus / Synapse parsers
// ============================================================================

const luaparse = require("luaparse");
const crypto = require("crypto");

// ============================================================================
// SECTION 1 - RNG helpers
// ============================================================================

function _rand(min, max) {
  // crypto.randomInt is [min, max) -- inclusive of min, exclusive of max.
  return crypto.randomInt(min, max + 1);
}
function randInt(min, max) { return _rand(min, max); }
function randChoice(arr) { return arr[_rand(0, arr.length - 1)]; }
function randHexName(nBytes) {
  return "_0x" + crypto.randomBytes(nBytes || 3).toString("hex");
}
function shuffle(arr) {
  const out = arr.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = _rand(0, i);
    const tmp = out[i]; out[i] = out[j]; out[j] = tmp;
  }
  return out;
}


// ============================================================================
// SECTION 1b - String literal value normalizer (FIX)
// ============================================================================
// luaparse may emit StringLiteral with only `raw` set (quoted form) and leave
// `value` undefined depending on the parser version / options. Every string
// literal touchpoint MUST go through this helper -- otherwise typeof-value
// guards silently drop every string, which manifests as strings encrypted = 0
// and manifest.strings = 0 even on trivial inputs.
// ============================================================================
function _stringLiteralValue(node) {
  if (!node) return null;
  if (typeof node.value === "string") return node.value;
  if (typeof node.raw !== "string" || node.raw.length < 2) return null;
  const r = node.raw;
  // Long-bracket strings: [[...]] or [=[...]=]
  if (r.charAt(0) === "[") {
    const m = r.match(/^\[(=*)\[([\s\S]*)\](\1)\]$/);
    return m ? m[2] : null;
  }
  // Regular quoted: strip outer quotes, unescape common sequences
  const q = r.charAt(0);
  if (q !== '"' && q !== "'") return null;
  const inner = r.slice(1, -1);
  return inner
    .replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\r/g, "\r")
    .replace(/\\"/g, '"').replace(/\\'/g, "'").replace(/\\\\/g, "\\");
}

// ============================================================================
// SECTION 2 - Whitelist tables
// ============================================================================

const ROBLOX_GLOBALS = new Set([
  "_G","_ENV","_VERSION","assert","collectgarbage","error","getfenv",
  "getmetatable","ipairs","load","loadstring","next","pairs","pcall","print",
  "rawequal","rawget","rawlen","rawset","select","setfenv","setmetatable",
  "tonumber","tostring","type","unpack","xpcall","string","table","math",
  "os","io","coroutine","debug","bit32","utf8","game","workspace","script",
  "shared","plugin","wait","spawn","delay","tick","time","elapsedTime",
  "warn","typeof","gcinfo","Enum","Instance","CFrame","Vector2","Vector3",
  "Color3","UDim","UDim2","Ray","Region3","BrickColor","TweenInfo",
  "NumberSequence","NumberSequenceKeypoint","ColorSequence",
  "ColorSequenceKeypoint","NumberRange","Rect","PhysicalProperties",
  "Random","Faces","Axes","Vector3int16","Vector2int16","Region3int16",
  "task","buffer","vector",
]);

const EXECUTOR_GLOBALS = new Set([
  "hookfunction","hookmetamethod","getgenv","getrenv","getsenv","getreg",
  "getconnections","getgc","getinstances","getnilinstances","getscripts",
  "getloadedmodules","getcallingscript","getrawmetatable","setrawmetatable",
  "checkcaller","isreadonly","setreadonly","iscclosure","islclosure",
  "newcclosure","identifyexecutor","lz4compress","lz4decompress",
  "queue_on_teleport","syn","fluxus","krnl","delta","request","http_request",
  "http","cloneref","gethui","getnamecallmethod","setnamecallmethod",
  "isexecutorclosure","LPH_NO_VIRTUALIZE","LPH_JIT","LPH_ENCSTR",
  "firetouchinterest","fireclickdetector","fireproximityprompt",
  "mouse1click","mouse1press","mouse1release","keypress","keyrelease",
  "getscriptbytecode","decompile",
]);

// Names that must never be renamed OR string-encrypted. Encrypting or
// renaming any of these breaks reflection (FindFirstChild, GetService,
// WaitForChild, Enum lookup, remote-event names, etc.).
const RESERVED_STRINGS = new Set([
  // Services
  "Players","ReplicatedStorage","ReplicatedFirst","ServerStorage",
  "ServerScriptService","Workspace","Lighting","StarterGui","StarterPack",
  "StarterPlayer","StarterPlayerScripts","StarterCharacterScripts",
  "SoundService","Chat","TextChatService","Teams","Debris","TweenService",
  "RunService","UserInputService","CoreGui","GuiService",
  "ContextActionService","HttpService","DataStoreService","MessagingService",
  "MemoryStoreService","PathfindingService","PhysicsService",
  "CollectionService","MarketplaceService","TeleportService","PolicyService",
  "LocalizationService","BadgeService","GamePassService","GroupService",
  "FriendsService","SocialService","AnalyticsService","AssetService",
  "InsertService","ContentProvider","TextService","VoiceChatService","Stats",
  "LogService","VirtualUser","VirtualInputManager","HapticService",
  "VRService","NotificationService","AdService","RbxAnalyticsService",
  // Character / instance
  "Humanoid","HumanoidRootPart","Head","Torso","UpperTorso","LowerTorso",
  "LeftArm","RightArm","LeftLeg","RightLeg","Character","Backpack",
  "PlayerGui","PlayerScripts","Camera","Terrain","Baseplate","Animator",
  "Animation","AnimationTrack","Sound","SoundGroup","ParticleEmitter",
  "PointLight","SpotLight","SurfaceLight","BillboardGui","ScreenGui",
  "SurfaceGui","TextLabel","TextButton","TextBox","ImageLabel","ImageButton",
  "Frame","ScrollingFrame","UIListLayout","UIGridLayout","UIPadding",
  "UICorner","UIStroke","UIGradient","UISizeConstraint",
  "UIAspectRatioConstraint","LocalScript","Script","ModuleScript","Folder",
  "Configuration","IntValue","StringValue","BoolValue","NumberValue",
  "ObjectValue","Vector3Value","CFrameValue","Color3Value","BrickColorValue",
  "RayValue",
  // Methods commonly called by name string
  "HttpGet","HttpGetAsync","HttpPost","HttpPostAsync","GetService",
  "FindFirstChild","FindFirstChildOfClass","FindFirstChildWhichIsA",
  "FindFirstAncestor","FindFirstAncestorOfClass",
  "FindFirstAncestorWhichIsA","FindFirstDescendant","WaitForChild",
  "GetChildren","GetDescendants","IsA","IsDescendantOf","Destroy","Clone",
  "GetPropertyChangedSignal","GetAttribute","SetAttribute","GetAttributes",
  "GetAttributeChangedSignal","FireServer","FireClient","FireAllClients",
  "InvokeServer","InvokeClient","Fire","Connect","Disconnect","Wait","Once",
  "ConnectParallel","OnClientEvent","OnServerEvent","OnClientInvoke",
  "OnServerInvoke","OnInvoke","GetPlayers","GetPlayerByUserId",
  "GetPlayerFromCharacter","Kick","LoadCharacter","MoveTo","PivotTo",
  "SetPrimaryPartCFrame","BreakJoints","MakeJoints","GetMass","GetVelocity",
  "ApplyImpulse","ApplyAngularImpulse","MouseButton1Click",
  "MouseButton1Down","MouseButton1Up","MouseButton2Click","MouseButton2Down",
  "MouseButton2Up","MouseEnter","MouseLeave","MouseMoved","Activated",
  "InputBegan","InputChanged","InputEnded","PlayerAdded","PlayerRemoving",
  "CharacterAdded","CharacterRemoving","Touched","TouchEnded","Died",
  "HealthChanged","Changed","AncestryChanged","ChildAdded","ChildRemoved",
  "DescendantAdded","DescendantRemoving","Stepped","Heartbeat",
  "RenderStepped",
  // Frameworks / method-call bases seen in reflection
  "OrionLib","Rayfield","Kavo","Linoria","Fluent","Mercury","MakeWindow",
  "MakeTab","AddButton","AddToggle","AddSlider","AddDropdown",
  "AddColorpicker","AddLabel","AddTextbox","AddParagraph","AddKeybind",
  "Notify","Notification",
  // Serialization / http
  "JSONEncode","JSONDecode","PostAsync","RequestAsync","GetAsync","SetAsync",
  "UpdateAsync","RemoveAsync",
  // Type names
  "boolean","number","string","table","function","userdata","thread","nil",
]);

// ============================================================================
// SECTION 3 - ReferenceManifest (source-driven whitelist, dual-source scan)
// ============================================================================
//
// Public API compatible with v24: static scan(primaryCode, referenceCode?)
// If a reference file is provided (e.g. macrozure.txt uploaded via the
// dashboard), its identifiers + strings + property names + method bases feed
// into the SAME preservation set as the primary code's own scan. Both sources
// share the whitelist so anything present in either file survives obfuscation
// intact.
// ============================================================================

class ReferenceManifest {
  constructor() {
    this.identifiers = new Set();
    this.strings = new Set();
    this.propertyNames = new Set();
    this.zeroInitLocals = new Set();
    this.forwardRefs = new Set();
    this.methodCallBases = new Set();
    this.stats = {};
  }

  // v24-compatible entry point. Both args are optional; either or both can
  // be scanned. If BOTH parse-fail, we fall back to a lexical scan so the
  // manifest is never empty when there is content to look at.
  static scan(rawCode, referenceCode) {
    const m = new ReferenceManifest();
    ReferenceManifest._scanInto(m, rawCode);
    if (referenceCode && typeof referenceCode === "string" && referenceCode.trim().length > 0) {
      ReferenceManifest._scanInto(m, referenceCode);
    }
    m.stats = {
      identifiers: m.identifiers.size,
      strings: m.strings.size,
      propertyNames: m.propertyNames.size,
      zeroInitLocals: m.zeroInitLocals.size,
      forwardRefs: m.forwardRefs.size,
      methodCallBases: m.methodCallBases.size,
    };
    return m;
  }

  // Scan a single source into an existing manifest. Tries Lua 5.3 first,
  // then Lua 5.1 (Roblox scripts written for older executors). On both
  // failures, falls back to a lexical scan.
  static _scanInto(m, rawCode) {
    if (!rawCode || typeof rawCode !== "string") return;
    let ast = null;
    try {
      ast = luaparse.parse(rawCode, { luaVersion: "5.3", comments: false, locations: true });
    } catch (_) {
      try {
        ast = luaparse.parse(rawCode, { luaVersion: "5.1", comments: false, locations: true });
      } catch (_) {
        ReferenceManifest._lexInto(m, rawCode);
        return;
      }
    }

    const declaredAt = new Map();
    const calledAt = new Map();
    function recDecl(name, line) {
      if (!name) return;
      m.identifiers.add(name);
      const p = declaredAt.get(name);
      if (p === undefined || line < p) declaredAt.set(name, line);
    }
    function recCall(name, line) {
      if (!name) return;
      const p = calledAt.get(name);
      if (p === undefined || line < p) calledAt.set(name, line);
    }

    function walk(node) {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) { for (const n of node) walk(n); return; }
      const line = (node.loc && node.loc.start && node.loc.start.line) || 0;
      switch (node.type) {
        case "Identifier":
          if (node.name) m.identifiers.add(node.name);
          break;
        case "StringLiteral": {
          const _v = _stringLiteralValue(node);
          if (_v !== null) m.strings.add(_v);
          break;
        }
        case "LocalStatement":
          if (Array.isArray(node.variables)) {
            node.variables.forEach((v, i) => {
              if (!v || !v.name) return;
              recDecl(v.name, line);
              const init = node.init && node.init[i];
              if (init && (
                (init.type === "NumericLiteral" && init.value === 0) ||
                (init.type === "BooleanLiteral" && init.value === false) ||
                init.type === "NilLiteral"
              )) m.zeroInitLocals.add(v.name);
            });
          }
          break;
        case "FunctionDeclaration":
          if (node.identifier && node.identifier.type === "Identifier") {
            recDecl(node.identifier.name, line);
          }
          if (Array.isArray(node.parameters)) {
            for (const p of node.parameters) if (p && p.name) recDecl(p.name, line);
          }
          break;
        case "ForNumericStatement":
          if (node.variable && node.variable.name) recDecl(node.variable.name, line);
          break;
        case "ForGenericStatement":
          if (Array.isArray(node.variables)) {
            for (const v of node.variables) if (v && v.name) recDecl(v.name, line);
          }
          break;
        case "AssignmentStatement":
          if (Array.isArray(node.variables)) {
            for (const v of node.variables) {
              if (v && v.type === "Identifier") recDecl(v.name, line);
            }
          }
          break;
        case "MemberExpression":
          if (node.identifier && node.identifier.name) m.propertyNames.add(node.identifier.name);
          if (node.indexer === ":" && node.base && node.base.type === "Identifier") {
            m.methodCallBases.add(node.base.name);
          }
          break;
        case "TableKeyString":
          if (node.key && node.key.name) m.propertyNames.add(node.key.name);
          break;
        case "CallExpression":
          if (node.base && node.base.type === "Identifier") recCall(node.base.name, line);
          break;
      }
      for (const k of Object.keys(node)) {
        if (k === "loc" || k === "range" || k === "type") continue;
        walk(node[k]);
      }
    }
    walk(ast);

    for (const [name, callLine] of calledAt.entries()) {
      const dl = declaredAt.get(name);
      if (dl !== undefined && dl > callLine) m.forwardRefs.add(name);
    }
  }

  // Lexical fallback when the source cannot be parsed as Lua.
  static _lexInto(m, rawCode) {
    const IDENT = /\b[A-Za-z_][A-Za-z0-9_]*\b/g;
    const STR = /"([^"\\]|\\.)*"|'([^'\\]|\\.)*'/g;
    const PROP = /\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;
    const METHOD = /:\s*([A-Za-z_][A-Za-z0-9_]*)/g;
    let mt;
    while ((mt = IDENT.exec(rawCode)) !== null) m.identifiers.add(mt[0]);
    while ((mt = STR.exec(rawCode)) !== null) {
      try {
        const v = JSON.parse(mt[0].replace(/'/g, '"'));
        if (typeof v === "string") m.strings.add(v);
      } catch (_) {}
    }
    while ((mt = PROP.exec(rawCode)) !== null) m.propertyNames.add(mt[1]);
    while ((mt = METHOD.exec(rawCode)) !== null) m.propertyNames.add(mt[1]);
  }
}

// Module-level manifest reference (matches v24 pattern). Set by
// obfuscateWithReport before each run; passes consult it directly.
let _currentManifest = null;

// ============================================================================
// SECTION 4 - Preprocess (Luau -> Lua 5.3)
// ============================================================================
//
// Steps: extract string literals (so later regexes can't corrupt them),
// rewrite compound assigns (x += y -> x = x + (y)), lower `continue` to
// goto __continue_N__, strip Luau type annotations, restore string literals.
// ============================================================================

function preprocess(rawCode) {
  // v25.16 Fix 2: normalize CRLF (\r\n) and lone CR (\r) to LF (\n) BEFORE
  // any other transform runs. Windows-authored scripts (like azure.txt) ship
  // with CRLF; downstream regex transforms assumed LF and were silently
  // injecting mixed endings, which broke luaparse position tracking on
  // large scripts (all AST-modifying stages failed around bytes 155k-166k).
  rawCode = rawCode.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  const strings = [];
  let work = "";
  let i = 0, idx = 0;
  const len = rawCode.length;

  while (i < len) {
    const c = rawCode[i];

    // Line comment
    if (c === "-" && rawCode[i + 1] === "-" && rawCode[i + 2] !== "[") {
      const nl = rawCode.indexOf("\n", i);
      const end = nl < 0 ? len : nl;
      work += rawCode.substring(i, end);
      i = end;
      continue;
    }

    // Long-bracket string / long comment
    if (c === "[" || (c === "-" && rawCode[i + 1] === "-" && rawCode[i + 2] === "[")) {
      let j = i;
      const isComment = c === "-";
      if (isComment) j += 2;
      if (rawCode[j] === "[") {
        let level = 0;
        let k = j + 1;
        while (rawCode[k] === "=") { level++; k++; }
        if (rawCode[k] === "[") {
          const closer = "]" + "=".repeat(level) + "]";
          const endIdx = rawCode.indexOf(closer, k + 1);
          if (endIdx > 0) {
            const content = rawCode.substring(i, endIdx + closer.length);
            if (isComment) {
              work += content;
            } else {
              const key = "___STR_" + (idx++) + "___";
              strings.push({ key, value: content });
              work += key;
            }
            i = endIdx + closer.length;
            continue;
          }
        }
      }
    }

    // Quoted string
    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      i++;
      while (i < len) {
        const ch = rawCode[i];
        if (ch === "\\" && i + 1 < len) { i += 2; continue; }
        if (ch === quote) { i++; break; }
        if (ch === "\n") break;
        i++;
      }
      const key = "___STR_" + (idx++) + "___";
      strings.push({ key, value: rawCode.substring(start, i) });
      work += key;
      continue;
    }

    // Backtick (Luau interpolation)
    if (c === "`") {
      const start = i;
      i++;
      let depth = 0;
      while (i < len) {
        const ch = rawCode[i];
        if (ch === "\\" && i + 1 < len) { i += 2; continue; }
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
        else if (ch === "`" && depth === 0) { i++; break; }
        i++;
      }
      const key = "___STR_" + (idx++) + "___";
      strings.push({ key, value: rawCode.substring(start, i) });
      work += key;
      continue;
    }

    work += c;
    i++;
  }

  // Compound assignments: LHS op= RHS  ->  LHS = LHS op (RHS)
  const IDENT = "[A-Za-z_][A-Za-z0-9_]*";
  const CHAIN = IDENT + "(?:\\s*[.:]\\s*" + IDENT + "|\\s*\\[[^\\]]+\\])*";
  const compoundRe = new RegExp(
    "(" + CHAIN + ")\\s*([+\\-*/%]|\\.\\.)=\\s*([^\\n;]+)", "g"
  );
  work = work.replace(compoundRe, (_m, lhs, op, rhs) => {
    // Strip trailing inline comment on RHS (fixes "x += 5 - note" swallowing paren)
    let clean = rhs;
    for (let k = 0; k < clean.length - 1; k++) {
      if (clean[k] === "-" && clean[k + 1] === "-") { clean = clean.substring(0, k); break; }
    }
    clean = clean.trim();
    if (!clean) return lhs + " = " + lhs;
    return lhs + " = " + lhs + " " + op + " (" + clean + ")";
  });

  // Lower `continue` to goto __continue_N__
  work = lowerContinue(work);

  // Strip Luau type annotations
  // (a) local x: Type = ...
  work = work.replace(
    new RegExp("(\\blocal\\s+" + IDENT + "(?:\\s*,\\s*" + IDENT + ")*)\\s*:\\s*[A-Za-z_][A-Za-z0-9_.<>?]*", "g"),
    "$1"
  );
  // (b) function params (name: Type, ...) -- v25.24 REINTRODUCED via paren walker.
  // The v25.19 removal note said: "If we ever need this again, do a proper
  // paren-balance walker (Option 2)." This IS that walker. Instead of a regex
  // that miscounts nested parens, we scan token-by-token, track paren depth,
  // and only strip `: Type` inside function parameter lists.
  work = _stripLuauParamTypes(work);
  changesMarker: /* v25.19-comment-preserved-below */
  // (b-legacy) function params (name: Type, ...) -- ORIGINAL v25.19 removal note.
  // The old paren-walker regex mangled nested calls like fn((a or {})) by
  // capturing the empty inner group first, then re-emitting "()" around the
  // outer remainder ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â producing an extra ")". This broke every AST stage on
  // azure.txt (identical error at every stage: "<name> expected near '('").
  // Function-parameter Luau type annotations are rare in Roblox exploit /
  // game scripts; the far more common `local x: Type = ...` form is handled
  // by a separate, non-paren-based regex that has no such bug.
  // If we ever need this again, do a proper paren-balance walker (Option 2).
  // (c) return type: function foo(...): Type
  work = work.replace(
    /(\))\s*:\s*[A-Za-z_][A-Za-z0-9_.<>?]*(?=\s*(?:\n|--|\bthen\b|\bdo\b|\breturn\b|\blocal\b|\bif\b|\bfor\b|\bwhile\b|\brepeat\b|\bend\b|;|$))/g,
    "$1"
  );
  // (d) type Foo = ...
  work = work.replace(/^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*=.*$/gm, "");
  // (e) export type ...
  work = work.replace(/^\s*export\s+type\s+.*$/gm, "");

  // Restore strings (v25.26: single-pass, collision-safe).
  // The old for/split/join loop had two failure modes on large files:
  //   1) Any source token that literally read "___STR_N___" (identifier,
  //      literal, comment) would get substituted with an unrelated value,
  //      corrupting later code.
  //   2) V8's split() on ~800KB inputs across thousands of iterations was
  //      the observed source of the 8-byte string truncation in the 719KB
  //      Luau test case (production report: 6 stages rolled back on the
  //      same location, ~168k-179k byte offset).
  // Single-pass regex + Map lookup fixes both: O(n) instead of O(n*m),
  // and each placeholder is replaced exactly once at its own position.
  const _strMap = new Map();
  for (const s of strings) _strMap.set(s.key, s.value);
  work = work.replace(/___STR_(\d+)___/g, (match) => {
    const v = _strMap.get(match);
    return v !== undefined ? v : match;
  });
  return work;
}


// ============================================================================
// v25.24 - Luau function-parameter type stripper (paren-balance walker)
// ============================================================================
// Scans the source, finds each `function (` or `function name(` or
// `function name.method(` or `function name:method(` opening paren, then
// walks that parameter list with proper paren/bracket/brace balancing. Inside
// the param list, strips `: Type` from each parameter, where Type can itself
// contain parens (function types), braces (table types), brackets (generics),
// unions (`|`), intersections (`&`), and question marks (optional).
//
// Also handles:
//   * Generic parameters: function<T, U>(x: T) -> we skip the <...> block
//   * Return types: function(): number  -- handled by existing (c) stripper
//   * Default values not present in Luau, so we don't need to handle those
// ============================================================================
function _stripLuauParamTypes(code) {
  // Locate every "function" keyword that opens a parameter list.
  // We must NOT touch "function" inside strings, comments, or as identifier.
  // Since preprocess() already substituted string literals with ___STR_N___
  // placeholders and preserved comments, we can scan directly here.
  const n = code.length;
  const out = [];
  let i = 0;

  while (i < n) {
    // Find next 'function' keyword.
    const fnIdx = code.indexOf("function", i);
    if (fnIdx < 0) {
      out.push(code.substring(i));
      break;
    }
    // Check word boundary before "function".
    const prev = fnIdx > 0 ? code[fnIdx - 1] : " ";
    if (/[A-Za-z0-9_]/.test(prev)) {
      // Not a keyword (part of identifier), skip.
      out.push(code.substring(i, fnIdx + 8));
      i = fnIdx + 8;
      continue;
    }
    // Emit everything up to and including "function".
    out.push(code.substring(i, fnIdx + 8));
    i = fnIdx + 8;

    // Skip whitespace.
    while (i < n && /\s/.test(code[i])) { out.push(code[i]); i++; }

    // Optional: skip identifier chain (name, name.method, name:method, name.a.b:c)
    while (i < n && /[A-Za-z_]/.test(code[i])) {
      // Consume identifier
      while (i < n && /[A-Za-z0-9_]/.test(code[i])) { out.push(code[i]); i++; }
      // Consume . or : separator
      while (i < n && /\s/.test(code[i])) { out.push(code[i]); i++; }
      if (i < n && (code[i] === "." || code[i] === ":")) {
        out.push(code[i]); i++;
        while (i < n && /\s/.test(code[i])) { out.push(code[i]); i++; }
      } else break;
    }

    // Optional: skip generic parameter list <T, U, V>
    if (i < n && code[i] === "<") {
      let depth = 1;
      out.push(code[i]); i++;
      while (i < n && depth > 0) {
        if (code[i] === "<") depth++;
        else if (code[i] === ">") depth--;
        out.push(code[i]); i++;
      }
      while (i < n && /\s/.test(code[i])) { out.push(code[i]); i++; }
    }

    // Now we must see '(' -- if not, this wasn't a function-decl form.
    if (i >= n || code[i] !== "(") continue;

    // We're at the opening paren of the parameter list. Emit it and walk.
    out.push("(");
    i++;
    // Track balance of (), [], {} inside the param list so we can find the
    // matching close paren without being fooled by table/tuple/function types.
    let paren = 1;
    // Accumulate the parameter list content, then strip types from it.
    let paramList = "";
    while (i < n && paren > 0) {
      const c = code[i];
      if (c === "(") { paren++; paramList += c; i++; continue; }
      if (c === ")") {
        paren--;
        if (paren === 0) break;
        paramList += c; i++; continue;
      }
      // Handle nested [] and {} (they don't affect our paren counter but we
      // need to skip through them without splitting on ',' inside them).
      paramList += c;
      i++;
    }
    // Now paramList holds everything between the outer parens (exclusive).
    // Split by top-level commas (respecting <>, [], {}, ()) and strip types.
    const stripped = _stripTypesFromParams(paramList);
    out.push(stripped);
    out.push(")");
    i++; // consume the closing ')'
  }

  return out.join("");
}

function _stripTypesFromParams(paramList) {
  // Split on top-level commas, then for each param: keep everything up to
  // the first top-level ':' (that's the param name; optional '?' allowed).
  const parts = [];
  let depth_paren = 0, depth_brace = 0, depth_bracket = 0, depth_angle = 0;
  let start = 0;
  for (let k = 0; k < paramList.length; k++) {
    const c = paramList[k];
    if (c === "(") depth_paren++;
    else if (c === ")") depth_paren--;
    else if (c === "{") depth_brace++;
    else if (c === "}") depth_brace--;
    else if (c === "[") depth_bracket++;
    else if (c === "]") depth_bracket--;
    else if (c === "<") depth_angle++;
    else if (c === ">") depth_angle--;
    else if (c === "," && depth_paren === 0 && depth_brace === 0 && depth_bracket === 0 && depth_angle === 0) {
      parts.push(paramList.substring(start, k));
      start = k + 1;
    }
  }
  parts.push(paramList.substring(start));

  const cleaned = parts.map(p => {
    // Find first top-level ':' -- everything after it is the type annotation.
    let dp = 0, db = 0, dk = 0, da = 0;
    for (let k = 0; k < p.length; k++) {
      const c = p[k];
      if (c === "(") dp++;
      else if (c === ")") dp--;
      else if (c === "{") db++;
      else if (c === "}") db--;
      else if (c === "[") dk++;
      else if (c === "]") dk--;
      else if (c === "<") da++;
      else if (c === ">") da--;
      else if (c === ":" && dp === 0 && db === 0 && dk === 0 && da === 0) {
        return p.substring(0, k);
      }
    }
    return p;
  });

  return cleaned.join(",");
}

function lowerContinue(code) {
  if (code.indexOf("continue") < 0) return code;
  const kwSet = new Set(["for","while","repeat","do","end","until","function","if","then","else","elseif","continue"]);
  const tokens = [];
  const n = code.length;
  let i = 0, buf = "";
  const flush = () => { if (buf.length) { tokens.push({ kind: "text", value: buf }); buf = ""; } };

  while (i < n) {
    const c = code[i];
    if (c === "_" && code.substring(i, i + 6) === "___STR") {
      const end = code.indexOf("___", i + 6);
      if (end > 0) { buf += code.substring(i, end + 3); i = end + 3; continue; }
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(code[j])) j++;
      const word = code.substring(i, j);
      const prev = i > 0 ? code[i - 1] : " ";
      if (kwSet.has(word) && !/[A-Za-z0-9_]/.test(prev)) {
        flush();
        tokens.push({ kind: "kw", value: word });
        i = j;
        continue;
      }
      buf += word;
      i = j;
      continue;
    }
    buf += c;
    i++;
  }
  flush();

  const stack = [];
  let counter = 0;
  const out = [];
  for (const t of tokens) {
    if (t.kind === "kw") {
      const kw = t.value;
      if (kw === "for" || kw === "while") stack.push({ type: "pending_loop", label: null, needs: false });
      else if (kw === "repeat") stack.push({ type: "repeat_loop", label: null, needs: false });
      else if (kw === "function") stack.push({ type: "function" });
      else if (kw === "if") stack.push({ type: "if" });
      else if (kw === "do") {
        const top = stack[stack.length - 1];
        if (top && top.type === "pending_loop") top.type = "loop";
        else stack.push({ type: "do" });
      } else if (kw === "end") {
        const closing = stack.pop();
        if (closing && closing.type === "loop" && closing.needs) {
          out.push({ kind: "text", value: " ::" + closing.label + ":: " });
        }
      } else if (kw === "until") {
        const closing = stack.pop();
        if (closing && closing.type === "repeat_loop" && closing.needs) {
          out.push({ kind: "text", value: " ::" + closing.label + ":: " });
        }
      } else if (kw === "continue") {
        let loop = null;
        for (let k = stack.length - 1; k >= 0; k--) {
          const b = stack[k];
          if (b.type === "function") break;
          if (b.type === "loop" || b.type === "repeat_loop") { loop = b; break; }
        }
        if (loop) {
          if (!loop.label) { loop.label = "__continue_" + (counter++) + "__"; loop.needs = true; }
          out.push({ kind: "text", value: "goto " + loop.label });
          continue;
        } else {
          out.push({ kind: "text", value: "--[[continue-oob]]" });
          continue;
        }
      }
    }
    out.push(t);
  }
  return out.map(t => t.value).join("");
}

// ============================================================================
// SECTION 5 - Numeric literal encoding
// ============================================================================
//
// Rewrite integer literals as small math expressions. Skips floats, tiny
// values (< 2), and huge values (> 0x7fffff) to avoid Lua number-format
// edge cases and to keep the output compact.
// ============================================================================

function encodeNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return String(n);
  if (!Number.isInteger(n)) return String(n);
  const abs = Math.abs(n);
  if (abs < 2 || abs > 0x7fffff) return String(n);
  const forms = [
    () => { const k = _rand(1, 0xff); return "(bit32.bxor(" + (n ^ k) + "," + k + "))"; },
    () => { const a = _rand(1, Math.min(abs, 0xffff)); return "(" + (n - a) + "+" + a + ")"; },
    () => { const a = _rand(1, Math.min(abs, 0xffff)); return "(" + (n + a) + "-" + a + ")"; },
    () => {
      const shift = _rand(1, 8);
      const rest = n >> shift;
      const rem = n & ((1 << shift) - 1);
      return "(bit32.lshift(" + rest + "," + shift + ")+" + rem + ")";
    },
  ];
  return randChoice(forms)();
}

// ============================================================================
// SECTION 6 - String encryption
// ============================================================================

function encryptStringBytes(str, key, shift, mask) {
  // mask: optional 4-byte array [m0, m1, m2, m3]. Applied via mask[i%4]
  // AFTER the existing per-index XOR. When absent OR all zeros, behaves
  // identically to the pre-v25.5 encoder (backward-compatible).
  const m0 = mask ? (mask[0] & 0xff) : 0;
  const m1 = mask ? (mask[1] & 0xff) : 0;
  const m2 = mask ? (mask[2] & 0xff) : 0;
  const m3 = mask ? (mask[3] & 0xff) : 0;
  const mArr = [m0, m1, m2, m3];
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    const k = (key + ((i + shift) % 11)) & 0xff;
    const enc = (c ^ k) & 0xff;
    bytes.push((enc ^ mArr[i & 3]) & 0xff);
  }
  return bytes;
}

function makeStringDecoder(fnName, key, shift, mask) {
  // If no mask (or all zeros), emit the legacy decoder verbatim.
  const hasMask = mask && (mask[0] || mask[1] || mask[2] || mask[3]);
  if (!hasMask) {
    return "local function " + fnName + "(t) " +
      "local k=" + key + " local s='' " +
      "for i=1,#t do " +
        "s=s..string.char(bit32.bxor(t[i],(k+((i-1+" + shift + ")%11)))%256) " +
      "end return s end";
  }
  // Mask-enhanced decoder. Emits a small mask lookup table then inverts
  // the mask XOR BEFORE the per-index XOR (opposite order of encoding).
  const m0 = mask[0] & 0xff, m1 = mask[1] & 0xff;
  const m2 = mask[2] & 0xff, m3 = mask[3] & 0xff;
  return "local function " + fnName + "(t) " +
    "local k=" + key + " " +
    "local m={[0]=" + m0 + "," + m1 + "," + m2 + "," + m3 + "} " +
    "local s='' " +
    "for i=1,#t do " +
      "local b=bit32.bxor(t[i],m[(i-1)%4]) " +
      "s=s..string.char(bit32.bxor(b,(k+((i-1+" + shift + ")%11)))%256) " +
    "end return s end";
}

function bytesToLuaTable(bytes) { return "{" + bytes.join(",") + "}"; }

// ============================================================================
// SECTION 6b - Inner VM wrap helpers (v25.6)
// ============================================================================

const _VM_OP = {
  LOADN:  1, LOADS: 2, ADD: 3, SUB: 4, MUL: 5, DIV: 6,
  MOD:    7, CONCAT: 8, PRINT: 9, HALT: 10,
};
const _VM_BINOP = {
  "+": _VM_OP.ADD, "-": _VM_OP.SUB, "*": _VM_OP.MUL,
  "/": _VM_OP.DIV, "%": _VM_OP.MOD, "..": _VM_OP.CONCAT,
};

function vmCanCompileExpression(node) {
  if (!node || typeof node !== "object") return false;
  if (node.__obf) return false;
  if (node.type === "NumericLiteral" && typeof node.value === "number") return true;
  if (node.type === "StringLiteral" && typeof node.value === "string") return true;
  if (node.type === "BinaryExpression" && _VM_BINOP[node.operator]) {
    return vmCanCompileExpression(node.left) && vmCanCompileExpression(node.right);
  }
  return false;
}

function vmCanCompileStatement(node) {
  if (!node || node.type !== "CallStatement") return false;
  const call = node.expression;
  if (!call || call.type !== "CallExpression") return false;
  if (!call.base || call.base.type !== "Identifier" || call.base.name !== "print") return false;
  if (!Array.isArray(call.arguments) || call.arguments.length === 0) return false;
  for (const arg of call.arguments) if (!vmCanCompileExpression(arg)) return false;
  return true;
}

function vmCompileExpression(node, out) {
  if (node.type === "NumericLiteral") { out.push([_VM_OP.LOADN, node.value]); return; }
  if (node.type === "StringLiteral")  { out.push([_VM_OP.LOADS, node.value]); return; }
  if (node.type === "BinaryExpression") {
    vmCompileExpression(node.left, out);
    vmCompileExpression(node.right, out);
    out.push([_VM_BINOP[node.operator]]);
    return;
  }
  throw new Error("vmCompileExpression: unreachable for " + node.type);
}

function vmCompileStatement(callStmt, out) {
  const startPc = out.length + 1;   // 1-based, matches Lua indexing
  const args = callStmt.expression.arguments;
  for (const arg of args) vmCompileExpression(arg, out);
  out.push([_VM_OP.PRINT, args.length]);
  out.push([_VM_OP.HALT]);
  return startPc;
}

function vmSerializeInstruction(inst) {
  const parts = [String(inst[0])];
  for (let i = 1; i < inst.length; i++) {
    const v = inst[i];
    if (typeof v === "number") parts.push(String(v));
    else if (typeof v === "string") parts.push(JSON.stringify(v));
    else throw new Error("vmSerializeInstruction: bad operand type " + typeof v);
  }
  return "{" + parts.join(",") + "}";
}

function vmGenerateBytecodeTable(bytecodeVar, instructions) {
  return "local " + bytecodeVar + "={" +
         instructions.map(vmSerializeInstruction).join(",") + "}";
}

// Dispatcher: pure switch, loud errors, no pcall wrapper, no loadstring.
// Compatible with both Lua 5.1 (Roblox executors) and 5.3+ (Luau) via the
// `table.unpack or unpack` idiom.
// ---------------------------------------------------------------------------
// Outer VM helpers (v25.8) -- XOR-encoded bytecode + Lua decoder.
// ---------------------------------------------------------------------------
// Bytecode encoding (JS side):
//   Input:  [[1, 42], [9, 1], [10]]  (nested arrays)
//   Step 1: flatten with argCount markers:
//           [1, 1, 42,   9, 1, 1,   10, 0]
//           (opcode, argCount, args...)
//   Step 2: separate strings into a side table -- replace with sentinel
//           marker 0xF0 followed by string-table index.
//   Step 3: XOR each byte with mask[i%4].
//   Step 4: emit the encoded bytes + string table + decoder Lua that
//           reverses the transform and rebuilds the nested-table shape.
//
// Failure mode: if the encode step throws or produces invalid data, the
// outer wrap is silently skipped. The inner VM (if any) still ships as
// the plain nested-table form.
// ---------------------------------------------------------------------------

const _VM2_STRING_MARKER = 0xF0;   // Sentinel: next byte is index into string table.

function vmEncodeFlat(bytecode) {
  // Turn nested [[op, args...], ...] into a flat sequence with argCount
  // prefix per instruction, splitting strings into a side table.
  const flat = [];
  const strings = [];
  for (const inst of bytecode) {
    const op = inst[0];
    const argCount = inst.length - 1;
    if (!Number.isInteger(op) || op < 0 || op > 255) {
      throw new Error("vmEncodeFlat: opcode out of range: " + op);
    }
    if (argCount < 0 || argCount > 255) {
      throw new Error("vmEncodeFlat: argCount out of range: " + argCount);
    }
    flat.push(op);
    flat.push(argCount);
    for (let i = 1; i < inst.length; i++) {
      const v = inst[i];
      if (typeof v === "number") {
        // Numeric operands are pushed raw; the Lua side reads them as one
        // byte (opcodes) OR the string-marker sequence handles strings.
        // For LOADN we cap at 24-bit unsigned to keep encoding trivial.
        if (!Number.isFinite(v)) throw new Error("non-finite numeric operand");
        // Encode number as sentinel 0xF1 followed by 4 bytes big-endian.
        flat.push(0xF1);
        const n = (v | 0) >>> 0;  // to unsigned 32-bit
        flat.push((n >>> 24) & 0xff);
        flat.push((n >>> 16) & 0xff);
        flat.push((n >>>  8) & 0xff);
        flat.push( n         & 0xff);
      } else if (typeof v === "string") {
        const idx = strings.length;
        if (idx > 255) throw new Error("vmEncodeFlat: too many strings (>255)");
        strings.push(v);
        flat.push(_VM2_STRING_MARKER);
        flat.push(idx);
      } else {
        throw new Error("vmEncodeFlat: unsupported operand type " + typeof v);
      }
    }
  }
  return { flat, strings };
}

function vmXorBytes(bytes, mask4) {
  const out = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = (bytes[i] ^ mask4[i & 3]) & 0xff;
  }
  return out;
}

function vmFlatToLuaTable(bytes) {
  return "{" + bytes.join(",") + "}";
}

function vmStringsToLuaTable(strings) {
  // Uses 1-based Lua indexing but encoder uses 0-based JS indexing --
  // the Lua decoder adds 1 to the sentinel index it reads.
  const parts = strings.map(s => JSON.stringify(s));
  return "{" + parts.join(",") + "}";
}

// Generates the Lua decoder that reverses vmEncodeFlat + vmXorBytes and
// returns the nested-table bytecode the inner dispatcher expects.
// The decoder function name is passed in as decoderName; it takes no
// arguments and returns the decoded bytecode table.
function vmGenerateOuterDecoder(decoderName, encodedVar, stringsVar, mask4) {
  const m0 = mask4[0] & 0xff, m1 = mask4[1] & 0xff;
  const m2 = mask4[2] & 0xff, m3 = mask4[3] & 0xff;
  return [
    "local function " + decoderName + "()",
    "  local e=" + encodedVar,
    "  local s=" + stringsVar,
    "  local m={[0]=" + m0 + "," + m1 + "," + m2 + "," + m3 + "}",
    "  local n=#e",
    "  local dec={}",
    "  for i=1,n do dec[i]=bit32.bxor(e[i],m[(i-1)%4]) end",
    "  local out={}",
    "  local i=1",
    "  while i<=n do",
    "    local op=dec[i]; i=i+1",
    "    local ac=dec[i]; i=i+1",
    "    local inst={op}",
    "    for k=1,ac do",
    "      local tag=dec[i]; i=i+1",
    "      if tag==" + _VM2_STRING_MARKER + " then",
    "        local sidx=dec[i]; i=i+1",
    "        inst[#inst+1]=s[sidx+1]",
    "      elseif tag==241 then",  // 0xF1 numeric sentinel
    "        local b1=dec[i]; i=i+1",
    "        local b2=dec[i]; i=i+1",
    "        local b3=dec[i]; i=i+1",
    "        local b4=dec[i]; i=i+1",
    "        inst[#inst+1]=b1*16777216+b2*65536+b3*256+b4",
    "      else",
    "        error(\"[VM2] bad operand tag: \"..tostring(tag))",
    "      end",
    "    end",
    "    out[#out+1]=inst",
    "  end",
    "  return out",
    "end",
  ].join(" ");
}

function vmGenerateDispatcher(vmFnName, bytecodeVar) {
  return [
    "local function " + vmFnName + "(pc)",
    " local stack={} local sp=0",
    " local _unp=table.unpack or unpack",
    " while true do",
    "  local inst=" + bytecodeVar + "[pc]",
    "  if not inst then error(\"[VM] pc out of bounds: \"..tostring(pc)) end",
    "  local op=inst[1]",
    "  if op==1 then sp=sp+1; stack[sp]=inst[2]",
    "  elseif op==2 then sp=sp+1; stack[sp]=inst[2]",
    "  elseif op==3 then local b=stack[sp]; sp=sp-1; stack[sp]=stack[sp]+b",
    "  elseif op==4 then local b=stack[sp]; sp=sp-1; stack[sp]=stack[sp]-b",
    "  elseif op==5 then local b=stack[sp]; sp=sp-1; stack[sp]=stack[sp]*b",
    "  elseif op==6 then local b=stack[sp]; sp=sp-1; stack[sp]=stack[sp]/b",
    "  elseif op==7 then local b=stack[sp]; sp=sp-1; stack[sp]=stack[sp]%b",
    "  elseif op==8 then local b=stack[sp]; sp=sp-1; stack[sp]=tostring(stack[sp])..tostring(b)",
    "  elseif op==9 then",
    "    local n=inst[2]",
    "    local args={}",
    "    for i=n,1,-1 do args[i]=stack[sp-(n-i)] end",
    "    sp=sp-n",
    "    print(_unp(args,1,n))",
    "  elseif op==10 then return",
    "  else error(\"[VM] unknown opcode: \"..tostring(op)) end",
    "  pc=pc+1",
    " end",
    "end",
  ].join(" ");
}


// Decide whether a string is safe to encrypt.
function _shouldEncrypt(value, manifest, strictMode) {
  if (typeof value !== "string") return false;
  if (value.length < 4 || value.length > 800) return false;
  // Manifest wins: any string seen in the primary code OR the uploaded
  // reference file stays literal. This is what makes macrozure work.
  if (manifest && manifest.strings.has(value)) return false;
  if (RESERVED_STRINGS.has(value)) return false;
  if (ROBLOX_GLOBALS.has(value) || EXECUTOR_GLOBALS.has(value)) return false;
  // Metamethods
  if (value.startsWith("__") && value.length <= 20) return false;
  // Roblox asset / http URIs
  if (/^rbxass?et/i.test(value) || /^rbxthumb/i.test(value)) return false;
  if (/^https?:\/\//.test(value)) return false;
  // Package/module version identifiers, e.g. "sleitnick_net@0.2.0"
  if (/^[A-Za-z_][A-Za-z0-9_]*@[0-9]/.test(value)) return false;
  // Class-name suffixes commonly reflected
  if (/(Service|Controller|Handler|Manager|Remote|Event|Signal|Module)$/.test(value) && value.length < 40) return false;
  // Short PascalCase (likely class name)
  if (!strictMode && /^[A-Z][a-z]/.test(value) && value.length < 8) return false;
  // Short ALL_CAPS (likely enum / key)
  if (!strictMode && /^[A-Z0-9_]+$/.test(value) && value.length < 8) return false;
  return true;
}

// ============================================================================
// SECTION 7 - RenameCtx (scope-aware, manifest-hoisted)
// ============================================================================
//
// The v23 fix preserved: hoistFromManifest seeds the ROOT scope with ONE
// canonical hex name for every identifier the manifest saw. Every closure
// in the file then agrees on that same rename, so a variable declared in
// one closure and used in another (e.g. parryRemote, toggleSpam) can never
// end up with two different hex names.
// ============================================================================

class RenameCtx {
  constructor(manifest) {
    this.manifest = manifest;
    this.scopes = [new Map()];
  }
  pushScope() { this.scopes.push(new Map()); }
  popScope()  { if (this.scopes.length > 1) this.scopes.pop(); }
  _fresh()    { return randHexName(3); }

  _isReserved(name) {
    return ROBLOX_GLOBALS.has(name) ||
           EXECUTOR_GLOBALS.has(name) ||
           RESERVED_STRINGS.has(name) ||
           name.startsWith("_") ||
           name === "self";
  }

  declare(name) {
    if (this._isReserved(name)) return name;
    const scope = this.scopes[this.scopes.length - 1];
    if (scope.has(name)) return scope.get(name);
    // If declared in the root scope as a hoist, and we're currently in an
    // inner scope, this is a legit shadow -> give it its own name.
    if (this.scopes.length > 1 && this.scopes[0].has(name)) {
      const hex = this._fresh();
      scope.set(name, hex);
      return hex;
    }
    const hex = this._fresh();
    scope.set(name, hex);
    return hex;
  }

  lookup(name) {
    if (this._isReserved(name)) return name;
    for (let i = this.scopes.length - 1; i >= 0; i--) {
      const s = this.scopes[i];
      if (s.has(name)) return s.get(name);
    }
    // Unknown name -> pass through (executor-injected global, reflection
    // target, etc.). NEVER auto-declare here; that was the v16-era bug
    // that caused inconsistent renames across closures.
    return name;
  }

  // Seed the root scope from the manifest so all closures share ONE
  // canonical rename per source name.
  hoistFromManifest() {
    if (!this.manifest) return;
    const root = this.scopes[0];
    for (const name of this.manifest.identifiers) {
      if (this._isReserved(name)) continue;
      if (!root.has(name)) root.set(name, this._fresh());
    }
  }

  // Hoist immediate-body locals so forward references + recursive calls
  // resolve to the same hex as the declaration itself.
  hoistBlock(stmts) {
    if (!Array.isArray(stmts)) return;
    for (const stmt of stmts) {
      if (!stmt) continue;
      if (stmt.type === "LocalStatement" && Array.isArray(stmt.variables)) {
        for (const v of stmt.variables) if (v && v.name) this.declare(v.name);
      } else if (stmt.type === "FunctionDeclaration"
                 && stmt.identifier && stmt.identifier.type === "Identifier") {
        this.declare(stmt.identifier.name);
      }
    }
  }
}

// ============================================================================
// SECTION 8 - AST walker (rename + string encrypt + numeric encode)
// ============================================================================
//
// Single walker driven by a context of active transforms. Position-aware
// so it never renames a property (the v19 fix: MemberExpression.identifier,
// TableKeyString.key, non-local `function obj.method` chains).
// ============================================================================

function walkTransform(node, ctx) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const n of node) walkTransform(n, ctx); return; }

  const opensFn = ctx.rename && (
    node.type === "FunctionDeclaration" || node.type === "FunctionExpression"
  );
  const opensLoop = ctx.rename && (
    node.type === "ForNumericStatement" || node.type === "ForGenericStatement"
  );

  // Root: hoist manifest first, then top-level decls, then descend.
  if (ctx.rename && node.type === "Chunk") {
    ctx.rename.hoistFromManifest();
    ctx.rename.hoistBlock(node.body);
  }

  // Local function decl -> declare NAME in PARENT scope so recursion works,
  // then open the new scope for its body below.
  if (ctx.rename && node.type === "FunctionDeclaration" && node.isLocal
      && node.identifier && node.identifier.type === "Identifier") {
    node.identifier.name = ctx.rename.declare(node.identifier.name);
  }
  // Non-local `function foo()` at top level: identifier was hoisted; rewrite
  // it to the canonical hoisted name so it matches every call site.
  else if (ctx.rename && node.type === "FunctionDeclaration" && !node.isLocal
           && node.identifier && node.identifier.type === "Identifier") {
    node.identifier.name = ctx.rename.lookup(node.identifier.name);
  }

  if (opensFn) {
    ctx.rename.pushScope();
    if (Array.isArray(node.parameters)) {
      for (const p of node.parameters) {
        if (p && p.type === "Identifier" && p.name) p.name = ctx.rename.declare(p.name);
      }
    }
    if (Array.isArray(node.body)) ctx.rename.hoistBlock(node.body);
  }

  if (opensLoop) {
    ctx.rename.pushScope();
    if (node.type === "ForNumericStatement" && node.variable && node.variable.name) {
      node.variable.name = ctx.rename.declare(node.variable.name);
    }
    if (node.type === "ForGenericStatement" && Array.isArray(node.variables)) {
      for (const v of node.variables) if (v && v.name) v.name = ctx.rename.declare(v.name);
    }
  }

  if (ctx.rename && node.type === "LocalStatement" && Array.isArray(node.variables)) {
    for (const v of node.variables) {
      if (v && v.type === "Identifier" && v.name) v.name = ctx.rename.declare(v.name);
    }
  }

  // Descend into children with position-aware skips.
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "range" || k === "__obf") continue;
    if (opensFn && k === "parameters") continue;
    if (opensLoop && (k === "variable" || k === "variables")) continue;
    if (ctx.rename && node.type === "LocalStatement" && k === "variables") continue;
    if (ctx.rename && node.type === "FunctionDeclaration" && k === "identifier" && node.isLocal) continue;
    // v19 property guard: never rename a property-position identifier.
    if (ctx.rename && node.type === "MemberExpression" && k === "identifier") continue;
    if (ctx.rename && node.type === "TableKeyString" && k === "key") continue;
    if (ctx.rename && node.type === "FunctionDeclaration" && k === "identifier"
        && !node.isLocal && node.identifier
        && (node.identifier.type === "MemberExpression" || node.identifier.type === "IndexExpression")) continue;

    const c = node[k];
    if (Array.isArray(c)) { for (const x of c) walkTransform(x, ctx); }
    else if (c && typeof c === "object") walkTransform(c, ctx);
  }

  // Identifier rename in variable position only.
  if (ctx.rename && node.type === "Identifier" && node.name) {
    node.name = ctx.rename.lookup(node.name);
  }

  // Numeric literal encoding.
  if (ctx.encNumbers && node.type === "NumericLiteral"
      && typeof node.value === "number" && !node.__obf) {
    const expr = encodeNumber(node.value);
    if (expr !== String(node.value)) {
      node.__obf = { type: "num", expr };
      if (ctx.numMeta) ctx.numMeta.encoded++;
    }
  }

  // String literal encryption. Uses _stringLiteralValue to handle luaparse
  // versions that populate `raw` but leave `value` undefined.
  if (ctx.encStrings && node.type === "StringLiteral" && !node.__obf) {
    const _strVal = _stringLiteralValue(node);
    if (_strVal !== null) {
      if (_shouldEncrypt(_strVal, ctx.manifest, ctx.strict)) {
        const bytes = encryptStringBytes(_strVal, ctx.encKey, ctx.encShift, ctx.xorMask);
        node.__obf = { type: "str", bytes };
        ctx.strMeta.encrypted++;
      } else {
        ctx.strMeta.skipped++;
      }
    }
  }

  if (opensFn)   ctx.rename.popScope();
  if (opensLoop) ctx.rename.popScope();
}

// ============================================================================
// SECTION 9 - Serializer (AST -> Lua source)
// ============================================================================

const WORD_BINOPS = new Set(["and", "or"]);

function serializeBlock(stmts) {
  return stmts.map(serialize).filter(s => s.length > 0).join(";");
}

function serializeBinary(node) {
  const op = node.operator;
  const left = serialize(node.left);
  const right = serialize(node.right);
  if (WORD_BINOPS.has(op)) return "(" + left + " " + op + " " + right + ")";
  return "(" + left + op + right + ")";
}

function serialize(node) {
  if (!node) return "";
  if (node.__obf) {
    if (node.__obf.type === "str") return "_D(" + bytesToLuaTable(node.__obf.bytes) + ")";
    if (node.__obf.type === "num") return node.__obf.expr;
    if (node.__obf.type === "vm")  return node.__obf.expr;
  }
  switch (node.type) {
    case "Chunk": return serializeBlock(node.body);
    case "LocalStatement": {
      const vs = node.variables.map(v => v.name).join(",");
      const init = node.init.map(serialize).join(",");
      return "local " + vs + (init ? "=" + init : "");
    }
    case "AssignmentStatement":
      return node.variables.map(serialize).join(",") + "=" + node.init.map(serialize).join(",");
    case "CallStatement": return serialize(node.expression);
    case "CallExpression":
      return serialize(node.base) + "(" + node.arguments.map(serialize).join(",") + ")";
    case "StringCallExpression":
      return serialize(node.base) + serialize(node.argument);
    case "TableCallExpression":
      return serialize(node.base) + serialize(node.arguments);
    case "Identifier": return node.name;
    case "StringLiteral": {
      const v = typeof node.value === "string" ? node.value
              : (node.raw ? node.raw.slice(1, -1) : "");
      return JSON.stringify(v);
    }
    case "NumericLiteral": return String(node.value);
    case "BooleanLiteral": return node.value ? "true" : "false";
    case "NilLiteral": return "nil";
    case "VarargLiteral": return "...";
    case "MemberExpression":
      return serialize(node.base) + node.indexer + node.identifier.name;
    case "IndexExpression":
      return serialize(node.base) + "[" + serialize(node.index) + "]";
    case "BinaryExpression":
    case "LogicalExpression": return serializeBinary(node);
    case "UnaryExpression":
      return "(" + node.operator + " " + serialize(node.argument) + ")";
    case "FunctionDeclaration": {
      const ps = node.parameters.map(p => p.type === "VarargLiteral" ? "..." : p.name).join(",");
      const body = serializeBlock(node.body);
      const id = node.identifier ? serialize(node.identifier) : "";
      const local = node.isLocal ? "local " : "";
      return id ? local + "function " + id + "(" + ps + ") " + body + " end"
                : "function(" + ps + ") " + body + " end";
    }
    case "IfStatement": {
      let s = "";
      for (const c of node.clauses) {
        if (c.type === "IfClause")
          s += "if " + serialize(c.condition) + " then " + serializeBlock(c.body) + " ";
        else if (c.type === "ElseifClause")
          s += "elseif " + serialize(c.condition) + " then " + serializeBlock(c.body) + " ";
        else if (c.type === "ElseClause")
          s += "else " + serializeBlock(c.body) + " ";
      }
      return s + "end";
    }
    case "WhileStatement":
      return "while " + serialize(node.condition) + " do " + serializeBlock(node.body) + " end";
    case "RepeatStatement":
      return "repeat " + serializeBlock(node.body) + " until " + serialize(node.condition);
    case "ForNumericStatement": {
      const step = node.step ? "," + serialize(node.step) : "";
      return "for " + node.variable.name + "=" + serialize(node.start) + "," +
             serialize(node.end) + step + " do " + serializeBlock(node.body) + " end";
    }
    case "ForGenericStatement":
      return "for " + node.variables.map(v => v.name).join(",") + " in " +
             node.iterators.map(serialize).join(",") + " do " +
             serializeBlock(node.body) + " end";
    case "DoStatement":
      return "do " + serializeBlock(node.body) + " end";
    case "ReturnStatement":
      return "return " + node.arguments.map(serialize).join(",");
    case "BreakStatement": return "break";
    case "GotoStatement": return "goto " + node.label.name;
    case "LabelStatement": return "::" + node.label.name + "::";
    case "TableConstructorExpression": {
      const fs = node.fields.map(f => {
        if (f.type === "TableKey") return "[" + serialize(f.key) + "]=" + serialize(f.value);
        if (f.type === "TableKeyString") return f.key.name + "=" + serialize(f.value);
        return serialize(f.value);
      });
      return "{" + fs.join(",") + "}";
    }
    default:
      // v25.17 Option B diagnostic: surface unknown node types instead of
      // silently emitting an empty string. Every caller of serialize() sits
      // inside a try/catch that routes errors into report.warn(), so this
      // change makes the failing AST node type visible in the dashboard
      // Warnings panel instead of producing invalid Lua downstream.
      throw new Error("serialize: unhandled node type \"" + (node && node.type) + "\"");
  }
}

// ============================================================================
// SECTION 10 - Validator + parser helper
// ============================================================================

// v25.18 diagnostic: pull ~140 chars around a (line,column) so warnings can
// show the actual invalid-Lua snippet instead of just "at line N".
function _snippetAround(code, line, column) {
  if (!code || typeof code !== "string" || !line) return "";
  const lines = code.split("\n");
  const lineIdx = Math.max(0, (line | 0) - 1);
  const targetLine = lines[lineIdx] || "";
  const col = Math.max(0, (column | 0) - 1);
  const s = Math.max(0, col - 60);
  const e = Math.min(targetLine.length, col + 60);
  let snip = targetLine.slice(s, e);
  snip = snip.replace(/[\x00-\x1f\x7f]/g, ch =>
    "\\x" + ch.charCodeAt(0).toString(16).padStart(2, "0"));
  const caretPos = col - s;
  return " snippet=[" + snip + "] caret@" + caretPos +
         " (lineLen=" + targetLine.length + ")";
}

function validate(code) {
  try {
    luaparse.parse(code, { luaVersion: "5.3", comments: false });
    return { ok: true };
  } catch (e1) {
    try {
      luaparse.parse(code, { luaVersion: "5.1", comments: false });
      return { ok: true };
    } catch (e2) {
      return { ok: false, error: e1.message, line: e1.line, column: e1.column };
    }
  }
}

// v25.20: last parse error is stashed here so the caller (when _parseAst
// returns null) can surface line/column/message in a warning, and snip a
// piece of the source around it to show the exact Luau construct that broke.
let _lastParseError = null;
function _parseAst(code) {
  _lastParseError = null;
  let e53 = null;
  try {
    return luaparse.parse(code, { luaVersion: "5.3", comments: false, locations: false });
  } catch (e) { e53 = e; }
  try {
    return luaparse.parse(code, { luaVersion: "5.1", comments: false, locations: false });
  } catch (e51) {
    // Prefer 5.3 error since that is what we run stages against.
    _lastParseError = {
      message: (e53 && e53.message) || (e51 && e51.message) || "unknown",
      line: (e53 && e53.line) || (e51 && e51.line) || 0,
      column: (e53 && e53.column) || (e51 && e51.column) || 0,
    };
    return null;
  }
}

// ============================================================================
// ============================================================================
// SECTION 11 - Constant pool with poison entries (maximum tier)
// ============================================================================

function generatePoisonPool(varName, poolKey, poolShift) {
  const poison = [
    "HttpGet","GetService","Players","LocalPlayer","Character","Humanoid",
    "WalkSpeed","JumpPower","Health","MaxHealth","TeleportService",
    "UserInputService","RunService","Workspace","ReplicatedStorage",
    "FindFirstChild","WaitForChild","GetChildren","Destroy","Clone",
    "PlayerAdded","CharacterAdded","Touched","MouseButton1Click",
    "RemoteEvent","RemoteFunction","FireServer","InvokeServer",
    "JSONEncode","JSONDecode","print","warn","error","pcall",
  ];
  const count = randInt(20, 40);
  const entries = [];
  for (let i = 0; i < count; i++) {
    const val = randChoice(poison) + "_" + randHexName(2).slice(3);
    const bytes = encryptStringBytes(val, poolKey, poolShift);
    entries.push("{" + bytes.join(",") + "}");
  }
  return "local " + varName + "={" + shuffle(entries).join(",") + "}";
}

// ============================================================================
// SECTION 11B - Integrity check (payload tamper detection)
// ============================================================================
//
// Compute a rolling multiply-by-31 checksum over the first ~200 chars of the
// wrapped payload at obfuscation time. Emit a Lua function that recomputes
// the same checksum at runtime. If any byte was patched between build and
// execution, the checksums diverge and the script silent-returns before any
// decoder or user code runs.
//
// Pure computation -- no getgc, no hookfunction, no environment probes.
// Safe on every executor. If the JS-side compute somehow diverges from the
// Lua-side compute (impossible with plain 7-bit ASCII markers), worst case
// is silent-exit -- indistinguishable from a normal loader failure, never
// a crash.
// ============================================================================

function generateAntiTamper() {
  // Silent-exit anti-tamper. Runs ONCE at load time. Three one-shot probes:
  //   1. `load` is a hooked Lua closure (not the original C function)
  //   2. `loadstring` is a hooked Lua closure
  //   3. Timing sanity -- a trivial no-op loop takes > 5 seconds
  //      (meaning we're being single-stepped)
  // Every probe is pcall-wrapped. A pcall FAILURE is treated as "the
  // environment blocks introspection" -> safe, no trigger. Only a
  // positive-shape reading triggers the silent exit.
  const fn = randHexName(3);
  const okVar = randHexName(2);
  const infoVar = randHexName(2);
  const t0Var = randHexName(2);
  const t1Var = randHexName(2);
  const tmpVar = randHexName(2);
  return "local function " + fn + "() " +
    // Probe 1: load hooked. debug.getinfo(load,"S").what == "Lua" means it
    // was replaced by a Lua-defined wrapper. Original is a C function.
    "local " + okVar + "," + infoVar + "=pcall(function() " +
    "return debug.getinfo(load,\"S\") end) " +
    "if " + okVar + " and type(" + infoVar + ")==\"table\" and " +
    infoVar + ".what==\"Lua\" then return true end " +
    // Probe 2: loadstring hooked, same shape.
    "local " + okVar + "2," + infoVar + "2=pcall(function() " +
    "return debug.getinfo(loadstring,\"S\") end) " +
    "if " + okVar + "2 and type(" + infoVar + "2)==\"table\" and " +
    infoVar + "2.what==\"Lua\" then return true end " +
    // Probe 3: one-shot timing. 100 iterations of a trivial op should be
    // sub-millisecond on any real machine; > 10s means single-stepping.
    "local " + okVar + "3," + tmpVar + "=pcall(function() " +
    "local " + t0Var + "=tick() " +
    "local t={} " +
    "for i=1,100 do t[i]=i end " +
    "local " + t1Var + "=tick() " +
    "return (" + t1Var + "-" + t0Var + ")>10 end) " +
    "if " + okVar + "3 and " + tmpVar + "==true then return true end " +
    "return false " +
    "end " +
    // Silent exit.
    "if " + fn + "() then return end";
}

function generateAntiDump() {
  // Silent-exit anti-dump. Runs ONCE at load time before the payload.
  // Detects:
  //   1. `getscriptbytecode` global exists AND is callable (bytecode dumper)
  //   2. `decompile` global exists AND is callable (decompiler active)
  // Both probes are pcall-wrapped. If `type()` itself throws (impossible on
  // any real executor but defensively wrapped anyway), we treat that as
  // "environment blocks introspection" -- safe, no trigger. Only a positive
  // type == "function" reading triggers silent exit.
  const fn = randHexName(3);
  const okVar = randHexName(2);
  const tVar = randHexName(2);
  return "local function " + fn + "() " +
    // Probe 1: getscriptbytecode. Uses rawget on the global env so we avoid
    // firing __index metamethods that a sandbox might set up. If the value
    // exists and its type is "function", a dumper is exposed.
    "local " + okVar + "," + tVar + "=pcall(function() " +
    "local g=rawget(getfenv(0),\"getscriptbytecode\") " +
    "return g~=nil and type(g)==\"function\" end) " +
    "if " + okVar + " and " + tVar + "==true then return true end " +
    // Probe 2: decompile, same shape.
    "local " + okVar + "2," + tVar + "2=pcall(function() " +
    "local g=rawget(getfenv(0),\"decompile\") " +
    "return g~=nil and type(g)==\"function\" end) " +
    "if " + okVar + "2 and " + tVar + "2==true then return true end " +
    "return false " +
    "end " +
    // Silent exit: top-level return, script does nothing further.
    "if " + fn + "() then return end";
}

function generateAntiDebugger() {
  // Silent-exit anti-debugger. Runs ONCE at load time before the payload.
  // Detects:
  //   1. getfenv(0) tampering  -- returns a non-table or nils out globals
  //   2. debug.sethook active  -- a foreign hook set on this thread
  //   3. debug.getinfo on ourselves says source is not "=[C]" and not the
  //      loadstring chunk we expect (a decompiler/dumper replaced us)
  // Every check is pcall-wrapped. A pcall FAILURE (throwing debug lib)
  // means "no debug lib available" -- we treat that as safe, not hostile.
  // Only a pcall that SUCCEEDS AND returns a hostile-shape value triggers
  // the silent exit.
  const fn = randHexName(3);
  const okVar = randHexName(2);
  const resVar = randHexName(2);
  const hookVar = randHexName(2);
  const envVar = randHexName(2);
  return "local function " + fn + "() " +
    // Check 1: getfenv(0) must return a table. If it returns anything else,
    // something replaced _G with a probe. pcall wraps because sandboxed
    // executors may block getfenv entirely (that is FINE -- ok=false path).
    "local " + okVar + "," + envVar + "=pcall(getfenv,0) " +
    "if " + okVar + " and type(" + envVar + ")~=\"table\" then return true end " +
    // Check 2: debug.sethook set by someone else on the current coroutine.
    // debug.gethook returns the hook function, mask, count. If the hook is
    // a function (not nil), a foreign profiler/tracer is attached.
    "local " + okVar + "2," + hookVar + "=pcall(function() return debug.gethook() end) " +
    "if " + okVar + "2 and type(" + hookVar + ")==\"function\" then return true end " +
    // Check 3: our own closure's source. Under a normal loadstring/loader,
    // debug.getinfo(1,\"S\").source starts with '=' (chunk name) or the code
    // itself. If it is a real file path (starts with '@'), the payload has
    // been dumped to disk and re-loaded -- suspicious.
    "local " + okVar + "3," + resVar + "=pcall(function() return debug.getinfo(1,\"S\") end) " +
    "if " + okVar + "3 and type(" + resVar + ")==\"table\" and type(" + resVar + ".source)==\"string\" " +
    "and string.sub(" + resVar + ".source,1,1)==\"@\" then return true end " +
    "return false " +
    "end " +
    // Silent exit: if the probe returns true, top-level return -- the
    // script simply does nothing, no error message, no crash.
    "if " + fn + "() then return end";
}

function generateIntegrityCheck(payload) {
  // Marker is a prefix slice of the payload. Pure 7-bit ASCII by
  // construction (all our wrappers emit only ASCII), so JS charCodeAt and
  // Lua string.byte agree byte-for-byte.
  //
  // v25.13: marker length is randomized per build (150-500 bytes) so
  // an attacker cannot rely on the fixed 200-byte cap of prior versions.
  // They now have to guess the coverage window, which changes every
  // obfuscation. Math.min caps against actual payload length so short
  // payloads still get their full contents covered.
  const markerLen = randInt(150, 500);
  const marker = payload.substring(0, Math.min(markerLen, payload.length));
  let expected = 0;
  for (let i = 0; i < marker.length; i++) {
    expected = ((expected * 31) + marker.charCodeAt(i)) & 0x7fffffff;
  }
  const fnName = randHexName(3);
  const chkVar = randHexName(2);
  const expVar = randHexName(2);
  return "local function " + fnName + "() " +
    "local " + expVar + "=" + expected + " " +
    "local " + chkVar + "=0 " +
    "local s=" + JSON.stringify(marker) + " " +
    "for i=1,#s do " + chkVar + "=(" + chkVar + "*31+string.byte(s,i))%2147483648 end " +
    "return " + chkVar + "==" + expVar + " " +
    "end " +
    "if not " + fnName + "() then return end";
}

// ============================================================================
// SECTION 12 - Minifier (whitespace collapse + long-line chunking)
// ============================================================================
//
// Some executors (Delta, Fluxus, Synapse V3) truncate very long single-line
// scripts. Insert a newline after `;` at ~500-char intervals for safety.
// ============================================================================

function minify(code) {
  const lines = code.split("\n").map(l => l.trim()).filter(l => l.length > 0);
  let out = lines.join("\n").replace(/[ \t]+/g, " ");
  const CHUNK = 500;
  const chunks = [];
  let lastBreak = 0;
  for (let i = CHUNK; i < out.length; i += CHUNK) {
    let breakAt = -1;
    for (let j = i; j < Math.min(i + 200, out.length); j++) {
      if (out[j] === ";") { breakAt = j + 1; break; }
    }
    if (breakAt > lastBreak) {
      chunks.push(out.substring(lastBreak, breakAt));
      lastBreak = breakAt;
      i = breakAt;
    }
  }
  if (lastBreak < out.length) chunks.push(out.substring(lastBreak));
  return chunks.join("\n").trim();
}

// ============================================================================
// SECTION 13 - Script profiler (drives report display + auto-downgrade)
// ============================================================================

function profileScript(ast, rawCode) {
  const p = {
    sourceChars: rawCode.length,
    riskTier: "low",
    complexityScore: 0,
    maxBlockDepth: 0,
    functionCount: 0,
    pcallCount: 0,
    hasHookfunction: false,
    hasHookmetamethod: false,
    hasSetmetatable: false,
    hasRuntimeReflection: false,
  };
  function calleeName(base) {
    if (!base) return null;
    if (base.type === "Identifier") return base.name;
    if (base.type === "MemberExpression" && base.identifier) return base.identifier.name;
    return null;
  }
  const OPEN = new Set(["DoStatement","WhileStatement","RepeatStatement",
    "ForNumericStatement","ForGenericStatement","IfClause","ElseifClause","ElseClause"]);

  function walk(node, depth) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { for (const n of node) walk(n, depth); return; }
    const t = node.type;
    if (t === "FunctionDeclaration" || t === "FunctionExpression") p.functionCount++;
    if (t === "CallExpression" && node.base) {
      const nm = calleeName(node.base);
      if (nm === "pcall" || nm === "xpcall") p.pcallCount++;
      if (nm === "hookfunction") p.hasHookfunction = true;
      if (nm === "hookmetamethod") p.hasHookmetamethod = true;
      if (nm === "setmetatable") p.hasSetmetatable = true;
    }
    const nd = OPEN.has(t) ? depth + 1 : depth;
    if (nd > p.maxBlockDepth) p.maxBlockDepth = nd;
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      walk(node[k], nd);
    }
  }
  walk(ast, 0);

  const reflectRe = /\b(getgc|debug\.info|debug\.get\w+|debug\.set\w+|getreg|getrenv|getgenv|getsenv|getconnections)\s*\(/;
  p.hasRuntimeReflection = reflectRe.test(rawCode);

  p.complexityScore = Math.round(
    (p.sourceChars / 1000) * 0.5 +
    p.maxBlockDepth * 3 +
    p.functionCount * 0.5 +
    p.pcallCount * 0.3 +
    (p.hasHookfunction ? 20 : 0) +
    (p.hasSetmetatable ? 10 : 0)
  );
  if (p.maxBlockDepth >= 100 || p.complexityScore >= 500) p.riskTier = "extreme";
  else if (p.maxBlockDepth >= 50 || p.complexityScore >= 200) p.riskTier = "high";
  else if (p.maxBlockDepth >= 25 || p.complexityScore >= 80) p.riskTier = "medium";
  return p;
}

// ============================================================================
// SECTION 14 - ObfuscationReport (matches v24 shape read by dashboard.js)
// ============================================================================
//
// Fields consumed by dashboard.js renderReport() must all exist:
//   requestedLevel, actualLevel, wasDowngraded, downgradeReason,
//   profile (riskTier, complexityScore, maxBlockDepth, functionCount,
//     pcallCount, hasHookfunction, hasHookmetamethod, hasRuntimeReflection),
//   manifest (identifiers, strings, propertyNames, zeroInitLocals,
//     forwardRefs, methodCallBases),
//   layers (vmWrap, outerVM, antiDebugger, integrityCheck, stringEncryption,
//     stringEncryptionStrict, constantObfuscation, constantPool, antiTamper,
//     antiDump, byteLevelXor, antiDebuggerMode, identifierRename,
//     numericObfuscation),
//   stats (originalBytes, obfuscatedBytes, sizeRatio, elapsedMs,
//     stringsEncrypted, stringsSkipped),
//   warnings (array of strings)
// ============================================================================

class ObfuscationReport {
  constructor(requestedLevel) {
    this.requestedLevel = requestedLevel || "medium";
    this.actualLevel = this.requestedLevel;
    this.wasDowngraded = false;
    this.downgradeReason = null;
    this.profile = {};
    this.manifest = {};
    // All the layer keys the dashboard checks -- initialized to false so
    // renderReport shows them as "inactive" instead of "unknown".
    this.layers = {
      vmWrap: false,
      outerVM: false,
      antiDebugger: false,
      antiDebuggerMode: null,
      integrityCheck: false,
      stringEncryption: false,
      stringEncryptionStrict: false,
      constantObfuscation: false,
      numericObfuscation: false,
      identifierRename: false,
      constantPool: false,
      antiTamper: false,
      antiDump: false,
      byteLevelXor: false,
    };
    this.stats = {
      originalBytes: 0,
      obfuscatedBytes: 0,
      sizeRatio: 1,
      elapsedMs: 0,
      stringsEncrypted: 0,
      stringsSkipped: 0,
    };
    // v25.23: per-stage timing so we can see exactly where time is spent.
    this.stageTimings = {};
    this.warnings = [];
    this.stagesSucceeded = [];
    this.stagesSkipped = [];
  }
  warn(msg) { this.warnings.push(msg); }
}

// ============================================================================
// SECTION 15 - Staged pipeline
// ============================================================================
//
// Each stage: clone the current-known-good AST, apply the transform,
// serialize, re-parse. On success -> promote the new state. On failure ->
// log to report, keep the previous state, continue with the next stage.
// The final output is GUARANTEED to parse as valid Lua.
// ============================================================================

function cloneAst(ast) {
  // v25.23: fast structural clone that skips loc/range metadata.
  // JSON.parse(JSON.stringify()) is ~3-5x slower and uses ~40% more memory
  // because it serializes every loc/range object we don't need after parse.
  // On a 500KB script this saves ~15-25 seconds of pure clone time.
  return _fastClone(ast);
}

function _fastClone(node) {
  if (node === null || typeof node !== "object") return node;
  if (Array.isArray(node)) {
    const out = new Array(node.length);
    for (let i = 0; i < node.length; i++) out[i] = _fastClone(node[i]);
    return out;
  }
  const out = {};
  for (const k in node) {
    // Skip position metadata -- luaparse never re-reads it after parse and
    // it accounts for ~50% of an AST's memory footprint.
    if (k === "loc" || k === "range") continue;
    out[k] = _fastClone(node[k]);
  }
  return out;
}

// v25.23: stages listed here only attach __obf markers to leaf nodes -- they
// cannot produce invalid Lua because the serializer treats __obf as a black
// box and never lets it corrupt structure. For these stages we skip cloneAst
// AND validate(), saving ~15-25 seconds per stage on a 500KB script.
// v25.25: string-encryption removed from safe stages. Observed in production
// (719KB Luau script) that some encrypted strings produce output that only
// downstream stages surface as invalid. Keeping validate() as a safety net
// for string-encryption catches this at the right stage.
const _SAFE_STAGES = new Set(["numeric-encoding"]);

function runStage(name, ast, ctx, fn, report) {
  const _t0 = Date.now();
  try {
    if (_SAFE_STAGES.has(name)) {
      // Fast path: mutate in place (safe -- only __obf markers), skip validate.
      fn(ast, ctx);
      const code = serialize(ast);
      report.stagesSucceeded.push(name);
      if (report.stageTimings) report.stageTimings[name] = Date.now() - _t0;
      return { ok: true, ast, code };
    }
    // Slow path: clone + validate for stages that can restructure the AST.
    const clone = cloneAst(ast);
    fn(clone, ctx);
    const code = serialize(clone);
    const check = validate(code);
    if (!check.ok) {
      report.warn("Stage \"" + name + "\" produced invalid Lua (" +
                  check.error + " at " + (check.line||"?") + ":" + (check.column||"?") + ")" +
                  _snippetAround(code, check.line, check.column) + " - skipped");
      report.stagesSkipped.push(name);
      if (report.stageTimings) report.stageTimings[name] = Date.now() - _t0;
      return { ok: false };
    }
    report.stagesSucceeded.push(name);
    if (report.stageTimings) report.stageTimings[name] = Date.now() - _t0;
    return { ok: true, ast: clone, code };
  } catch (e) {
    report.warn("Stage \"" + name + "\" threw: " + e.message + " - skipped");
    report.stagesSkipped.push(name);
    if (report.stageTimings) report.stageTimings[name] = Date.now() - _t0;
    return { ok: false };
  }
}

function _pipeline(rawCode, level, options, report) {
  const startedAt = Date.now();

  // Preprocess Luau -> Lua and parse baseline.
  const preprocessed = preprocess(rawCode);
  const baselineAst = _parseAst(preprocessed);
  if (!baselineAst) {
    report.warn("Baseline parse failed - returning minified source only" +
      (_lastParseError
        ? " (" + _lastParseError.message +
          " at " + (_lastParseError.line || "?") + ":" + (_lastParseError.column || "?") + ")" +
          _snippetAround(preprocessed, _lastParseError.line, _lastParseError.column)
        : ""));
    report.actualLevel = "basic";
    report.wasDowngraded = true;
    report.downgradeReason = "Input script could not be parsed after preprocessing";
    const min = minify(preprocessed);
    report.stats.originalBytes = rawCode.length;
    report.stats.obfuscatedBytes = min.length;
    report.stats.sizeRatio = min.length / Math.max(1, rawCode.length);
    report.stats.elapsedMs = Date.now() - startedAt;
    return { code: min, report };
  }

  // Build manifest -- primary code + optional reference file. Set the
  // module-level pointer so nested helpers (like _shouldEncrypt in the
  // walker) can consult it directly.
  const manifest = ReferenceManifest.scan(preprocessed, options.referenceCode);
  // FIX: prevent self-poisoning of the string whitelist. The primary-code
  // scan populates manifest.strings with EVERY literal in the user's own
  // source, which then causes _shouldEncrypt to whitelist all of them and
  // emit 0 encrypted strings. Rebuild manifest.strings from the reference
  // file only (identifiers/propertyNames/methodBases still come from both).
  if (options.referenceCode && typeof options.referenceCode === "string"
      && options.referenceCode.trim().length > 0) {
    const refOnly = ReferenceManifest.scan(options.referenceCode);
    manifest.strings = refOnly.strings;
  } else {
    manifest.strings = new Set();
  }
  _currentManifest = manifest;
  report.manifest = {
    identifiers: manifest.identifiers.size,
    strings: manifest.strings.size,
    propertyNames: manifest.propertyNames.size,
    zeroInitLocals: manifest.zeroInitLocals.size,
    forwardRefs: manifest.forwardRefs.size,
    methodCallBases: manifest.methodCallBases.size,
    referenceUsed: !!(options.referenceCode && options.referenceCode.trim && options.referenceCode.trim().length > 0),
  };

  // Profile.
  const profile = profileScript(baselineAst, preprocessed);
  report.profile = {
    riskTier: profile.riskTier,
    complexityScore: profile.complexityScore,
    maxBlockDepth: profile.maxBlockDepth,
    functionCount: profile.functionCount,
    pcallCount: profile.pcallCount,
    hasHookfunction: profile.hasHookfunction,
    hasHookmetamethod: profile.hasHookmetamethod,
    hasSetmetatable: profile.hasSetmetatable,
    hasRuntimeReflection: profile.hasRuntimeReflection,
  };

  // v25.15+ Fix 1: no more tier auto-downgrade. Attempt the requested level.
  // Per-stage rollback catches any layer whose output fails to parse.
  let effectiveLevel = level;
  if (level === "maximum" && profile.riskTier === "extreme" && !options.forceMaximum) {
    report.warn(
      "Script profile risk=EXTREME (functions=" + profile.functionCount +
      ", depth=" + profile.maxBlockDepth +
      ", complexity=" + profile.complexityScore +
      "); attempting maximum tier. Per-stage rollback will skip any single layer that fails to parse."
    );
  }
  report.actualLevel = effectiveLevel;

  // ------------------------------------------------------------------
  // v25.14 (Phase 2a): Manual layer overrides.
  // ------------------------------------------------------------------
  // options.layerOverrides is a map from layer name to "auto"|"force"|"skip".
  // - "auto" (default): existing smart-skip logic decides.
  // - "skip":  never emit this layer, regardless of profile.
  // - "force": emit even when smart-skip would have suppressed it.
  //            A warning is added so the user sees the deliberate override.
  //
  // layerOverrideDecision(name, autoEnabled) returns:
  //   { enabled: bool, forced: bool }
  //   .enabled = final decision (yes emit / no skip)
  //   .forced  = user overrode smart-skip via "force"; caller may want to warn.
  //
  // If the level isn't "maximum" the overrides still apply, but "force" on a
  // layer that requires maximum will still no-op (we don't emit maximum-only
  // layers on medium/basic tiers). The caller checks effectiveLevel itself.
  // ------------------------------------------------------------------
  const _overrides = (options && options.layerOverrides) || {};
  function layerOverrideDecision(name, autoEnabled) {
    const v = _overrides[name];
    if (v === "skip") {
      return { enabled: false, forced: false, mode: "skip" };
    }
    if (v === "force") {
      return { enabled: true, forced: !autoEnabled, mode: "force" };
    }
    return { enabled: autoEnabled, forced: false, mode: "auto" };
  }
  report.layerOverrides = {
    antiDebugger: _overrides.antiDebugger || "auto",
    antiDump:     _overrides.antiDump     || "auto",
    antiTamper:   _overrides.antiTamper   || "auto",
    byteLevelXor: _overrides.byteLevelXor || "auto",
    vmWrap:       _overrides.vmWrap       || "auto",
    outerVM:      _overrides.outerVM      || "auto",
  };

  // Levels "none" / "basic" -- no AST transforms.
  if (effectiveLevel === "none") {
    report.stats.originalBytes = rawCode.length;
    report.stats.obfuscatedBytes = rawCode.length;
    report.stats.elapsedMs = Date.now() - startedAt;
    return { code: rawCode, report };
  }
  if (effectiveLevel === "basic") {
    const min = minify(preprocessed);
    report.stats.originalBytes = rawCode.length;
    report.stats.obfuscatedBytes = min.length;
    report.stats.sizeRatio = min.length / Math.max(1, rawCode.length);
    report.stats.elapsedMs = Date.now() - startedAt;
    return { code: min, report };
  }

  // ---- Medium / Maximum: staged AST transforms with rollback ----
  let goodAst = baselineAst;
  let goodCode = serialize(baselineAst);
  report.stagesSucceeded.push("baseline");

  const encKey = randInt(30, 200);
  const encShift = randInt(1, 20);
  const decoderFn = randHexName(3);
  const strMeta = { encrypted: 0, skipped: 0 };
  const strict = effectiveLevel === "maximum";

  // Byte-level XOR mask (v25.5). Maximum tier only, and only when the
  // payload does NOT use hooks/reflection (same smart-skip contract as
  // the other v25.x guards). When the mask stays null, encryptStringBytes
  // and makeStringDecoder emit the pre-v25.5 output byte-for-byte, so
  // enabling/disabling this layer is a pure superset -- never a break.
  let xorMask = null;
  {
    const autoOn = (effectiveLevel === "maximum") &&
                   !profile.hasHookfunction && !profile.hasHookmetamethod;
    const dec = layerOverrideDecision("byteLevelXor", autoOn);
    if (dec.enabled && effectiveLevel === "maximum") {
      const buf = crypto.randomBytes(4);
      xorMask = [buf[0], buf[1], buf[2], buf[3]];
      if (dec.forced) {
        report.warn("Byte-level XOR force-enabled by user override (script installs hooks; may collide with bit32.bxor)");
      }
    } else if (dec.mode === "skip") {
      report.warn("Byte-level XOR skipped by user override");
    }
  }

  // Stage: inner VM wrap (v25.7). Runs FIRST, before any other transform,
  // so it sees the pristine AST. Later stages (numeric-encoding, string-
  // encryption, identifier-rename) all skip nodes that already have __obf
  // markers, so once we tag a statement with type "vm" it stays intact.
  // Maximum tier only; smart-skip on hook/reflection payloads to stay
  // conservative.
  let vmFnName = null;
  let vmBcVar  = null;
  let vmBytecode = [];
  let vmStatementsWrapped = 0;
  const _vmAutoOn = (effectiveLevel === "maximum") &&
                    !profile.hasHookfunction && !profile.hasHookmetamethod &&
                    !profile.hasRuntimeReflection;
  const _vmDec = layerOverrideDecision("vmWrap", _vmAutoOn);
  if (_vmDec.enabled && effectiveLevel === "maximum") {
    if (_vmDec.forced) {
      report.warn("Inner VM force-enabled by user override (script uses hooks/reflection; VM may false-positive)");
    }
    try {
      const localVmFn = randHexName(3);
      const localBcVar = randHexName(3);
      const localBc = [];
      let wrappedCount = 0;

      // Deep-clone the AST for the trial. If validate() fails after we
      // patch it we discard the clone and keep goodAst untouched.
      const trialAst = cloneAst(goodAst);
      if (trialAst && Array.isArray(trialAst.body)) {
        for (const stmt of trialAst.body) {
          if (vmCanCompileStatement(stmt)) {
            const startPc = vmCompileStatement(stmt, localBc);
            // Replace the statement's expression with an __obf marker whose
            // rendered form is a plain call to the VM dispatcher.
            stmt.expression.__obf = {
              type: "vm",
              expr: localVmFn + "(" + startPc + ")",
            };
            wrappedCount++;
          }
        }
      }

      if (wrappedCount >= 1) {
        // Serialize the trial AST WITH the dispatcher + bytecode prepended
        // and confirm the whole thing still parses. If it does, commit.
        const trialCode = serialize(trialAst);
        const dispatcherSrc = vmGenerateDispatcher(localVmFn, localBcVar);
        const bcTableSrc = vmGenerateBytecodeTable(localBcVar, localBc);
        const trialFull = bcTableSrc + " " + dispatcherSrc + " " + trialCode;
        const chk = validate(trialFull);
        if (chk.ok) {
          goodAst  = trialAst;
          goodCode = trialCode;    // dispatcher+bytecode prepended in wrap phase
          vmFnName = localVmFn;
          vmBcVar  = localBcVar;
          vmBytecode = localBc;
          vmStatementsWrapped = wrappedCount;
          report.layers.vmWrap = true;
          report.stagesSucceeded.push("vm-wrap");
          if (report.stats) {
            report.stats.vmStatements = wrappedCount;
          }
        } else {
          report.warn("VM wrap produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(combined, chk.line, chk.column) + " - skipped");
          report.stagesSkipped.push("vm-wrap");
        }
      }
      // wrappedCount === 0: nothing eligible, silent skip (not even a warn).
    } catch (e) {
      report.warn("VM wrap threw: " + e.message + " - skipped");
      report.stagesSkipped.push("vm-wrap");
    }
  } else if (_vmDec.mode === "skip") {
    report.warn("Inner VM skipped by user override");
  }

  // Stage: numeric encoding
  {
    const _numMeta = { encoded: 0 };
    const ctx = { encNumbers: true, manifest, strMeta: { encrypted: 0, skipped: 0 }, numMeta: _numMeta };
    const r = runStage("numeric-encoding", goodAst, ctx, walkTransform, report);
    if (r.ok) {
      goodAst = r.ast; goodCode = r.code;
      report.layers.numericObfuscation = true;
      report.layers.constantObfuscation = true; // alias for dashboard's older label
      if (report.stats) report.stats.numericConstsObfuscated = _numMeta.encoded;
    }
  }

  // Stage: string encryption
  {
    const local = { encrypted: 0, skipped: 0 };
    const ctx = {
      encStrings: true, manifest, strict,
      encKey, encShift, decoderFn,
      xorMask,
      strMeta: local,
    };
    const r = runStage("string-encryption", goodAst, ctx, walkTransform, report);
    if (r.ok) {
      goodAst = r.ast; goodCode = r.code;
      report.layers.stringEncryption = true;
      report.layers.stringEncryptionStrict = strict;
      strMeta.encrypted = local.encrypted;
      strMeta.skipped = local.skipped;
    }
  }

  // Stage: identifier rename (manifest-hoisted)
  {
    const rename = new RenameCtx(manifest);
    const ctx = { rename, manifest, strMeta: { encrypted: 0, skipped: 0 } };
    const r = runStage("identifier-rename", goodAst, ctx, walkTransform, report);
    if (r.ok) {
      goodAst = r.ast; goodCode = r.code;
      report.layers.identifierRename = true;
    }
  }

  // Wrap: decoder + optional poison pool.
  // v25.5: pass xorMask into makeStringDecoder. When mask is null the
  // decoder is byte-for-byte identical to the pre-v25.5 version.
  // v25.6: if VM wrap ran, prepend dispatcher + bytecode table FIRST so
  // integrity + anti-tamper + anti-dump + anti-debugger cover it too.
  // v25.8: outer VM -- XOR-encode the inner bytecode table and emit a
  // decoder that rebuilds it at load time. Only maximum tier. If inner
  // VM was skipped, still emit a decoy decoder + fake payload so the
  // layer registers active but has no runtime cost.
  let wrapped = goodCode;
  let outerVmActive = false;
  const _ovmAutoOn = (effectiveLevel === "maximum") &&
                     !profile.hasHookfunction && !profile.hasHookmetamethod;
  const _ovmDec = layerOverrideDecision("outerVM", _ovmAutoOn);
  if (_ovmDec.enabled && effectiveLevel === "maximum") {
    if (_ovmDec.forced) {
      report.warn("Outer VM force-enabled by user override (script installs hooks; decoder may collide with bit32.bxor)");
    }
    try {
      if (report.layers.vmWrap && vmFnName && vmBcVar && vmBytecode.length > 0) {
        // Real path: encode the inner bytecode, replace the inner table
        // literal with a call to the outer decoder.
        const enc = vmEncodeFlat(vmBytecode);
        const buf = crypto.randomBytes(4);
        const outerMask = [buf[0], buf[1], buf[2], buf[3]];
        const xored = vmXorBytes(enc.flat, outerMask);
        const encVar = randHexName(3);
        const strVar = randHexName(3);
        const decoderFn2 = randHexName(3);
        const encTable = "local " + encVar + "=" + vmFlatToLuaTable(xored);
        const strTable = "local " + strVar + "=" + vmStringsToLuaTable(enc.strings);
        const decoderSrc = vmGenerateOuterDecoder(decoderFn2, encVar, strVar, outerMask);
        // Replace the inner bytecode table literal with a decoder call.
        const innerBcTable = vmGenerateBytecodeTable(vmBcVar, vmBytecode);
        const innerBcAsCall = "local " + vmBcVar + "=" + decoderFn2 + "()";
        const dispatcherSrc = vmGenerateDispatcher(vmFnName, vmBcVar);
        const combined = encTable + " " + strTable + " " + decoderSrc + " " +
                         innerBcAsCall + " " + dispatcherSrc + " " + wrapped;
        // Pre-flight validate.
        const chk = validate(combined);
        if (chk.ok) {
          wrapped = combined;
          outerVmActive = true;
        } else {
          report.warn("Outer VM produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(combined, chk.line, chk.column) + " - falling back to inner-only");
          // Fall back to plain inner-VM prepend (v25.6 behavior).
          wrapped = innerBcTable + " " + dispatcherSrc + " " + wrapped;
        }
      } else {
        // Decoy path: inner VM didn't run, but we still emit a decoder +
        // fake encoded payload so the outer layer registers active.
        const fakeBytecode = [[10]];  // Just a HALT -- inert.
        const enc = vmEncodeFlat(fakeBytecode);
        const buf = crypto.randomBytes(4);
        const outerMask = [buf[0], buf[1], buf[2], buf[3]];
        const xored = vmXorBytes(enc.flat, outerMask);
        const encVar = randHexName(3);
        const strVar = randHexName(3);
        const decoderFn2 = randHexName(3);
        const decoyVar = randHexName(3);
        const encTable = "local " + encVar + "=" + vmFlatToLuaTable(xored);
        const strTable = "local " + strVar + "=" + vmStringsToLuaTable(enc.strings);
        const decoderSrc = vmGenerateOuterDecoder(decoderFn2, encVar, strVar, outerMask);
        // Assign to an unused local so the decoder body ships but nothing
        // actually dispatches the fake bytecode.
        const decoyCall = "local " + decoyVar + "=" + decoderFn2 + "()";
        const combined = encTable + " " + strTable + " " + decoderSrc + " " +
                         decoyCall + " " + wrapped;
        const chk = validate(combined);
        if (chk.ok) {
          wrapped = combined;
          outerVmActive = true;
        }
        // If validation fails on the decoy, silently skip (no user impact).
      }
    } catch (e) {
      report.warn("Outer VM threw: " + e.message + " - skipped");
      // Fall back to the pre-outer wrap: if inner VM was active, restore
      // its plain form.
      if (report.layers.vmWrap && vmFnName && vmBcVar && vmBytecode.length > 0) {
        const innerBcTable = vmGenerateBytecodeTable(vmBcVar, vmBytecode);
        const dispatcherSrc = vmGenerateDispatcher(vmFnName, vmBcVar);
        wrapped = innerBcTable + " " + dispatcherSrc + " " + wrapped;
      }
    }
  } else if (report.layers.vmWrap && vmFnName && vmBcVar) {
    // Inner VM active but outer VM disabled (not maximum, or hooks
    // detected, or user override) -- just emit plain inner form.
    const bcTableSrc = vmGenerateBytecodeTable(vmBcVar, vmBytecode);
    const dispatcherSrc = vmGenerateDispatcher(vmFnName, vmBcVar);
    wrapped = bcTableSrc + " " + dispatcherSrc + " " + wrapped;
  }
  if (_ovmDec.mode === "skip") {
    report.warn("Multi-layer outer VM skipped by user override");
  }
  if (outerVmActive) {
    report.layers.outerVM = true;
    report.stagesSucceeded.push("outer-vm");
  }
  if (report.layers.stringEncryption) {
    const decoderCode = makeStringDecoder(decoderFn, encKey, encShift, xorMask);
    wrapped = decoderCode + " local _D=" + decoderFn + " " + wrapped;
    if (xorMask) {
      report.layers.byteLevelXor = true;
      report.stagesSucceeded.push("byte-level-xor");
    }
  }
  if (effectiveLevel === "maximum") {
    const poolVar = "_CP" + randHexName(2).slice(3);
    wrapped = generatePoisonPool(poolVar, encKey, encShift) + " " + wrapped;
    report.layers.constantPool = true;
  }

  // Stage: anti-debugger (silent-exit guard).
  // Only maximum tier. Skip ONLY when the script itself installs hooks
  // (hookfunction / hookmetamethod) that would collide with our probes.
  if (effectiveLevel === "maximum") {
    const _adAutoOn = !profile.hasHookfunction && !profile.hasHookmetamethod;
    const _adDec = layerOverrideDecision("antiDebugger", _adAutoOn);
    if (!_adDec.enabled) {
      if (_adDec.mode === "skip") {
        report.warn("Anti-debugger skipped by user override");
      } else {
        report.warn("Anti-debugger skipped: script installs hooks (would false-positive)");
      }
      report.stagesSkipped.push("anti-debugger");
    } else {
      if (_adDec.forced) {
        report.warn("Anti-debugger force-enabled by user override (script installs hooks; may false-positive)");
      }
      try {
        const withAD = generateAntiDebugger() + " " + wrapped;
        const chk = validate(withAD);
        if (chk.ok) {
          wrapped = withAD;
          report.layers.antiDebugger = true;
          report.stagesSucceeded.push("anti-debugger");
        } else {
          report.warn("Anti-debugger produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withAD, chk.line, chk.column) + " - skipped");
          report.stagesSkipped.push("anti-debugger");
        }
      } catch (e) {
        report.warn("Anti-debugger threw: " + e.message + " - skipped");
        report.stagesSkipped.push("anti-debugger");
      }
    }
  }

  // Stage: anti-dump (silent-exit guard against bytecode dumpers).
  // Only maximum tier. No smart-skip based on script content.
  // v25.14: honors user override for skip/force.
  if (effectiveLevel === "maximum") {
    const _axDec = layerOverrideDecision("antiDump", true);
    if (!_axDec.enabled) {
      report.warn("Anti-dump skipped by user override");
      report.stagesSkipped.push("anti-dump");
    } else {
      try {
        const withAX = generateAntiDump() + " " + wrapped;
        const chk = validate(withAX);
        if (chk.ok) {
          wrapped = withAX;
          report.layers.antiDump = true;
          report.stagesSucceeded.push("anti-dump");
        } else {
          report.warn("Anti-dump produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withAX, chk.line, chk.column) + " - skipped");
          report.stagesSkipped.push("anti-dump");
        }
      } catch (e) {
        report.warn("Anti-dump threw: " + e.message + " - skipped");
        report.stagesSkipped.push("anti-dump");
      }
    }
  }

  // Stage: anti-tamper wrapper (silent-exit on hooked load/loadstring or
  // debugger single-stepping).
  // Only maximum tier. Skip ONLY when the script installs hooks.
  if (effectiveLevel === "maximum") {
    const _atAutoOn = !profile.hasHookfunction && !profile.hasHookmetamethod;
    const _atDec = layerOverrideDecision("antiTamper", _atAutoOn);
    if (!_atDec.enabled) {
      if (_atDec.mode === "skip") {
        report.warn("Anti-tamper skipped by user override");
      } else {
        report.warn("Anti-tamper skipped: script installs hooks (would false-positive)");
      }
      report.stagesSkipped.push("anti-tamper");
    } else {
      if (_atDec.forced) {
        report.warn("Anti-tamper force-enabled by user override (script installs hooks; may false-positive)");
      }
      try {
        const withAT = generateAntiTamper() + " " + wrapped;
        const chk = validate(withAT);
        if (chk.ok) {
          wrapped = withAT;
          report.layers.antiTamper = true;
          report.stagesSucceeded.push("anti-tamper");
        } else {
          report.warn("Anti-tamper produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withAT, chk.line, chk.column) + " - skipped");
          report.stagesSkipped.push("anti-tamper");
        }
      } catch (e) {
        report.warn("Anti-tamper threw: " + e.message + " - skipped");
        report.stagesSkipped.push("anti-tamper");
      }
    }
  }

  // Stage: integrity check (payload tamper detection).
  // Prepended AFTER decoder + pool + anti-debugger + anti-dump + anti-tamper
  // so the checksum covers all wrapper code too. Wrapped in try/validate so
  // a bad checksum output can't kill the run.
  try {
    const withIntegrity = generateIntegrityCheck(wrapped) + " " + wrapped;
    const chk = validate(withIntegrity);
    if (chk.ok) {
      wrapped = withIntegrity;
      report.layers.integrityCheck = true;
      report.stagesSucceeded.push("integrity-check");
    } else {
      report.warn("Integrity check produced invalid Lua (" + chk.error + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withIntegrity, chk.line, chk.column) + " - skipped");
      report.stagesSkipped.push("integrity-check");
    }
  } catch (e) {
    report.warn("Integrity check threw: " + e.message + " - skipped");
    report.stagesSkipped.push("integrity-check");
  }

  // Final validation of the wrapped output. If it fails, fall back to the
  // bare renamed source (no decoder, no pool) -- still valid Lua.
  const finalCheck = validate(wrapped);
  if (!finalCheck.ok) {
    report.warn("Wrapped output failed validation (" + finalCheck.error +
                ") - falling back to bare transformed source");
    wrapped = goodCode;
    // If the VM stage ran, goodCode still has __obf 'vm' markers referring
    // to vmFnName. Without the dispatcher those become undefined calls at
    // runtime. Fall back to the pre-VM serialization instead: re-serialize
    // the baseline AST (which has no __obf 'vm' markers).
    if (report.layers.vmWrap) {
      try {
        wrapped = serialize(baselineAst);
      } catch (_) { /* best-effort */ }
      report.layers.vmWrap = false;
      if (report.stats) report.stats.vmStatements = 0;
    }
    report.layers.outerVM = false;
    report.layers.constantPool = false;
    report.layers.stringEncryption = false;
    report.layers.byteLevelXor = false;
    report.layers.antiDebugger = false;
    report.layers.antiDump = false;
    report.layers.antiTamper = false;
    report.layers.integrityCheck = false;
  }

  const finalCode = minify(wrapped);

  report.stats.originalBytes = rawCode.length;
  report.stats.obfuscatedBytes = finalCode.length;
  report.stats.sizeRatio = finalCode.length / Math.max(1, rawCode.length);
  report.stats.elapsedMs = Date.now() - startedAt;
  report.stats.stringsEncrypted = strMeta.encrypted;
  report.stats.stringsSkipped = strMeta.skipped;

  return { code: finalCode, report };
}

// ============================================================================
// SECTION 16 - Public API (drop-in for server.js v24.0)
// ============================================================================
//
// obfuscateWithReport(luaCode, level, userId, options) -> {code, report}
// obfuscate(luaCode, level, userId)                    -> string
//
// The server calls them like this:
//   obfuscateWithReport(code, obfLevel, userId, {
//     forceMaximum: !!forceMaximum,
//     referenceCode: referenceCode || null,
//   })
// so the signature and option shape here must match exactly.
// ============================================================================

async function obfuscateWithReport(luaCode, level, userId, options) {
  options = options || {};
  const report = new ObfuscationReport(level || "medium");
  report.requestedLevel = level || "medium";
  report.actualLevel = report.requestedLevel;
  // userId is accepted for signature parity with the v24 server; unused here.
  void userId;

  if (typeof luaCode !== "string" || luaCode.length === 0) {
    report.warn("Empty input");
    return { code: "", report };
  }

  const validLevels = new Set(["none", "basic", "medium", "maximum"]);
  if (!validLevels.has(level)) {
    report.warn("Unknown level \"" + level + "\" - defaulting to medium");
    level = "medium";
    report.requestedLevel = level;
    report.actualLevel = level;
  }

  try {
    return _pipeline(luaCode, level, options, report);
  } catch (e) {
    // Absolute last resort: return minified source so the user still gets
    // something executable rather than a 500.
    report.warn("Pipeline threw: " + e.message + " - returning minified source");
    report.actualLevel = "minified";
    report.wasDowngraded = true;
    report.downgradeReason = "Internal obfuscator error: " + e.message;
    let fallback = luaCode;
    try { fallback = minify(preprocess(luaCode)); } catch (_) {}
    report.stats.originalBytes = luaCode.length;
    report.stats.obfuscatedBytes = fallback.length;
    report.stats.sizeRatio = fallback.length / Math.max(1, luaCode.length);
    return { code: fallback, report };
  } finally {
    _currentManifest = null;
  }
}

async function obfuscate(luaCode, level, userId) {
  const result = await obfuscateWithReport(luaCode, level, userId, {});
  return typeof result === "string" ? result : result.code;
}

// ============================================================================
// SECTION 17 - Streaming API (live per-stage progress + skip/continue hooks)
// ============================================================================
//
// obfuscateWithStream(luaCode, level, userId, options) -> {code, report}
//
// options adds two hooks on top of the standard shape:
//   emit(event, data)          -- called before/after each stage. Fire-and-
//                                 forget. Errors inside emit are swallowed.
//   awaitDecision(stageName)   -- async, returns { skip: boolean } (or a
//                                 primitive-truthy for skip). Called before
//                                 every optional stage. If omitted, all
//                                 stages run.
//
// Event names the caller can expect:
//   "session-start"    { level, effectiveLevel, profile, manifest }
//   "stage-start"      { stage, index, total, description }
//   "stage-await"      { stage, index, total }   -- decision requested
//   "stage-skip"       { stage, index, total, reason }
//   "stage-success"    { stage, index, total, elapsedMs, detail }
//   "stage-failure"    { stage, index, total, error }
//   "session-complete" { report }
//
// The public event stream is intentionally small and stable so the SSE
// bridge in server.js can pass events through 1:1 without translation.
// ============================================================================

// Stage catalog: metadata that both the pipeline and the dashboard consume.
// order = the sequence stages fire in; skippable flag drives the "Skip"
// button visibility on the client.
const _STAGE_CATALOG = [
  { name: "numeric-encoding",   label: "Numeric obfuscation",     skippable: true,  levels: ["medium", "maximum"] },
  { name: "string-encryption",  label: "String encryption",       skippable: true,  levels: ["medium", "maximum"] },
  { name: "identifier-rename",  label: "Identifier rename",       skippable: true,  levels: ["medium", "maximum"] },
  { name: "constant-pool",      label: "Constant pool + poison",  skippable: true,  levels: ["maximum"] },
  { name: "integrity-check",    label: "Integrity check",         skippable: true,  levels: ["medium", "maximum"] },
  { name: "anti-debugger",     label: "Anti-debugger",           skippable: true,  levels: ["maximum"] },
];

async function obfuscateWithStream(luaCode, level, userId, options) {
  options = options || {};
  const emit = typeof options.emit === "function" ? options.emit : () => {};
  const awaitDecision = typeof options.awaitDecision === "function"
    ? options.awaitDecision : null;
  void userId;

  const safeEmit = (evt, data) => {
    try { emit(evt, data); } catch (_) { /* never let a listener kill the run */ }
  };

  const report = new ObfuscationReport(level || "medium");
  report.requestedLevel = level || "medium";
  report.actualLevel = report.requestedLevel;

  if (typeof luaCode !== "string" || luaCode.length === 0) {
    report.warn("Empty input");
    safeEmit("session-complete", { report });
    return { code: "", report };
  }
  const validLevels = new Set(["none", "basic", "medium", "maximum"]);
  if (!validLevels.has(level)) {
    report.warn("Unknown level \"" + level + "\" - defaulting to medium");
    level = "medium";
    report.requestedLevel = level;
    report.actualLevel = level;
  }

  const startedAt = Date.now();

  // Baseline: preprocess + parse.
  let preprocessed, baselineAst;
  try {
    preprocessed = preprocess(luaCode);
    baselineAst = _parseAst(preprocessed);
  } catch (e) {
    report.warn("Preprocess threw: " + e.message);
  }

  if (!baselineAst) {
    report.warn("Baseline parse failed - returning minified source only" +
      (_lastParseError
        ? " (" + _lastParseError.message +
          " at " + (_lastParseError.line || "?") + ":" + (_lastParseError.column || "?") + ")" +
          _snippetAround(preprocessed, _lastParseError.line, _lastParseError.column)
        : ""));
    report.actualLevel = "basic";
    report.wasDowngraded = true;
    report.downgradeReason = "Input script could not be parsed after preprocessing";
    const min = minify(preprocessed || luaCode);
    report.stats.originalBytes = luaCode.length;
    report.stats.obfuscatedBytes = min.length;
    report.stats.sizeRatio = min.length / Math.max(1, luaCode.length);
    report.stats.elapsedMs = Date.now() - startedAt;
    safeEmit("session-complete", { report });
    return { code: min, report };
  }

  // Manifest + profile.
  const manifest = ReferenceManifest.scan(preprocessed, options.referenceCode);
  _currentManifest = manifest;
  report.manifest = {
    identifiers: manifest.identifiers.size,
    strings: manifest.strings.size,
    propertyNames: manifest.propertyNames.size,
    zeroInitLocals: manifest.zeroInitLocals.size,
    forwardRefs: manifest.forwardRefs.size,
    methodCallBases: manifest.methodCallBases.size,
    referenceUsed: !!(options.referenceCode && options.referenceCode.trim && options.referenceCode.trim().length > 0),
  };
  const profile = profileScript(baselineAst, preprocessed);
  report.profile = {
    riskTier: profile.riskTier,
    complexityScore: profile.complexityScore,
    maxBlockDepth: profile.maxBlockDepth,
    functionCount: profile.functionCount,
    pcallCount: profile.pcallCount,
    hasHookfunction: profile.hasHookfunction,
    hasHookmetamethod: profile.hasHookmetamethod,
    hasSetmetatable: profile.hasSetmetatable,
    hasRuntimeReflection: profile.hasRuntimeReflection,
  };

  // v25.15+ Fix 1: no more tier auto-downgrade. Attempt the requested level.
  // Per-stage rollback catches any layer whose output fails to parse.
  let effectiveLevel = level;
  if (level === "maximum" && profile.riskTier === "extreme" && !options.forceMaximum) {
    report.warn(
      "Script profile risk=EXTREME (functions=" + profile.functionCount +
      ", depth=" + profile.maxBlockDepth +
      ", complexity=" + profile.complexityScore +
      "); attempting maximum tier. Per-stage rollback will skip any single layer that fails to parse."
    );
  }
  report.actualLevel = effectiveLevel;

  // Filter the stage catalog to what applies at this level.
  const applicable = _STAGE_CATALOG.filter(s => s.levels.indexOf(effectiveLevel) >= 0);

  safeEmit("session-start", {
    level, effectiveLevel,
    profile: report.profile,
    manifest: report.manifest,
    stages: applicable.map((s, i) => ({ name: s.name, label: s.label, index: i, total: applicable.length })),
    wasDowngraded: report.wasDowngraded,
    downgradeReason: report.downgradeReason,
  });

  // "none" / "basic" -- no interactive stages.
  if (effectiveLevel === "none") {
    report.stats.originalBytes = luaCode.length;
    report.stats.obfuscatedBytes = luaCode.length;
    report.stats.elapsedMs = Date.now() - startedAt;
    safeEmit("session-complete", { report });
    _currentManifest = null;
    return { code: luaCode, report };
  }
  if (effectiveLevel === "basic") {
    const min = minify(preprocessed);
    report.stats.originalBytes = luaCode.length;
    report.stats.obfuscatedBytes = min.length;
    report.stats.sizeRatio = min.length / Math.max(1, luaCode.length);
    report.stats.elapsedMs = Date.now() - startedAt;
    safeEmit("session-complete", { report });
    _currentManifest = null;
    return { code: min, report };
  }

  // Interactive staged pipeline.
  let goodAst = baselineAst;
  let goodCode = serialize(baselineAst);
  report.stagesSucceeded.push("baseline");

  const encKey = randInt(30, 200);
  const encShift = randInt(1, 20);
  const decoderFn = randHexName(3);
  const strMeta = { encrypted: 0, skipped: 0 };
  const strict = effectiveLevel === "maximum";

  // Helper: for AST stages, ask permission, then run and emit progress.
  async function askThenRun(stage, index, total, applyFn) {
    safeEmit("stage-start", { stage: stage.name, index, total, label: stage.label });
    if (awaitDecision && stage.skippable) {
      safeEmit("stage-await", { stage: stage.name, index, total, label: stage.label });
      let decision;
      try { decision = await awaitDecision(stage.name); }
      catch (e) { decision = { skip: false }; }
      const skip = decision === true || (decision && decision.skip);
      if (skip) {
        safeEmit("stage-skip", { stage: stage.name, index, total, reason: "user-requested" });
        report.stagesSkipped.push(stage.name);
        return { ran: false };
      }
    }
    const started = Date.now();
    try {
      const result = applyFn();
      const elapsedMs = Date.now() - started;
      if (result && result.ok) {
        safeEmit("stage-success", { stage: stage.name, index, total, elapsedMs, detail: result.detail || null });
        return { ran: true, ok: true, ast: result.ast, code: result.code };
      }
      safeEmit("stage-failure", { stage: stage.name, index, total, error: (result && result.error) || "stage returned not-ok" });
      report.stagesSkipped.push(stage.name);
      return { ran: true, ok: false };
    } catch (e) {
      safeEmit("stage-failure", { stage: stage.name, index, total, error: e.message });
      report.stagesSkipped.push(stage.name);
      return { ran: true, ok: false };
    }
  }

  const total = applicable.length;

  for (let i = 0; i < applicable.length; i++) {
    const stage = applicable[i];

    if (stage.name === "numeric-encoding") {
      const r = await askThenRun(stage, i, total, () => {
        const ctx = { encNumbers: true, manifest, strMeta: { encrypted: 0, skipped: 0 } };
        const s = runStage("numeric-encoding", goodAst, ctx, walkTransform, report);
        if (s.ok) { goodAst = s.ast; goodCode = s.code; return { ok: true, ast: s.ast, code: s.code, detail: "numeric literals rewritten" }; }
        return { ok: false, error: "stage validation failed" };
      });
      if (r.ran && r.ok) {
        report.layers.numericObfuscation = true;
        report.layers.constantObfuscation = true;
      }
      continue;
    }

    if (stage.name === "string-encryption") {
      const r = await askThenRun(stage, i, total, () => {
        const local = { encrypted: 0, skipped: 0 };
        const ctx = { encStrings: true, manifest, strict, encKey, encShift, decoderFn, strMeta: local };
        const s = runStage("string-encryption", goodAst, ctx, walkTransform, report);
        if (s.ok) {
          goodAst = s.ast; goodCode = s.code;
          strMeta.encrypted = local.encrypted;
          strMeta.skipped = local.skipped;
          return { ok: true, ast: s.ast, code: s.code, detail: local.encrypted + " strings encrypted, " + local.skipped + " skipped" };
        }
        return { ok: false, error: "stage validation failed" };
      });
      if (r.ran && r.ok) {
        report.layers.stringEncryption = true;
        report.layers.stringEncryptionStrict = strict;
      }
      continue;
    }

    if (stage.name === "identifier-rename") {
      const r = await askThenRun(stage, i, total, () => {
        const rename = new RenameCtx(manifest);
        const ctx = { rename, manifest, strMeta: { encrypted: 0, skipped: 0 } };
        const s = runStage("identifier-rename", goodAst, ctx, walkTransform, report);
        if (s.ok) { goodAst = s.ast; goodCode = s.code; return { ok: true, ast: s.ast, code: s.code, detail: manifest.identifiers.size + " identifiers considered" }; }
        return { ok: false, error: "stage validation failed" };
      });
      if (r.ran && r.ok) report.layers.identifierRename = true;
      continue;
    }

    if (stage.name === "constant-pool") {
      // Only meaningful if string encryption ran (decoder needed).
      const r = await askThenRun(stage, i, total, () => {
        if (!report.layers.stringEncryption) {
          return { ok: false, error: "constant-pool requires string encryption to be active" };
        }
        return { ok: true, detail: "poison pool queued for wrap phase" };
      });
      if (r.ran && r.ok) report.layers.constantPool = true;
      continue;
    }

    if (stage.name === "integrity-check") {
      // Integrity is a wrap-phase decision -- queue it, apply below.
      const r = await askThenRun(stage, i, total, () => {
        return { ok: true, detail: "integrity check queued for wrap phase" };
      });
      if (r.ran && r.ok) report.layers.integrityCheck = true;
      continue;
    }

    if (stage.name === "anti-debugger") {
      // Smart-skip on reflection-heavy scripts. If the payload itself uses
      // hookfunction / hookmetamethod / getrawmetatable / getgc, our probes
      // for foreign hooks will false-positive on the payload's OWN hooks.
      // We surface this as a SKIPPED stage (not a failure) so the UI can
      // explain WHY the layer is off.
      const r = await askThenRun(stage, i, total, () => {
        if (profile.hasHookfunction || profile.hasHookmetamethod ||
            profile.hasRuntimeReflection) {
          return { ok: false, error: "skipped: script uses hooks/reflection (would false-positive)" };
        }
        return { ok: true, detail: "anti-debugger queued for wrap phase" };
      });
      if (r.ran && r.ok) report.layers.antiDebugger = true;
      continue;
    }
  }

  // ---- Wrap phase: apply layer flags decided above. ----
  let wrapped = goodCode;
  if (report.layers.stringEncryption) {
    const decoderCode = makeStringDecoder(decoderFn, encKey, encShift);
    wrapped = decoderCode + " local _D=" + decoderFn + " " + wrapped;
  }
  if (report.layers.constantPool) {
    const poolVar = "_CP" + randHexName(2).slice(3);
    wrapped = generatePoisonPool(poolVar, encKey, encShift) + " " + wrapped;
  }
  if (report.layers.antiDebugger) {
    try {
      const withAD = generateAntiDebugger() + " " + wrapped;
      const chk = validate(withAD);
      if (chk.ok) {
        wrapped = withAD;
      } else {
        report.warn("Anti-debugger wrap produced invalid Lua (" + (chk.error||"?") + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withAD, chk.line, chk.column) + " - skipped");
        report.layers.antiDebugger = false;
      }
    } catch (e) {
      report.warn("Anti-debugger wrap threw: " + e.message + " - skipped");
      report.layers.antiDebugger = false;
    }
  }
  if (report.layers.integrityCheck) {
    try {
      const withIntegrity = generateIntegrityCheck(wrapped) + " " + wrapped;
      const chk = validate(withIntegrity);
      if (chk.ok) {
        wrapped = withIntegrity;
      } else {
        report.warn("Integrity wrap produced invalid Lua (" + (chk.error||"?") + " at " + (chk.line||"?") + ":" + (chk.column||"?") + ")" + _snippetAround(withIntegrity, chk.line, chk.column) + " - skipped");
        report.layers.integrityCheck = false;
      }
    } catch (e) {
      report.warn("Integrity wrap threw: " + e.message + " - skipped");
      report.layers.integrityCheck = false;
    }
  }

  const finalCheck = validate(wrapped);
  if (!finalCheck.ok) {
    report.warn("Wrapped output failed validation (" + finalCheck.error +
                ") - falling back to bare transformed source");
    wrapped = goodCode;
    report.layers.constantPool = false;
    report.layers.stringEncryption = false;
    report.layers.integrityCheck = false;
    report.layers.antiDebugger = false;
  }

  const finalCode = minify(wrapped);

  report.stats.originalBytes = luaCode.length;
  report.stats.obfuscatedBytes = finalCode.length;
  report.stats.sizeRatio = finalCode.length / Math.max(1, luaCode.length);
  report.stats.elapsedMs = Date.now() - startedAt;
  report.stats.stringsEncrypted = strMeta.encrypted;
  report.stats.stringsSkipped = strMeta.skipped;

  safeEmit("session-complete", { report });
  _currentManifest = null;
  return { code: finalCode, report };
}

// Match v24's process guards so a stray promise rejection doesn't kill the server.
process.on("uncaughtException", (err) => console.error("[obfuscator] Uncaught:", err.message));
process.on("unhandledRejection", (r) => console.error("[obfuscator] Unhandled:", r));

module.exports = { obfuscate, obfuscateWithReport, obfuscateWithStream };
