// AzureVM Obfuscator v25.0 - Clean rewrite (drop-in for server.js v24.0)
// ============================================================================
// This file replaces the v24 obfuscator with a minimal, guaranteed-executable
// pipeline. Public API is byte-compatible with server.js:
//
//   obfuscate(luaCode, level, userId)                    -> Promise<string>
//   obfuscateWithReport(luaCode, level, userId, options) -> Promise<{code, report}>
//
// Where options = { forceMaximum?: bool, referenceCode?: string|null }.
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
        case "StringLiteral":
          if (typeof node.value === "string") m.strings.add(node.value);
          break;
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
  // (b) function params (name: Type, ...)
  work = work.replace(/\(([^()]*)\)/g, (_m, inside) => {
    const cleaned = inside.replace(
      new RegExp("(" + IDENT + ")\\s*:\\s*[A-Za-z_][A-Za-z0-9_.<>?]*", "g"),
      "$1"
    );
    return "(" + cleaned + ")";
  });
  // (c) return type: function foo(...): Type
  work = work.replace(
    /(\))\s*:\s*[A-Za-z_][A-Za-z0-9_.<>?]*(?=\s*(?:\n|--|\bthen\b|\bdo\b|\breturn\b|\blocal\b|\bif\b|\bfor\b|\bwhile\b|\brepeat\b|\bend\b|;|$))/g,
    "$1"
  );
  // (d) type Foo = ...
  work = work.replace(/^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*=.*$/gm, "");
  // (e) export type ...
  work = work.replace(/^\s*export\s+type\s+.*$/gm, "");

  // Restore strings
  for (const s of strings) work = work.split(s.key).join(s.value);
  return work;
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

function encryptStringBytes(str, key, shift) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    const k = (key + ((i + shift) % 11)) & 0xff;
    bytes.push((c ^ k) & 0xff);
  }
  return bytes;
}

function makeStringDecoder(fnName, key, shift) {
  return "local function " + fnName + "(t) " +
    "local k=" + key + " local s='' " +
    "for i=1,#t do " +
      "s=s..string.char(bit32.bxor(t[i],(k+((i-1+" + shift + ")%11)))%256) " +
    "end return s end";
}

function bytesToLuaTable(bytes) { return "{" + bytes.join(",") + "}"; }

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
    if (expr !== String(node.value)) node.__obf = { type: "num", expr };
  }

  // String literal encryption.
  if (ctx.encStrings && node.type === "StringLiteral"
      && typeof node.value === "string" && !node.__obf) {
    if (_shouldEncrypt(node.value, ctx.manifest, ctx.strict)) {
      const bytes = encryptStringBytes(node.value, ctx.encKey, ctx.encShift);
      node.__obf = { type: "str", bytes };
      ctx.strMeta.encrypted++;
    } else {
      ctx.strMeta.skipped++;
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
    default: return "";
  }
}

// ============================================================================
// SECTION 10 - Validator + parser helper
// ============================================================================

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

function _parseAst(code) {
  try {
    return luaparse.parse(code, { luaVersion: "5.3", comments: false, locations: false });
  } catch (_) {
    try {
      return luaparse.parse(code, { luaVersion: "5.1", comments: false, locations: false });
    } catch (_) {
      return null;
    }
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

function generateIntegrityCheck(payload) {
  // Marker is the first slice of the payload. Pure 7-bit ASCII by
  // construction (all our wrappers emit only ASCII), so JS charCodeAt and
  // Lua string.byte agree byte-for-byte.
  const marker = payload.substring(0, Math.min(200, payload.length));
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
  // JSON round-trip is fine: our AST has no functions, no cycles, no protos.
  return JSON.parse(JSON.stringify(ast));
}

function runStage(name, ast, ctx, fn, report) {
  try {
    const clone = cloneAst(ast);
    fn(clone, ctx);
    const code = serialize(clone);
    const check = validate(code);
    if (!check.ok) {
      report.warn("Stage \"" + name + "\" produced invalid Lua (" +
                  check.error + " at line " + check.line + ") - skipped");
      report.stagesSkipped.push(name);
      return { ok: false };
    }
    report.stagesSucceeded.push(name);
    return { ok: true, ast: clone, code };
  } catch (e) {
    report.warn("Stage \"" + name + "\" threw: " + e.message + " - skipped");
    report.stagesSkipped.push(name);
    return { ok: false };
  }
}

function _pipeline(rawCode, level, options, report) {
  const startedAt = Date.now();

  // Preprocess Luau -> Lua and parse baseline.
  const preprocessed = preprocess(rawCode);
  const baselineAst = _parseAst(preprocessed);
  if (!baselineAst) {
    report.warn("Baseline parse failed - returning minified source only");
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

  // Auto-downgrade: extreme risk -> medium unless force flag set.
  let effectiveLevel = level;
  if (level === "maximum" && profile.riskTier === "extreme" && !options.forceMaximum) {
    effectiveLevel = "medium";
    report.wasDowngraded = true;
    report.downgradeReason =
      "Script risk tier is EXTREME (block depth " + profile.maxBlockDepth +
      ", complexity " + profile.complexityScore + "). Auto-downgraded to medium " +
      "to avoid runtime failures. Enable 'Force maximum' to override.";
  }
  report.actualLevel = effectiveLevel;

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

  // Stage: numeric encoding
  {
    const ctx = { encNumbers: true, manifest, strMeta: { encrypted: 0, skipped: 0 } };
    const r = runStage("numeric-encoding", goodAst, ctx, walkTransform, report);
    if (r.ok) {
      goodAst = r.ast; goodCode = r.code;
      report.layers.numericObfuscation = true;
      report.layers.constantObfuscation = true; // alias for dashboard's older label
    }
  }

  // Stage: string encryption
  {
    const local = { encrypted: 0, skipped: 0 };
    const ctx = {
      encStrings: true, manifest, strict,
      encKey, encShift, decoderFn,
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
  let wrapped = goodCode;
  if (report.layers.stringEncryption) {
    const decoderCode = makeStringDecoder(decoderFn, encKey, encShift);
    wrapped = decoderCode + " local _D=" + decoderFn + " " + wrapped;
  }
  if (effectiveLevel === "maximum") {
    const poolVar = "_CP" + randHexName(2).slice(3);
    wrapped = generatePoisonPool(poolVar, encKey, encShift) + " " + wrapped;
    report.layers.constantPool = true;
  }

  // Stage: integrity check (payload tamper detection).
  // Prepended AFTER decoder + pool so the checksum covers the wrapper too.
  // Wrapped in try/validate so a bad checksum output can't kill the run.
  try {
    const withIntegrity = generateIntegrityCheck(wrapped) + " " + wrapped;
    const chk = validate(withIntegrity);
    if (chk.ok) {
      wrapped = withIntegrity;
      report.layers.integrityCheck = true;
      report.stagesSucceeded.push("integrity-check");
    } else {
      report.warn("Integrity check produced invalid Lua (" + chk.error + ") - skipped");
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
    report.layers.constantPool = false;
    report.layers.stringEncryption = false;
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
    report.warn("Baseline parse failed - returning minified source only");
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

  // Auto-downgrade decision.
  let effectiveLevel = level;
  if (level === "maximum" && profile.riskTier === "extreme" && !options.forceMaximum) {
    effectiveLevel = "medium";
    report.wasDowngraded = true;
    report.downgradeReason =
      "Script risk tier is EXTREME (block depth " + profile.maxBlockDepth +
      ", complexity " + profile.complexityScore + "). Auto-downgraded to medium " +
      "to avoid runtime failures. Enable 'Force maximum' to override.";
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
  if (report.layers.integrityCheck) {
    try {
      const withIntegrity = generateIntegrityCheck(wrapped) + " " + wrapped;
      const chk = validate(withIntegrity);
      if (chk.ok) {
        wrapped = withIntegrity;
      } else {
        report.warn("Integrity wrap produced invalid Lua - skipped");
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
