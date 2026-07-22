// AzureVM Obfuscator v21.0 - Forward-ref & reflection-string hardening
// v21.0 changes (2026-07):
//   1. NEVER_ENCRYPT_STRINGS expanded with reflection-heavy script markers
//      (TIME/PRY/SwordsController/sleitnick_net/etc) that were being encrypted
//      by strict mode and breaking anti-cheat / net-scanning scripts.
//   2. _shouldEncryptString gains pattern rules: package version keys
//      (name@version), *Service/*Controller/*Handler/*Manager class-like
//      names, and short ALL_CAPS hash keys are now literal.
//   3. RenameCtx.hoistScope now also hoists non-local top-level function
//      decls and top-level bare assignments. Fixes the setActive forward-ref
//      bug where 'function setActive(on)' at line ~880 was called from
//      inside local functions at lines ~130-140 and got renamed inconsistently.
//   4. walkAst rewrites non-local FunctionDeclaration.identifier to match the
//      hoisted name so declaration and all forward call sites agree.
// Downstream: 'Applied' report card should now show more layers active on
// reflection-heavy scripts, and the 'zero statements compilable' warning
// remains truthful (VM wrap is separate from the fixes above; see notes below).
//
// KNOWN LIMITATION: VM wrap still requires bare-identifier CallStatements to
// compile. Real Roblox scripts (property assigns, method calls, control flow)
// naturally emit zero. The VM harness is a bonus layer; the byte-level XOR +
// string encryption + numeric obfuscation chain remains the primary carrier.
// Fixing VM coverage properly requires supporting AssignmentStatement and
// method-call semantics in vmCompileStmt/vmCompileExpr, which is a much
// larger change than this batch.
//
// AzureVM Obfuscator v20.0 - Staged obfuscation (adaptive per-feature)
// Applied fix (this batch):
//   NEW MODE: Maximum tier now runs each obfuscation feature ONE AT A TIME,
//   validating the output after each stage. If a stage produces invalid Lua,
//   it's SKIPPED and the previous stable state is preserved. Result: even if
//   one feature breaks on a specific script, the other layers still apply.
//   
//   Stages (executed in order for maximum tier):
//     1. baseline (pre-analysis + Luau conversion)
//     2. numeric obfuscation
//     3. string encryption (strict)
//     4. identifier rename (RenameCtx with hoisting from v17)
//     5. nesting reduction
//     6. serialize
//     7. wrap with decoder + constant pool
//     8. byte-level XOR chain (v19 restored)
//   
//   Trade-off: slower (~5-10s for large scripts) vs 1-pass, but GUARANTEED
//   to produce working output. Report card includes stage list showing which
//   features succeeded and which were skipped, per script.
//   
//   Medium tier keeps the original single-pass flow (already stable and fast).
// Previous v19.0 (Property identifier guard):
// AzureVM Obfuscator v19.0 - Property identifier guard (REAL fix)
// Applied fix (this batch):
//   THE REAL ROOT CAUSE for macrozure UI-not-showing:
//   The walkAst recursion loop was descending into MemberExpression.identifier
//   (the .field part of obj.field) and TableKeyString.key (the key in {key=v}).
//   These are PROPERTY NAMES not variables, but the Identifier rename step
//   below the loop was renaming them. When the property name coincidentally
//   matched a hoisted local (e.g. `local LocalPlayer = Players.LocalPlayer`
//   hoists 'LocalPlayer', then the .LocalPlayer property gets renamed to hex),
//   the runtime saw `Players._0xhex` which is not a valid Instance member.
//   
//   Fix: Skip renaming in property positions:
//     - MemberExpression.identifier (obj.field)
//     - TableKeyString.key ({key=v})
//     - Non-local FunctionDeclaration with MemberExpression identifier
//       (function obj.method or function obj:method)
//   
//   Also restored the byte-level XOR chain (v18 removed it as workaround,
//   but with the real fix in place, the chain works fine).
// Previous v18.0 (Direct execution workaround):
// AzureVM Obfuscator v18.0 - Direct execution (no byte-level chain)
// Applied fix (this batch):
//   ROOT CAUSE for macrozure silent-fail: byteLevelTripleObfuscate's inner
//   loadstring+pcall chain silently swallows syntax errors in the decoded
//   payload. For scripts with heavy pcall/hook usage (macrozure has 3 pcalls
//   + reflection), this creates a nested pcall failure with no visible error.
//   
//   Fix: Skip byteLevelTripleObfuscate entirely on maximum tier. Use direct
//   execution of the medium-style output (which already works for macrozure).
//   Maximum tier still applies: strict string encryption, numeric obfuscation,
//   constant pool with poison, hoisted RenameCtx. Only the outer XOR wrap +
//   loadstring chain is removed.
//   
//   Trade-off: -one encryption layer, +100% reliability. Byte-level XOR was
//   duplicated coverage anyway (payload already encrypted via string decoders).
// Previous v17.0 (Adaptive scope):
// AzureVM Obfuscator v17.0 - Adaptive scope (ULTIMATE FIX)
// Applied fixes (this batch):
//   ROOT CAUSE for macrozure silent-fail on maximum:
//     - RenameCtx.lookup() no longer auto-declares unknown names.
//     - Added hoistScope() pre-pass. Before walking a scope body,
//       pre-declare all locals so forward refs resolve to same hex name.
//     - Wired into Chunk (top-level) and FunctionDeclaration bodies.
//   Consolidated fixes (from v16.3+v16.6):
//     - hasRuntimeReflection detection (skips anti-debug for reflection scripts)
//     - effectiveLevel threaded through byteLevelTripleObfuscate
//     - Fallback catch-block defensively uses medium tier
//     - Anti-debug threshold raised 2->3, gc pool 50k->200k
// Previous v16.2 (Second TDZ hotfix):
// AzureVM Obfuscator v16.2 - Second TDZ hotfix
// Applied fix (this batch):
//   P0.5  Fixed second TDZ ReferenceError: 'Cannot access \'profile\' before initialization'
//         tuneStrategy(profile, closureGraph, uiPatterns) at line ~3273
//         referenced 'profile' before its declaration further down. Hoisted
//         the profileScript() call AND the _report.profile capture above the
//         advanced intelligence block.
// Previous v16.1 (First TDZ hotfix):
// AzureVM Obfuscator v16.1 - TDZ hotfix
// Applied fix (this batch):
//   P0.4  Fixed TDZ ReferenceError: 'Cannot access \'ast\' before initialization'
//         analyzeClosureGraph(ast) and detectUIPatterns(ast) at lines ~3256
//         referenced 'ast' before its declaration at line ~3291. Hoisted the
//         'const code'/'const ast' declarations above the advanced intelligence
//         block. Fixes fallback-mode-active issue where reports showed FALLBACK.
// Previous v16.0 (Report API):
// AzureVM Obfuscator v16.0 - Report API added
// Applied fixes (this batch):
//   v16  obfuscateWithReport() returns {code, report} with full metadata:
//        - profile (riskTier, complexity, hooks, frameworks)
//        - actualLevel + wasDowngraded + downgradeReason
//        - layers (which passes fired: vmWrap, outerVM, antiDebugger, etc.)
//        - stats (bytes, elapsed, stringsEncrypted, numericConstsObfuscated)
//        - warnings[] for any concerns raised during obfuscation
//        - Optional forceMaximum flag to skip auto-downgrade (unsafe)
//   Backward compat: obfuscate() returns raw string like before.
// Previous v15.1 (Options B+C):
// AzureVM Obfuscator v15.1 - Options B+C (string encryption coverage)
// Applied fixes (this batch):
//   B  Loosened PascalCase filter: encrypt PascalCase strings of length >= 8
//      (e.g. "ZureMacro", "PremiumMacro" now encrypted; short class names still safe)
//   C  Strict mode via ctx.strictStrings (default: on for maximum tier only):
//      - Encrypts ALL PascalCase strings (any length not in reflection whitelist)
//      - Encrypts ALL_CAPS strings >= 6 chars
//      Medium tier keeps Option B behavior for safety.
// Previous v15.0 (Phase 3C):
// AzureVM Obfuscator v15.0 - Phase 3C added (Multi-layer VM)
// Applied fixes (this batch):
//   3C  Multi-layer VM: outer 6-opcode meta-VM reconstructs inner bc[] at runtime
//       - Per-run random opcode numbers, XOR key, position multiplier, rotate amount
//       - Byte-level rotate + position-dependent XOR encryption of inner bytestream
//       - ADVANCE no-op injected for pattern noise (~20% frequency)
//       - Auto-fallback to single-layer for tiny programs (<9 bc entries)
//       - Attacker must reverse BOTH VMs to extract inner bytecode
// Previous v14.0 (Phase 3A+3B):
// Applied fixes (this batch):
//   3A  VM dispatcher rewritten as table lookup + closures (no more if/elseif chain)
//       - Real + junk opcodes shuffled at emit time, each is a captured closure
//       - HALT via sentinel error in outer pcall (avoids per-tick flag check)
//   3B  Anti-debugger + anti-tamper enabled for low/medium/high/extreme
//       - Soft mode (skips hook-detect check) when script uses hookfunction
//         or hookmetamethod legitimately
//       - Suspicion counter: 2+ checks must fire before silent exit
//       - Only disabled when script uses BOTH hookfunction AND hookmetamethod
// Previous v13.0 (Phase 2):
// Applied fixes (this batch):
//   2A  Constant obfuscation in VM constants pool (encodeNumber on numeric consts)
//   2B  Conservative string encryption re-enabled with reflection-safe whitelist
//       - Skips: <4 or >800 chars, PascalCase, ALL_CAPS, __metatable, Roblox globals,
//         rbx URIs, service/class/method/event names (200+ entries)
//       - Skips string positions: obj["field"], {["k"]=v}, t["m"](), :"lit",
//         GetService/FindFirstChild/WaitForChild/etc argument slots
// Previous fixes (v12.0 Phase 1):
//   P0.1  Fixed `const code` self-reference in obfuscate() main flow
// Applied fixes:
//   P0.1  Fixed `const code` self-reference in obfuscate() main flow
//   P0.2  Fixed `effectiveIsMaximum` used-before-declared (TDZ ReferenceError)
//   P0.3  Fixed HALT dispatch: `elseif op=` -> `elseif op==`
//   P1.1  Polymorphic opcodes verified active (was silently disabled by P0.2)
//   P1.2  VM dispatch branches now shuffled per run (real + junk intermixed)
//   P1.4  Removed dead makeOpTable() (replaced by makeRandomizedOpTable)
// Effect: main obfuscation path (v13/v14/v16 features, VM wrap on maximum)
// now actually runs instead of throwing TDZ and falling back to minifier.
//
// AzureVM Obfuscator v11.4 - line-break minifier for executor compatibility
// v11.4 changes:
// - Aggressive minify now inserts newlines every ~500 chars at safe boundaries
// - Prevents Delta/Synapse/Fluxus parsers from choking on massive single-line scripts
// - Same code size and protection, just parseable
// - Fixes "attempt to call nil value" caused by silent parser truncation
// v11.0 - pre-analysis + safer Luau conversion
// v11.0 changes:
// - PRE-ANALYSIS PASS: symbol table, scope tree, forward-ref detection
// - Compound assign: strips inline comments from RHS (fixes - swallowing paren)
// - Continue labels: safer function-boundary check
// - Better parse-error reporting: exact line + context in logs
// - Downgrades gracefully with loud warnings instead of silent byte-level fallback
// v10.6 - disabled buggy string encryption
// v10.5 - - VM whitelist: Roblox/executor globals only
// v10.4 - - declaration-order tracking, no reordering
// v10.3 - - top-local tracking, method-call passthrough
// v10.2 - - method-call passthrough, executor-aware loader
// v10.1 - - executor-aware loader chain)
// Original: - - - - - v10.0 (Complete rewrite: simple exec_core, no nested returns, no CFF wrap)
// Improvements over v8.1:
//   1. Constants Pool with poison entries (was: unused/broken)
//   2. Position + prev-byte dependent stream cipher (was: triple XOR only)
//   3. VM expanded to 55+ opcodes with dummy variants (was: 35)
//   4. Randomized base64 alphabet per obfuscation (was: standard)
//   5. Junk with real side effects - - - - - - - - - - - - - DCE-resistant (was: pure locals)
//   6. Higher VM cap: 500 + smart sensitive-first sorting (was: 200)
const luaparse = require("luaparse");
const crypto = require("crypto");

// v16.0: ObfuscationReport - collects metadata across all passes so the
// dashboard can show WHY a given level was actually applied and WHICH
// layers fired. Populated by obfuscateWithReport().
class ObfuscationReport {
  constructor(requestedLevel){
    this.requestedLevel = requestedLevel;
    this.actualLevel = requestedLevel;
    this.wasDowngraded = false;
    this.downgradeReason = null;
    this.profile = null;
    this.layers = {
      vmWrap: false,
      outerVM: false,
      antiDebugger: false,
      antiDebuggerMode: null,
      integrityCheck: false,
      stringEncryption: false,
      stringEncryptionStrict: false,
      constantPool: false,
      constantObfuscation: false,
      byteLevelXor: false,
      antiTamper: false,
      antiDump: false
    };
    this.stats = {
      originalBytes: 0,
      obfuscatedBytes: 0,
      sizeRatio: 0,
      stringsEncrypted: 0,
      stringsSkipped: 0,
      numericConstsObfuscated: 0,
      vmCompiledStatements: 0,
      vmBytecodeLength: 0,
      elapsedMs: 0
    };
    this.warnings = [];
    this.timestamp = new Date().toISOString();
  }
  warn(msg){ this.warnings.push(msg); }
  setDowngrade(reason, newLevel){
    this.wasDowngraded = true;
    this.downgradeReason = reason;
    this.actualLevel = newLevel;
  }
  finalize(originalBytes, obfuscatedBytes, elapsedMs){
    this.stats.originalBytes = originalBytes;
    this.stats.obfuscatedBytes = obfuscatedBytes;
    this.stats.sizeRatio = originalBytes > 0
      ? Number((obfuscatedBytes / originalBytes).toFixed(3))
      : 0;
    this.stats.elapsedMs = elapsedMs;
  }
}


const ROBLOX_GLOBALS = new Set([
  "game","workspace","script","plugin","shared","_G","_ENV",
  "Enum","Instance","Vector2","Vector3","CFrame","Color3","UDim","UDim2",
  "Rect","Region3","Ray","BrickColor","NumberSequence","NumberSequenceKeypoint",
  "ColorSequence","ColorSequenceKeypoint","NumberRange","TweenInfo","PhysicalProperties",
  "Random","Faces","Axes","Vector2int16","Vector3int16","Font",
  "wait","spawn","delay","tick","time","elapsedTime","print","warn","error",
  "assert","pcall","xpcall","select","typeof","type","next","pairs","ipairs",
  "unpack","tostring","tonumber","setmetatable","getmetatable","rawget","rawset",
  "rawequal","rawlen","collectgarbage","loadstring","load","require","dofile",
  "loadfile","getfenv","setfenv","newproxy","coroutine",
  "string","table","math","os","io","debug","bit32","utf8",
  "task","buffer","getgenv","getrenv","getsenv","getreg",
  "hookfunction","hookmetamethod","getnamecallmethod","getconnections",
  "getgc","getinstances","getnilinstances","getscripts","getloadedmodules",
  "getcallingscript","getrawmetatable","setrawmetatable","checkcaller",
  "isreadonly","setreadonly","iscclosure","islclosure","newcclosure",
  "identifyexecutor","lz4compress","lz4decompress","queue_on_teleport",
  "syn","fluxus","krnl","delta","electron","sentinel","krampus",
  // v11.2: Extended executor globals - anti-detection, filesystem, cloning
  "cloneref","gethui","getnamecallmethod","setnamecallmethod","isexecutorclosure",
  "hookfunc","hookmethod","setthreadidentity","getthreadidentity",
  "isfile","isfolder","readfile","writefile","makefolder","delfolder","listfiles","delfile",
  "loadfile","getcustomasset","getsynasset","fireclickdetector","fireproximityprompt",
  "firetouchinterest","firesignal","replicatesignal",
  "setclipboard","setrbxclipboard","toclipboard","messagebox","request","http_request","http",
  "rconsoleprint","rconsoleinfo","rconsolewarn","rconsoleerror","rconsoleinput","rconsolename","rconsoleclear",
  "getscripthash","getscriptclosure","clonefunction","getcallbackvalue","comparetables",
  "getexecutorname","getexecutorversion",
  // Common Roblox datatypes and services (were missing)
  "Drawing","WebSocket","crypt","base64","cache",
  "OverlapParams","RaycastParams","DateTime","PathWaypoint",
  "Vector3","Vector2","CFrame","Color3","UDim","UDim2","Rect","Region3","Ray",
  "TweenInfo","NumberSequence","ColorSequence","NumberRange","BrickColor",
  "SharedTable","Content","Path2DControlPoint",
  // Luraph/obfuscator markers (harmless if unused, breaks if renamed)
  "LPH_NO_VIRTUALIZE","LPH_JIT","LPH_ENCSTR","LPH_NO_UPVALUES",
  "self","true","false","nil",
  "and","or","not","if","then","else","elseif","end","do","while","repeat","until",
  "for","in","function","return","break","goto","continue","local"
]);

const WORD_BINARY_OPS = new Set(["and","or",".."]);

// v6.2: Fake watermark rotation - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - decoy to mislead attackers into using
// wrong deobfuscator tools (Luraph/Luarmor/IronBrew deobs won't help here)
const _FAKE_WATERMARKS = [
  "-- This file was protected using Luraph Obfuscator v14.8 [https://lura.ph/]",
  "-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]",
  "-- This file was protected using Luraph Obfuscator v14.6.2 [https://lura.ph/]",
  "-- Obfuscated using Luarmor v3.9.1 [https://luarmor.net/]",
  "-- IronBrew v2.9.1 - Protection Level: MAX",
  "-- Prometheus 0.5.1 - https://github.com/levno-710/Prometheus",
  "-- MoonSec V3 [https://moonsec.dev/]"
];
function pickWatermark(){
  return _FAKE_WATERMARKS[_secRand(0,_FAKE_WATERMARKS.length-1)]+"\n";
}



// v9.0: Expanded from 35 to 55+ opcodes - - - - - - - - - - - - - dummy variants confuse pattern analysis
const OP_NAMES = [
  "PUSH_CONST","PUSH_NIL","PUSH_TRUE","PUSH_FALSE","PUSH_GLOBAL","SET_GLOBAL",
  "DUP","POP","CALL","RETURN","ADD","SUB","MUL","DIV","MOD","POW","CONCAT",
  "EQ","NEQ","LT","LE","GT","GE","NOT","NEG","LEN","JMP","JMP_IF_FALSE","JMP_IF_TRUE",
  "NEW_TABLE","SET_INDEX","GET_INDEX","GET_MEMBER","SET_MEMBER","METHOD_CALL","HALT",
  // Dummy opcodes - - - - - - - - - - - - - never emitted by compiler but present in interpreter
  "NOP_A","NOP_B","NOP_C","NOP_D","NOP_E",
  "SWAP","ROT3","PUSH_ZERO","PUSH_ONE","PUSH_NEG_ONE",
  "INC","DEC","DOUBLE","HALVE","SQUARE",
  "STR_LEN","STR_UPPER","STR_LOWER","STR_REVERSE","BITWISE_XOR"
];

// v8.1: Use crypto for security-critical randomness (keys, state numbers, opcodes)
// Falls back to Math.random if crypto.randomInt unavailable (older Node)
function _secRand(min,max){
  try{ return crypto.randomInt(min,max+1); }
  catch(e){ return min+Math.floor(Math.random()*(max-min+1)); }
}
function randInt(min,max){return _secRand(min,max);}
function randChoice(a){return a[_secRand(0,a.length-1)];}
function randHexName(len){
  len=len||6;
  const c="0123456789abcdef";
  let o="_0x";
  for(let i=0;i<len;i++)o+=c[_secRand(0,15)];
  return o;
}

// v9.0: Custom base64 alphabet - - - - - - - - - - - - - shuffled per obfuscation for anti-pattern-matching
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function makeCustomB64Alphabet(){
  const arr = B64_STD.split("");
  for(let i = arr.length - 1; i > 0; i--){
    const j = _secRand(0, i);
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  return arr.join("");
}

// v9.0: Stream cipher - - - - - - - - - - - - - position + prev-byte feedback (ChaCha20-inspired)
// Much harder to reverse than static XOR because each byte depends on the last
function streamCipherEncrypt(str, key1, key2, key3, iv){
  const bytes = [];
  let prev = iv & 0xff;
  for(let i = 0; i < str.length; i++){
    let c = str.charCodeAt(i) & 0xff;
    c ^= (key1 + (i % 251)) & 0xff;
    c ^= (prev + key2) & 0xff;
    c ^= (key3 + ((i * 7) % 137)) & 0xff;
    bytes.push(c);
    prev = c;
  }
  return bytes;
}

function makeStreamCipherDecoder(fnName, key1, key2, key3, iv){
  return "local function " + fnName + "(t) " +
    "local s = '' " +
    "local prev = " + iv + " " +
    "for i = 1, #t do " +
      "local c = t[i] " +
      "c = bit32.bxor(c, (" + key1 + " + ((i-1) % 251)) % 256) " +
      "c = bit32.bxor(c, (prev + " + key2 + ") % 256) " +
      "c = bit32.bxor(c, (" + key3 + " + ((i-1) * 7) % 137) % 256) " +
      "prev = t[i] " +
      "s = s .. string.char(c) " +
    "end " +
    "return s " +
  "end";
}

// P1.4 removed: makeOpTable() dead - superseded by makeRandomizedOpTable() (v14.0)

function preprocess(code){
  code=code.replace(/\r\n/g,"\n").replace(/\r/g,"\n");
  let out="";
  let i=0;
  const len=code.length;
  while(i<len){
    const c=code[i];
    const next=i+1<len?code[i+1]:"";
    if(c==="-"&&next==="-"){
      const j=i+2;
      if(code[j]==="["){
        let level=0,k=j+1;
        while(code[k]==="="){level++;k++;}
        if(code[k]==="["){
          const closer="]"+"=".repeat(level)+"]";
          const endIdx=code.indexOf(closer,k+1);
          if(endIdx>0){i=endIdx+closer.length;continue;}
          i=len;continue;
        }
      }
      while(i<len&&code[i]!=="\n")i++;
      continue;
    }
    if(c==="["){
      let level=0,j=i+1;
      while(code[j]==="="){level++;j++;}
      if(code[j]==="["){
        const closer="]"+"=".repeat(level)+"]";
        const endIdx=code.indexOf(closer,j+1);
        if(endIdx>0){out+=code.substring(i,endIdx+closer.length);i=endIdx+closer.length;continue;}
        out+=code.substring(i);i=len;continue;
      }
    }
    if(c==='"'||c==="'"){
      const quote=c;out+=c;i++;
      while(i<len){
        const ch=code[i];
        if(ch==="\\"&&i+1<len){out+=ch+code[i+1];i+=2;continue;}
        if(ch===quote){out+=ch;i++;break;}
        if(ch==="\n"){out+=ch;i++;break;}
        out+=ch;i++;
      }
      continue;
    }
    if(c==="`"){
      out+=c;i++;
      let depth=0;
      while(i<len){
        const ch=code[i];
        if(ch==="\\"&&i+1<len){out+=ch+code[i+1];i+=2;continue;}
        if(ch==="{")depth++;
        if(ch==="}")depth--;
        if(ch==="`"&&depth===0){out+=ch;i++;break;}
        out+=ch;i++;
      }
      continue;
    }
    out+=c;i++;
  }
  out=out.split("\n").map(l=>l.replace(/\s+$/,"")).join("\n");
  return out.trim();
}

// v9.1: Convert Luau-specific syntax to plain Lua 5.1 so luaparse can handle it
// Handles: compound assignments (+=, -=, *=, /=, ..=), continue statements, type annotations
function luauToLua(code) {
  // v9.5 fixes:
  // - Compound assignment precedence: wrap RHS in parens
  //     Before: a += b or c - - - - - - - - - - - - - a = a + b or c   (WRONG: parses as (a+b) or c)
  //     After:  a += b or c - - - - - - - - - - - - - a = a + (b or c) (correct)
  // - continue: convert to 'goto __continue_N__' and inject matching label before loop's 'end'
  //     This preserves semantic behavior (actually skips iteration in Lua 5.3)

  const strings = [];
  let idx = 0;

  // - Step 1: Protect strings first (character tokenizer, safest) -
  let work = "";
  let i = 0;
  const len = code.length;

  while (i < len) {
    const c = code[i];
    const next = i + 1 < len ? code[i + 1] : "";

    // Long-bracket comment
    if (c === "-" && next === "-") {
      let j = i + 2;
      if (code[j] === "[") {
        let level = 0, k = j + 1;
        while (code[k] === "=") { level++; k++; }
        if (code[k] === "[") {
          const closer = "]" + "=".repeat(level) + "]";
          const endIdx = code.indexOf(closer, k + 1);
          if (endIdx > 0) { i = endIdx + closer.length; continue; }
          i = len; continue;
        }
      }
      // Line comment
      while (i < len && code[i] !== "\n") i++;
      continue;
    }

    // Long-bracket string
    if (c === "[") {
      let level = 0, j = i + 1;
      while (code[j] === "=") { level++; j++; }
      if (code[j] === "[") {
        const closer = "]" + "=".repeat(level) + "]";
        const endIdx = code.indexOf(closer, j + 1);
        if (endIdx > 0) {
          const strContent = code.substring(i, endIdx + closer.length);
          const key = "___STR_" + (idx++) + "___";
          strings.push({ key, value: strContent });
          work += key;
          i = endIdx + closer.length;
          continue;
        }
      }
    }

    // Regular string
    if (c === '"' || c === "'") {
      const quote = c;
      let strStart = i;
      i++;
      while (i < len) {
        const ch = code[i];
        if (ch === "\\" && i + 1 < len) { i += 2; continue; }
        if (ch === quote) { i++; break; }
        if (ch === "\n") { break; }
        i++;
      }
      const strContent = code.substring(strStart, i);
      const key = "___STR_" + (idx++) + "___";
      strings.push({ key, value: strContent });
      work += key;
      continue;
    }

    // Backtick string
    if (c === "`") {
      let strStart = i;
      i++;
      let bDepth = 0;
      while (i < len) {
        const ch = code[i];
        if (ch === "\\" && i + 1 < len) { i += 2; continue; }
        if (ch === "{") bDepth++;
        else if (ch === "}") bDepth--;
        else if (ch === "`" && bDepth === 0) { i++; break; }
        i++;
      }
      const strContent = code.substring(strStart, i);
      const key = "___STR_" + (idx++) + "___";
      strings.push({ key, value: strContent });
      work += key;
      continue;
    }

    work += c;
    i++;
  }

  // - Step 2: Compound assignments with PRECEDENCE-SAFE wrapping -
  // Match: LHS op= REST_OF_EXPRESSION_UNTIL_STATEMENT_END
  // Then rewrite: LHS = LHS op (RHS)
  const IDENT = "[A-Za-z_][A-Za-z0-9_]*";
  const CHAIN = IDENT + "(?:\\s*[.:]\\s*" + IDENT + "|\\s*\\[[^\\]]+\\])*";
  // Match compound assignment and capture the entire RHS until end of line or ';'
  const compoundRegex = new RegExp(
    "(" + CHAIN + ")\\s*([+\\-*/%]|\\.\\.)=\\s*([^\\n;]+)",
    "g"
  );
  work = work.replace(compoundRegex, (m, lhs, op, rhs) => {
    // v11.0: Strip inline "-" comment from RHS before wrapping in parens.
    // Without this, "x += 5 - note" would become "x = x + (5 - note)" and
    // the - swallows the closing paren, causing a silent parse error.
    let cleanRhs = rhs;
    let inStr = null;
    for (let i = 0; i < cleanRhs.length - 1; i++) {
      const c = cleanRhs[i];
      if (inStr) {
        if (c === "\\") { i++; continue; }
        if (c === inStr) inStr = null;
      } else {
        if (c === '"' || c === "'") { inStr = c; continue; }
        if (c === "-" && cleanRhs[i+1] === "-") { cleanRhs = cleanRhs.substring(0, i); break; }
      }
    }
    cleanRhs = cleanRhs.trim();
    if (!cleanRhs) return m;
    return lhs + " = " + lhs + " " + op + " (" + cleanRhs + ")";
  });

  // - Step 3: continue - - - - - - - - - - - - - goto __continue_N__ + inject matching labels -
  // Strategy: assign a unique counter per loop, replace 'continue' inside with goto,
  // then inject ::__continue_N__:: before the 'end' of each loop that has a continue.
  //
  // Since we can't easily track loop nesting with regex, use this approach:
  //   1. Find each 'continue' occurrence
  //   2. Walk BACKWARDS to find the nearest enclosing loop start (for/while/repeat)
  //   3. Assign a unique label for that loop
  //   4. Replace continue with goto __continue_N__
  //   5. Inject ::__continue_N__:: before the matching 'end' or 'until'
  //
  // For simplicity + safety, we use a scan-based approach:
  // - Split into tokens conceptually via a simple state machine
  // - Track loop depth using keyword matching
  // - Assign labels per loop

  work = injectContinueLabels(work);

  // - Step 4: Type annotations (safe: only in specific contexts) -
  // Rule 1: local x: Type = ...
  work = work.replace(
    new RegExp("(\\blocal\\s+" + IDENT + "(?:\\s*,\\s*" + IDENT + ")*)\\s*:\\s*[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?(?:\\.[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?)*\\??", "g"),
    "$1"
  );

  // Rule 2: function params (name: Type, ...)
  work = work.replace(/\(([^()]*)\)/g, (m, inside) => {
    const cleaned = inside.replace(
      new RegExp("(" + IDENT + ")\\s*:\\s*[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?(?:\\.[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?)*\\??", "g"),
      "$1"
    );
    return "(" + cleaned + ")";
  });

  // Rule 3: return types
  work = work.replace(
    /(\))\s*:\s*[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?)*\??(?=\s*(?:\n|--|\bthen\b|\bdo\b|\breturn\b|\blocal\b|\bif\b|\bfor\b|\bwhile\b|\brepeat\b|\bend\b|;|$))/g,
    "$1"
  );

  // Rule 4: type Foo = ...
  work = work.replace(/^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*=.*$/gm, "");

  // Rule 5: export type
  work = work.replace(/^\s*export\s+type\s+.*$/gm, "");

  // - Step 5: Restore protected strings -
  for (const s of strings) {
    work = work.split(s.key).join(s.value);
  }

  return work;
}

// v9.6 helper: inject goto labels for continue statements
// FIX: Every 'if' block also needs 'end' tracking; ambiguity resolved by
// treating ALL 'end'-terminated constructs uniformly.
function injectContinueLabels(code) {
  if (code.indexOf("continue") < 0) return code;

  const tokens = tokenizeForContinue(code);
  const blockStack = [];
  let labelCounter = 0;
  const result = [];

  for (let ti = 0; ti < tokens.length; ti++) {
    const t = tokens[ti];

    if (t.kind === "keyword") {
      const kw = t.value;

      // Opening block keywords - - - - - - - - - - - - - each pushes exactly ONE block
      if (kw === "for" || kw === "while") {
        blockStack.push({ type: "pending_loop", labelName: null, needsLabel: false, kw });
      } else if (kw === "repeat") {
        // 'repeat' opens a loop that closes with 'until' (NOT 'end')
        blockStack.push({ type: "repeat_loop", labelName: null, needsLabel: false, kw });
      } else if (kw === "function") {
        blockStack.push({ type: "function", labelName: null, needsLabel: false, kw });
      } else if (kw === "if") {
        blockStack.push({ type: "if", labelName: null, needsLabel: false, kw });
      } else if (kw === "do") {
        // 'do' after 'for'/'while' = part of that loop's opener (don't push new block)
        // 'do' standalone = do-block that also uses 'end'
        const top = blockStack[blockStack.length - 1];
        if (top && top.type === "pending_loop") {
          top.type = "loop"; // promote to actual loop
        } else {
          blockStack.push({ type: "do", labelName: null, needsLabel: false, kw });
        }
      } else if (kw === "then") {
        // 'then' is part of if/elseif clause - - - - - - - - - - - - - no block push
        // But 'if X then' needs to open the if body; the block for 'if' was already pushed
      } else if (kw === "elseif") {
        // Continuation of if - - - - - - - - - - - - - no block change
      } else if (kw === "else") {
        // Continuation of if - - - - - - - - - - - - - no block change
      } else if (kw === "end") {
        // Close the topmost block (regardless of type: for/while/if/function/do)
        const closing = blockStack.pop();
        if (closing && closing.type === "loop" && closing.needsLabel) {
          result.push({ kind: "raw", value: " ::" + closing.labelName + ":: " });
        }
        // Note: 'repeat' loops close with 'until', not 'end' - - - - - - - - - - - - - handled below
      } else if (kw === "until") {
        // Close a repeat_loop
        // If the top block isn't a repeat_loop, we have a bug - - - - - - - - - - - - - but pop anyway to stay in sync
        const closing = blockStack.pop();
        if (closing && closing.type === "repeat_loop" && closing.needsLabel) {
          // For 'repeat body until cond', the label goes BEFORE 'until'
          result.push({ kind: "raw", value: " ::" + closing.labelName + ":: " });
        }
      } else if (kw === "continue") {
        // v11.0 FIX: walk back through if/do freely; only stop at function boundary.
        // Previously a 'continue' above a function boundary could leave a
        // dangling goto label, causing a silent parse error.
        let loopBlock = null;
        for (let bi = blockStack.length - 1; bi >= 0; bi--) {
          const b = blockStack[bi];
          if (b.type === "function") break;
          if (b.type === "loop" || b.type === "repeat_loop") {
            loopBlock = b;
            break;
          }
        }
        if (loopBlock) {
          if (!loopBlock.labelName) {
            loopBlock.labelName = "__continue_" + (labelCounter++) + "__";
            loopBlock.needsLabel = true;
          }
          result.push({ kind: "raw", value: "goto " + loopBlock.labelName });
          continue;
        } else {
          // continue outside a loop - - - - - - - - - - - - - safe no-op
          result.push({ kind: "raw", value: "--[[continue]]" });
          continue;
        }
      }
    }

    result.push(t);
  }

  return result.map(t => t.value).join("");
}

// Simple tokenizer for continue-label injection
// Splits into keywords (for/while/repeat/do/end/until/function/if/continue) and everything else
function tokenizeForContinue(code) {
  const tokens = [];
  const keywords = new Set(["for","while","repeat","do","end","until","function","if","continue"]);
  let i = 0;
  const len = code.length;
  let buffer = "";

  const flushBuffer = () => {
    if (buffer.length > 0) {
      tokens.push({ kind: "text", value: buffer });
      buffer = "";
    }
  };

  while (i < len) {
    const c = code[i];

    // Skip inside string placeholder ___STR_N___
    if (c === "_" && code.substring(i, i + 5) === "___ST") {
      // Read until end of placeholder
      const endIdx = code.indexOf("___", i + 5);
      if (endIdx > 0) {
        buffer += code.substring(i, endIdx + 3);
        i = endIdx + 3;
        continue;
      }
    }

    // Identifier / keyword
    if (/[a-zA-Z_]/.test(c)) {
      let j = i;
      while (j < len && /[a-zA-Z0-9_]/.test(code[j])) j++;
      const word = code.substring(i, j);
      if (keywords.has(word)) {
        // Check word boundary - - - - - - - - - - - - - must not be preceded by identifier char
        const prevChar = i > 0 ? code[i - 1] : " ";
        if (!/[a-zA-Z0-9_]/.test(prevChar)) {
          flushBuffer();
          tokens.push({ kind: "keyword", value: word });
          i = j;
          continue;
        }
      }
      buffer += word;
      i = j;
      continue;
    }

    buffer += c;
    i++;
  }

  flushBuffer();
  return tokens;
}

function aggressiveMinify(code){
  code=preprocess(code);
  code=code.split("\n").map(l=>l.trim()).filter(l=>l.length>0).join("\n");
  code=code.replace(/[ \t]+/g," ");
  const lines=code.split("\n");
  const result=[];
  for(let i=0;i<lines.length;i++){
    const line=lines[i];
    if(result.length===0){result.push(line);continue;}
    const prev=result[result.length-1].trim();
    let addSemi=true;
    if(/\b(do|then|else|repeat)\s*$/.test(prev))addSemi=false;
    else if(/[=,{(\[+\-*/%<>~^&|.:;]$/.test(prev))addSemi=false;
    else if(/\b(and|or|not|in|return|local|elseif)\s*$/.test(prev))addSemi=false;
    else if(/\)\s*$/.test(prev)&&/\bfunction\b/.test(prev)&&!/\bend\s*\)\s*$/.test(prev))addSemi=false;
    else if(/^(and|or|not)\b/.test(line))addSemi=false;
    else if(/^[.:,)\]}+\-*/%<>=~^&|]/.test(line))addSemi=false;
    else if(/^(then|do|else|elseif|end|until)\b/.test(line))addSemi=false;
    if(addSemi)result[result.length-1]=prev+";";
    result.push(line);
  }
  let out=result.join(" ");
  out=out.replace(/  +/g," ").replace(/;\s*;/g,";").replace(/;\s*end\b/g," end").replace(/;\s*\)/g,")").replace(/;\s*\}/g," }").replace(/;\s*until\b/g," until").replace(/;\s*elseif\b/g," elseif").replace(/;\s*else\b/g," else").replace(/;\s*then\b/g," then").replace(/;\s*do\b/g," do").replace(/;\s*(and|or)\b/g," $1").replace(/;\s*(\.\.|:|\.)/g," $1");
  // v11.4: break long lines every ~500 chars at safe boundaries (after ";" or "end")
  // Prevents Delta/executor parser from choking on massive single-line scripts.
  const CHUNK_TARGET = 500;
  const chunked = [];
  let lastBreak = 0;
  for(let i = CHUNK_TARGET; i < out.length; i += CHUNK_TARGET){
    // Find nearest ";" or " end " or " do " within next 200 chars
    let breakAt = -1;
    for(let j = i; j < Math.min(i + 200, out.length); j++){
      if(out[j] === ";" && (out[j-1] !== "\\" )){
        breakAt = j + 1;
        break;
      }
    }
    if(breakAt > lastBreak){
      chunked.push(out.substring(lastBreak, breakAt));
      lastBreak = breakAt;
      i = breakAt;
    }
  }
  if(lastBreak < out.length) chunked.push(out.substring(lastBreak));
  return chunked.join("\n").trim();
}

function vmCanCompile(node){
  if(!node)return false;
  const t=node.type;
  if(t==="CallStatement"){
    const e=node.expression;
    if(!e)return false;
    // v10.2 FIX: Reject method calls (obj:method()) - - VM compiler treats them
    // as regular calls, which loses the 'self' arg and turns the method name
    // into a global lookup, causing 'attempt to index nil with <method>' crashes.
    if(e.type==="CallExpression"){
      if(_hasMethodCall(e.base))return false;
      return vmCanCompile(e.base)&&e.arguments.every(a=>vmCanCompileExpr(a));
    }
    if(e.type==="StringCallExpression"){
      if(_hasMethodCall(e.base))return false;
      return vmCanCompile(e.base)&&vmCanCompileExpr(e.argument);
    }
    return false;
  }
  if(t==="Identifier"||t==="MemberExpression")return true;
  return false;
}

// v10.2: Walk AST and detect any method-syntax member access (indexer ":")
function _hasMethodCall(node){
  if(!node||typeof node!=="object")return false;
  if(node.type==="MemberExpression"&&node.indexer===":")return true;
  if(node.type==="MemberExpression")return _hasMethodCall(node.base);
  if(node.type==="IndexExpression")return _hasMethodCall(node.base)||_hasMethodCall(node.index);
  if(node.type==="CallExpression"){
    if(_hasMethodCall(node.base))return true;
    for(const a of (node.arguments||[])){
      if(_hasMethodCall(a))return true;
    }
    return false;
  }
  return false;
}

function vmCanCompileExpr(node){
  if(!node)return false;
  const t=node.type;
  if(t==="StringLiteral"||t==="NumericLiteral"||t==="BooleanLiteral"||t==="NilLiteral")return true;
  if(t==="Identifier")return true;
  if(t==="MemberExpression")return vmCanCompileExpr(node.base);
  if(t==="BinaryExpression"){
    const okOps=new Set(["+","-","*","/","%","..","==","~=","<","<=",">",">="]);
    return okOps.has(node.operator)&&vmCanCompileExpr(node.left)&&vmCanCompileExpr(node.right);
  }
  if(t==="UnaryExpression"){
    const okOps=new Set(["not","-","#"]);
    return okOps.has(node.operator)&&vmCanCompileExpr(node.argument);
  }
  if(t==="CallExpression"){
    if(_hasMethodCall(node.base))return false;
    return vmCanCompileExpr(node.base)&&node.arguments.every(a=>vmCanCompileExpr(a));
  }
  return false;
}

function vmCompileExpr(node, bc, consts, globals, OP){
  const t=node.type;
  if(t==="StringLiteral"){
    let idx=consts.findIndex(c=>c.type==="s"&&c.value===node.value);
    if(idx<0){consts.push({type:"s",value:node.value});idx=consts.length-1;}
    bc.push(OP.PUSH_CONST,idx);return;
  }
  if(t==="NumericLiteral"){
    let idx=consts.findIndex(c=>c.type==="n"&&c.value===node.value);
    if(idx<0){consts.push({type:"n",value:node.value});idx=consts.length-1;}
    bc.push(OP.PUSH_CONST,idx);return;
  }
  if(t==="BooleanLiteral"){bc.push(node.value?OP.PUSH_TRUE:OP.PUSH_FALSE);return;}
  if(t==="NilLiteral"){bc.push(OP.PUSH_NIL);return;}
  if(t==="Identifier"){
    let idx=globals.indexOf(node.name);
    if(idx<0){globals.push(node.name);idx=globals.length-1;}
    bc.push(OP.PUSH_GLOBAL,idx);return;
  }
  if(t==="MemberExpression"){
    vmCompileExpr(node.base,bc,consts,globals,OP);
    let idx=consts.findIndex(c=>c.type==="s"&&c.value===node.identifier.name);
    if(idx<0){consts.push({type:"s",value:node.identifier.name});idx=consts.length-1;}
    bc.push(OP.GET_MEMBER,idx);
    return;
  }
  if(t==="CallExpression"){
    vmCompileExpr(node.base,bc,consts,globals,OP);
    for(const a of node.arguments) vmCompileExpr(a,bc,consts,globals,OP);
    bc.push(OP.CALL,node.arguments.length,1);
    return;
  }
  if(t==="BinaryExpression"){
    vmCompileExpr(node.left,bc,consts,globals,OP);
    vmCompileExpr(node.right,bc,consts,globals,OP);
    const map={"+":OP.ADD,"-":OP.SUB,"*":OP.MUL,"/":OP.DIV,"%":OP.MOD,"..":OP.CONCAT,
               "==":OP.EQ,"~=":OP.NEQ,"<":OP.LT,"<=":OP.LE,">":OP.GT,">=":OP.GE};
    bc.push(map[node.operator]);
    return;
  }
  if(t==="UnaryExpression"){
    vmCompileExpr(node.argument,bc,consts,globals,OP);
    const map={"not":OP.NOT,"-":OP.NEG,"#":OP.LEN};
    bc.push(map[node.operator]);
    return;
  }
}

function vmCompileStmt(node,bc,consts,globals,OP){
  if(node.type==="CallStatement"){
    const e=node.expression;
    if(e.type==="CallExpression"){
      vmCompileExpr(e.base,bc,consts,globals,OP);
      for(const a of e.arguments) vmCompileExpr(a,bc,consts,globals,OP);
      bc.push(OP.CALL,e.arguments.length,0);
    } else if(e.type==="StringCallExpression"){
      vmCompileExpr(e.base,bc,consts,globals,OP);
      vmCompileExpr(e.argument,bc,consts,globals,OP);
      bc.push(OP.CALL,1,0);
    }
  }
}

function generateVMInterpreter(vmFn,OP,junkOpNames){
  // v14.0 (3A): Table-dispatch VM. Each opcode is a closure in a lookup table.
  // Runtime: local h={[N]=function() ... end, ...}; while true do h[op]() end
  // - Zero linear branch chain for pattern-matchers to fingerprint.
  // - Real + junk closures shuffled at emit time (order in table is randomized).
  // - Stack/sp/pc/bc/ks/gs/env captured as upvalues (Lua closes over them).
  // - HALT throws a sentinel error caught by an outer pcall, avoiding a
  //   flag-check-per-tick and preserving Luau's fast-path for closures.
  const realBranches = [
    ["PUSH_CONST",   "ps(ks[bc[pc]+1]) pc=pc+1"],
    ["PUSH_NIL",     "ps(nil)"],
    ["PUSH_TRUE",    "ps(true)"],
    ["PUSH_FALSE",   "ps(false)"],
    ["PUSH_GLOBAL",  "ps(env[gs[bc[pc]+1]]) pc=pc+1"],
    ["SET_GLOBAL",   "env[gs[bc[pc]+1]]=pp() pc=pc+1"],
    ["DUP",          "ps(st[sp])"],
    ["POP",          "pp()"],
    ["CALL",         "local na=bc[pc] pc=pc+1 local nr=bc[pc] pc=pc+1 local a={} for i=na,1,-1 do a[i]=pp() end local f=pp() local r={f(unpack(a))} if nr>0 then for i=1,nr do ps(r[i]) end end"],
    ["RETURN",       "error(_HALT,0)"],
    ["ADD",          "local b=pp() local a=pp() ps(a+b)"],
    ["SUB",          "local b=pp() local a=pp() ps(a-b)"],
    ["MUL",          "local b=pp() local a=pp() ps(a*b)"],
    ["DIV",          "local b=pp() local a=pp() ps(a/b)"],
    ["MOD",          "local b=pp() local a=pp() ps(a%b)"],
    ["POW",          "local b=pp() local a=pp() ps(a^b)"],
    ["CONCAT",       "local b=pp() local a=pp() ps(a..b)"],
    ["EQ",           "local b=pp() local a=pp() ps(a==b)"],
    ["NEQ",          "local b=pp() local a=pp() ps(a~=b)"],
    ["LT",           "local b=pp() local a=pp() ps(a<b)"],
    ["LE",           "local b=pp() local a=pp() ps(a<=b)"],
    ["GT",           "local b=pp() local a=pp() ps(a>b)"],
    ["GE",           "local b=pp() local a=pp() ps(a>=b)"],
    ["NOT",          "ps(not pp())"],
    ["NEG",          "ps(-pp())"],
    ["LEN",          "ps(#pp())"],
    ["JMP",          "pc=pc+bc[pc]"],
    ["JMP_IF_FALSE", "local v=pp() local o=bc[pc] pc=pc+1 if not v then pc=pc+o end"],
    ["JMP_IF_TRUE",  "local v=pp() local o=bc[pc] pc=pc+1 if v then pc=pc+o end"],
    ["NEW_TABLE",    "ps({})"],
    ["SET_INDEX",    "local v=pp() local k=pp() local t=st[sp] t[k]=v"],
    ["GET_INDEX",    "local k=pp() local t=pp() ps(t[k])"],
    ["GET_MEMBER",   "local m=ks[bc[pc]+1] pc=pc+1 local t=pp() ps(t[m])"],
    ["SET_MEMBER",   "local m=ks[bc[pc]+1] pc=pc+1 local v=pp() local t=pp() t[m]=v"],
    ["METHOD_CALL",  "local m=ks[bc[pc]+1] pc=pc+1 local na=bc[pc] pc=pc+1 local nr=bc[pc] pc=pc+1 local a={} for i=na,1,-1 do a[i]=pp() end local t=pp() local r={t[m](t,unpack(a))} if nr>0 then for i=1,nr do ps(r[i]) end end"],
    ["HALT",         "error(_HALT,0)"],
    // v9.0 dummy opcodes - never emitted, present in dispatch table
    ["NOP_A",        "local _n=1+2"],
    ["NOP_B",        "local _n=bit32.band(15,15)"],
    ["NOP_C",        "local _n=math.floor(3.14)"],
    ["NOP_D",        "local _n=#'x'"],
    ["NOP_E",        "local _n=string.byte('a')"],
    ["SWAP",         "local a=pp() local b=pp() ps(a) ps(b)"],
    ["ROT3",         "local a=pp() local b=pp() local c=pp() ps(b) ps(a) ps(c)"],
    ["PUSH_ZERO",    "ps(0)"],
    ["PUSH_ONE",     "ps(1)"],
    ["PUSH_NEG_ONE", "ps(-1)"],
    ["INC",          "local a=pp() ps(a+1)"],
    ["DEC",          "local a=pp() ps(a-1)"],
    ["DOUBLE",       "local a=pp() ps(a*2)"],
    ["HALVE",        "local a=pp() ps(a/2)"],
    ["SQUARE",       "local a=pp() ps(a*a)"],
    ["STR_LEN",      "local a=pp() ps(#tostring(a))"],
    ["STR_UPPER",    "local a=pp() ps(string.upper(tostring(a)))"],
    ["STR_LOWER",    "local a=pp() ps(string.lower(tostring(a)))"],
    ["STR_REVERSE",  "local a=pp() ps(string.reverse(tostring(a)))"],
    ["BITWISE_XOR",  "local b=pp() local a=pp() ps(bit32.bxor(a,b))"]
  ];

  // Junk branches with per-run random bodies (no-op semantics)
  const junkBranches = [];
  for (const name of (junkOpNames || [])) {
    const body = randChoice([
      "local _j=bit32.bxor(" + randInt(1,255) + "," + randInt(1,255) + ")",
      "local _j=math.floor(" + randInt(100,9999) + "/" + randInt(2,9) + ")",
      "local _j=string.byte('" + randChoice(["x","a","z","q","m","n"]) + "')",
      "local _j=#'" + randChoice(["abc","xyzq","mnop","test"]) + "'"
    ]);
    junkBranches.push([name, body]);
  }

  // Fisher-Yates shuffle real + junk together
  const allBranches = realBranches.concat(junkBranches);
  for (let i = allBranches.length - 1; i > 0; i--) {
    const j = _secRand(0, i);
    const tmp = allBranches[i]; allBranches[i] = allBranches[j]; allBranches[j] = tmp;
  }

  // Random names for the dispatch table + halt sentinel
  const hVar = randHexName(5);
  const haltSentinel = randHexName(5);

  // Header: declare stack, sp, pc, ps, pp as upvalues that all closures capture.
  // We wrap dispatch in a pcall that catches the HALT sentinel.
  const header = "local function " + vmFn + "(bc,ks,gs,env) " +
    "local _HALT='" + haltSentinel + "' " +
    "local st={} local sp=0 local pc=1 " +
    "local function ps(v) sp=sp+1 st[sp]=v end " +
    "local function pp() local v=st[sp] st[sp]=nil sp=sp-1 return v end " +
    "local " + hVar + "={";

  // Emit the dispatch table entries in shuffled order.
  const entries = [];
  for (const [name, body] of allBranches) {
    const opNum = OP[name];
    if (opNum == null) continue;
    entries.push("[" + opNum + "]=function() " + body + " end");
  }
  const tableBody = entries.join(",");

  // Runner: pcall a while-loop that looks up the current op and calls it.
  // If the closure errors with _HALT, we treat it as clean exit.
  // Unknown opcodes (shouldn't happen) also break the loop harmlessly.
  const footer = "} " +
    "local ok,err=pcall(function() " +
      "while true do " +
        "local op=bc[pc] pc=pc+1 " +
        "local h=" + hVar + "[op] " +
        "if not h then return end " +
        "h() " +
      "end " +
    "end) " +
    "if not ok and err~=_HALT and type(err)=='string' and not string.find(err,_HALT,1,true) then " +
      // Unknown runtime error inside VM - re-raise so user sees it
      "error(err,0) " +
    "end " +
    "end";

  return header + tableBody + footer;
}
function packBytecode(bc){
  // v8.1: 24-bit packing prevents silent truncation for large const pools
  const bytes=[];
  for(const n of bc){
    let v = (typeof n === "number") ? Math.max(0, n|0) : 0;
    if(v > 0xffffff){
      console.warn("[obfuscator] Bytecode value overflow:", v, "(clamped)");
      v = 0xffffff;
    }
    bytes.push((v>>16)&0xff, (v>>8)&0xff, v&0xff);
  }
  return Buffer.from(bytes).toString("base64");
}

function makeBytecodeUnpacker(fnName){
  // v8.1: 24-bit unpacker (matches new packBytecode)
  return "local function "+fnName+"(s) local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' local d={} for i=1,#b do d[string.sub(b,i,i)]=i-1 end local pad=0 if string.sub(s,-2)=='==' then pad=2 elseif string.sub(s,-1)=='=' then pad=1 end s=string.gsub(s,'[^A-Za-z0-9+/=]','') local raw={} for i=1,#s,4 do local a=d[string.sub(s,i,i)] or 0 local b1=d[string.sub(s,i+1,i+1)] or 0 local c=d[string.sub(s,i+2,i+2)] or 0 local e=d[string.sub(s,i+3,i+3)] or 0 local n=bit32.bor(bit32.lshift(a,18),bit32.lshift(b1,12),bit32.lshift(c,6),e) table.insert(raw,bit32.band(bit32.rshift(n,16),0xff)) table.insert(raw,bit32.band(bit32.rshift(n,8),0xff)) table.insert(raw,bit32.band(n,0xff)) end for i=1,pad do table.remove(raw) end local out={} for i=1,#raw,3 do local h=raw[i] or 0 local m=raw[i+1] or 0 local l=raw[i+2] or 0 table.insert(out,bit32.bor(bit32.lshift(h,16),bit32.lshift(m,8),l)) end return out end";
}

// v15.0 (3C): Multi-layer VM helpers.
// buildOuterVmProgram encrypts the inner bytecode array into a scrambled
// bytestream + a program of outer VM ops that decrypts+emits each byte.
// The result: attacker never sees the raw inner bc[] in the output.
function buildOuterVmProgram(innerBc){
  // Per-run random parameters (encryption keys, rotate amounts, positions)
  const outerKey = _secRand(30, 220);
  const outerMult = _secRand(3, 13);        // pos multiplier for XOR key evolution
  const rotShift = _secRand(1, 7);          // byte rotation amount (1-7 bits)
  const rotOp = _secRand(3, 3);             // outer op number for SHIFT (kept 3 for now)

  // Outer opcodes - shuffled at emit time for polymorphism
  const OP_FETCH = _secRand(10, 40);
  const OP_XOR = _secRand(50, 80);
  const OP_SHIFT = _secRand(90, 120);
  const OP_EMIT = _secRand(130, 160);
  const OP_ADVANCE = _secRand(170, 200);
  const OP_HALT = _secRand(210, 250);

  // Ensure all outer opcodes are unique
  const opSet = new Set([OP_FETCH, OP_XOR, OP_SHIFT, OP_EMIT, OP_ADVANCE, OP_HALT]);
  if(opSet.size !== 6){
    // Rare collision - re-roll deterministically
    return buildOuterVmProgram(innerBc);
  }

  // Convert innerBc (which is a plain int array, values 0..0xffffff) to
  // per-byte stream. innerBc uses 24-bit packing (same as packBytecode).
  const rawBytes = [];
  for(const n of innerBc){
    let v = (typeof n === "number") ? Math.max(0, n|0) : 0;
    if(v > 0xffffff) v = 0xffffff;
    rawBytes.push((v>>16)&0xff, (v>>8)&0xff, v&0xff);
  }

  // Encrypt each byte using SAME formula the outer VM will decrypt with.
  // Encryption: for pos i (0-indexed), encrypted = rotateRight(rawByte, rotShift) XOR ((outerKey + i*outerMult) & 0xff)
  // Decryption: reverse - XOR first, then rotateLeft(rotShift).
  const encBytes = [];
  for(let i = 0; i < rawBytes.length; i++){
    const rb = rawBytes[i] & 0xff;
    // Right rotate first (byte-level)
    const rotated = ((rb >> rotShift) | (rb << (8 - rotShift))) & 0xff;
    // XOR with position-dependent key
    const enc = rotated ^ ((outerKey + i * outerMult) & 0xff);
    encBytes.push(enc & 0xff);
  }

  // Build the outer VM program.
  // Pattern per byte: FETCH, XOR, SHIFT, EMIT. Optional ADVANCE (no-op) injected
  // for noise between real ops.
  // Emit as a Lua table of {op, ...operands} pseudo-instructions.
  const program = [];
  for(let i = 0; i < encBytes.length; i++){
    program.push(OP_FETCH);
    program.push(OP_XOR);
    program.push(OP_SHIFT);
    program.push(OP_EMIT);
    // 20% chance to inject an ADVANCE no-op for pattern noise
    if(_secRand(0, 99) < 20) program.push(OP_ADVANCE);
  }
  program.push(OP_HALT);

  // Base64-encode both the program and the encrypted bytestream
  const progBase64 = Buffer.from(program).toString("base64");
  const streamBase64 = Buffer.from(encBytes).toString("base64");

  return {
    progBase64,
    streamBase64,
    outerKey,
    outerMult,
    rotShift,
    opFetch: OP_FETCH,
    opXor: OP_XOR,
    opShift: OP_SHIFT,
    opEmit: OP_EMIT,
    opAdvance: OP_ADVANCE,
    opHalt: OP_HALT
  };
}

// v15.0 (3C): Emit the Lua source for the outer VM.
// Takes the outer program parameters + the inner VM function name to
// hand off to once the inner bc[] is reconstructed.
function generateOuterVmSource(outerProg, innerVmFn, ksVar, gsVar){
  const decodeFn = randHexName(6);          // outer VM runner
  const b64Fn = randHexName(6);             // base64 -> byte-table decoder
  const progVar = randHexName(5);
  const streamVar = randHexName(5);
  const bcVar = randHexName(5);
  const posVar = randHexName(4);
  const pcVar = randHexName(4);
  const aVar = randHexName(4);

  // Base64 decoder for byte tables (produces 1 byte per source unit).
  // Standard b64 -> uint8[]. Reused by both outer program and stream decode.
  const b64Decoder = "local function " + b64Fn + "(s) " +
    "local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' " +
    "local d={} for i=1,#b do d[string.sub(b,i,i)]=i-1 end " +
    "local pad=0 " +
    "if string.sub(s,-2)=='==' then pad=2 elseif string.sub(s,-1)=='=' then pad=1 end " +
    "s=string.gsub(s,'[^A-Za-z0-9+/=]','') " +
    "local raw={} " +
    "for i=1,#s,4 do " +
      "local a=d[string.sub(s,i,i)] or 0 " +
      "local b1=d[string.sub(s,i+1,i+1)] or 0 " +
      "local c=d[string.sub(s,i+2,i+2)] or 0 " +
      "local e=d[string.sub(s,i+3,i+3)] or 0 " +
      "local n=bit32.bor(bit32.lshift(a,18),bit32.lshift(b1,12),bit32.lshift(c,6),e) " +
      "table.insert(raw,bit32.band(bit32.rshift(n,16),0xff)) " +
      "table.insert(raw,bit32.band(bit32.rshift(n,8),0xff)) " +
      "table.insert(raw,bit32.band(n,0xff)) " +
    "end " +
    "for i=1,pad do table.remove(raw) end " +
    "return raw " +
    "end";

  // Outer VM runner. Decodes base64 program + stream, walks the program,
  // reconstructs inner bc[], then hands off to inner VM.
  //
  // NOTE: bc[] uses 24-bit values (packed 3 bytes per int). We reassemble
  // from every 3 decrypted bytes.
  const runner = "local function " + decodeFn + "() " +
    "local prog=" + b64Fn + "(" + progVar + ") " +
    "local stream=" + b64Fn + "(" + streamVar + ") " +
    "local rawBytes={} " +
    "local " + posVar + "=0 " +      // outer stream position (0-indexed byte counter)
    "local " + pcVar + "=1 " +       // outer program counter (1-indexed Lua)
    "local " + aVar + "=0 " +        // register A (holds current byte being processed)
    "local progLen=#prog " +
    "local rotShift=" + outerProg.rotShift + " " +
    "local invRot=8-rotShift " +
    "while " + pcVar + "<=progLen do " +
      "local op=prog[" + pcVar + "] " +
      pcVar + "=" + pcVar + "+1 " +
      "if op==" + outerProg.opFetch + " then " +
        aVar + "=stream[" + posVar + "+1] or 0 " +
      "elseif op==" + outerProg.opXor + " then " +
        aVar + "=bit32.bxor(" + aVar + ",(" + outerProg.outerKey + "+" + posVar + "*" + outerProg.outerMult + ")%256) " +
      "elseif op==" + outerProg.opShift + " then " +
        // Rotate left by rotShift (undoing the right-rotate done at encrypt)
        aVar + "=bit32.band(bit32.bor(bit32.lshift(" + aVar + ",rotShift),bit32.rshift(" + aVar + ",invRot)),0xff) " +
      "elseif op==" + outerProg.opEmit + " then " +
        "table.insert(rawBytes," + aVar + ") " +
        posVar + "=" + posVar + "+1 " +
      "elseif op==" + outerProg.opAdvance + " then " +
        // No-op (padding for pattern noise)
      "elseif op==" + outerProg.opHalt + " then " +
        "break " +
      "end " +
    "end " +
    // Reassemble 24-bit ints from 3-byte groups
    "local " + bcVar + "={} " +
    "for i=1,#rawBytes,3 do " +
      "local h=rawBytes[i] or 0 " +
      "local m=rawBytes[i+1] or 0 " +
      "local l=rawBytes[i+2] or 0 " +
      "table.insert(" + bcVar + ",bit32.bor(bit32.lshift(h,16),bit32.lshift(m,8),l)) " +
    "end " +
    // Handoff to inner VM
    innerVmFn + "(" + bcVar + "," + ksVar + "," + gsVar + ",getfenv and getfenv() or _ENV) " +
    "end";

  const streamDecl = "local " + progVar + "=\"" + outerProg.progBase64 + "\"; " +
    "local " + streamVar + "=\"" + outerProg.streamBase64 + "\"";

  return {
    outerSource: b64Decoder + "; " + streamDecl + "; " + runner + "; " + decodeFn + "()",
    decodeFnName: decodeFn
  };
}

function serializeConsts(consts){
  // v13.0 (2A): Numeric consts get math-expression obfuscation via encodeNumber.
  // Strings stay as JSON literals here (they're already encrypted by walkAst
  // BEFORE they reach the VM constants pool via 2B).
  const parts = consts.map(c=>{
    if(c.type==="s")return JSON.stringify(c.value);
    if(c.type==="n")return encodeNumber(c.value);
    return "nil";
  });
  return "{"+parts.join(",")+"}";
}

function serializeGlobals(globals){
  return "{"+globals.map(g=>JSON.stringify(g)).join(",")+"}";
}


// v7.0: Constant Pool - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - global encrypted table with real + poison entries
// Deobfuscator sees _CP[47] but has no clue what index 47 decodes to
// without emulating the entire pool decryption
function generateConstantPool(entries, poolKey, poolShift, fnName, varName){
  fnName = fnName || "_cp" + randHexName(3);
  varName = varName || "_CP" + randHexName(2);

  const allEntries = [];
  for(const entry of (entries || [])){
    allEntries.push({real: true, value: entry});
  }

  // 20-40 poison decoy entries - - - - - - - - - - - - - realistic Roblox strings to waste analyst time
  const poisonStrings = [
    "HttpGet","GetService","Players","LocalPlayer","Character","Humanoid",
    "WalkSpeed","JumpPower","Health","MaxHealth","TeleportService","MarketplaceService",
    "UserInputService","RunService","Workspace","ReplicatedStorage","ServerScriptService",
    "FindFirstChild","WaitForChild","GetChildren","GetDescendants","Destroy","Clone",
    "PlayerAdded","CharacterAdded","Touched","MouseButton1Click","BindableEvent",
    "RemoteEvent","RemoteFunction","FireServer","InvokeServer","Fire","OnServerEvent",
    "PostAsync","RequestAsync","JSONEncode","JSONDecode","Server","Client",
    "print","warn","error","assert","pcall","xpcall"
  ];
  const poisonCount = randInt(20, 40);
  for(let i = 0; i < poisonCount; i++){
    allEntries.push({real: false, value: randChoice(poisonStrings) + "_" + randHexName(2)});
  }
  // Shuffle real+poison together
  for(let i = allEntries.length - 1; i > 0; i--){
    const j = _secRand(0, i);
    const tmp = allEntries[i]; allEntries[i] = allEntries[j]; allEntries[j] = tmp;
  }

  const encEntries = allEntries.map(e => {
    const bytes = encryptString(e.value, poolKey, poolShift);
    return "{" + bytes.join(",") + "}";
  });

  const decoderCode = "local function " + fnName + "(t) local k=" + poolKey +
    " local s='' for i=1,#t do s=s..string.char(bit32.bxor(t[i],(k+((i-1+" + poolShift +
    ")%11)))%256) end return s end";

  const poolCode = "local " + varName + "={" + encEntries.join(",") + "}";

  return decoderCode + "; " + poolCode;
}


// v7.0: Real Watermarking - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - user-specific fingerprint scattered as junk vars
// Format: local _wmSIGSHORT = HASHNUM  (looks like junk, but SIGSHORT + HASHNUM
// combination uniquely identifies which user obfuscated this)
function generateUserWatermark(userId){
  const uid = userId || "anon";
  // Simple hash of userId
  let hash = 0;
  for(let i = 0; i < uid.length; i++){
    hash = ((hash << 5) - hash + uid.charCodeAt(i)) | 0;
  }
  const sig = Math.abs(hash).toString(16).substring(0, 6);
  const marks = [];
  // Scatter 3-5 watermark vars
  const markCount = randInt(3, 5);
  for(let i = 0; i < markCount; i++){
    // Random prefix per var - - - - - - - - - - - - - no regex signature
    const varName = randHexName(2) + sig.substring(i % sig.length, (i % sig.length) + 3) + randHexName(2);
    const value = ((Math.abs(hash) >> (i * 4)) & 0xffff) | 1;
    marks.push("local " + varName + "=" + value);
  }
  return marks.join("; ");
}


// v7.0: Anti-Dump Protection
// Detects dumper tools calling getgc/getreg/debug.getupvalue and returns fake data
// Prevents Sirhurt/Synapse dumper from extracting real strings/functions
function generateAntiDump(){
  const chkFn = randHexName(6);
  const isDump = randHexName(5);
  const fakeGc = randHexName(5);
  const fakeReg = randHexName(5);
  return "local " + chkFn + "=function() local " + isDump + "=false " +
    "if getgc then local ok,_=pcall(function() local g=getgc(true) for _,v in ipairs(g) do if type(v)=='function' then local i=debug.getinfo and debug.getinfo(v,'S') if i and i.short_src and string.find(i.short_src,'dumper') then " + isDump + "=true end end end end) end " +
    "if getreg then local ok=pcall(getreg) if not ok then " + isDump + "=true end end " +
    "if " + isDump + " then " +
    "local " + fakeGc + "=function() return {} end " +
    "local " + fakeReg + "=function() return {['fake_data']='dumper_detected'} end " +
    "if getgenv then pcall(function() getgenv().getgc=" + fakeGc + " getgenv().getreg=" + fakeReg + " end) end " +
    "end " +
    "return not " + isDump + " end " + chkFn + "()";
}



// v8.0: Control Flow Flattening - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - wraps execution in state-machine dispatcher
// Deobfuscator sees while-loop with random state numbers, can't determine flow order
function generateCFFDispatcher(payloadStates){
  const stateVar = randHexName(5);
  const dispatchFn = randHexName(6);
  const doneFlag = randHexName(4);
  // Randomize state numbers so order isn't obvious
  const shuffled = payloadStates.map((code,i)=>({code, realIdx:i, stateNum: randInt(100,9999)}));
  // Add 3-5 fake states that jump back to themselves (never execute payload)
  const fakeCount = randInt(3, 5);
  const fakeStates = [];
  for(let i = 0; i < fakeCount; i++){
    fakeStates.push({
      code: "local " + randHexName(4) + "=" + randInt(1,999) + "*" + randInt(1,999),
      realIdx: -1,
      stateNum: randInt(100,9999),
      nextState: randInt(100,9999)
    });
  }
  // Build the state machine
  let dispatcher = "local " + stateVar + "=" + shuffled[0].stateNum + "; ";
  dispatcher += "local " + doneFlag + "=false; ";
  dispatcher += "while not " + doneFlag + " do ";
  // Real state branches
  shuffled.forEach((s, idx)=>{
    const isFirst = idx === 0;
    const prefix = isFirst ? "if " : "elseif ";
    const nextStateNum = idx < shuffled.length - 1 ? shuffled[idx + 1].stateNum : null;
    dispatcher += prefix + stateVar + "==" + s.stateNum + " then " + s.code + "; ";
    if(nextStateNum !== null){
      dispatcher += stateVar + "=" + nextStateNum + " ";
    } else {
      dispatcher += doneFlag + "=true ";
    }
  });
  // Fake state branches (never reached - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - dead code)
  fakeStates.forEach(s=>{
    dispatcher += "elseif " + stateVar + "==" + s.stateNum + " then " + s.code + "; " + stateVar + "=" + s.nextState + " ";
  });
  dispatcher += "else " + doneFlag + "=true end end";
  return dispatcher;
}


// v8.0: Self-Modifying Bytecode - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - bytecode is XOR-scrambled at rest
// Runtime unscrambles it just before execution. Static disassembly = garbage.
function scrambleBytecode(bcArr, scrambleKey){
  const scrambled = bcArr.map((byte, i) => (byte ^ (scrambleKey + (i % 23))) & 0xff);
  return scrambled;
}

function generateBytecodeUnscrambler(fnName, scrambleKey){
  return "local function " + fnName + "(arr) local out={} for i=1,#arr do out[i]=bit32.bxor(arr[i],(" + scrambleKey + "+((i-1)%23)))%256 end return out end";
}


// v8.0: String Chunking - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - splits strings into pieces, concats at runtime
// Adds junk function calls between chunks to disrupt pattern matching
function chunkString(str){
  if(str.length < 6) return null; // too short to chunk usefully
  const numChunks = Math.min(4, Math.max(2, Math.floor(str.length / 5)));
  const chunkSize = Math.ceil(str.length / numChunks);
  const chunks = [];
  for(let i = 0; i < str.length; i += chunkSize){
    chunks.push(str.substring(i, Math.min(i + chunkSize, str.length)));
  }
  // Build concat expression with occasional junk empty-string fns
  const parts = chunks.map((c, i) => {
    if(i > 0 && Math.random() < 0.3){
      // Insert junk empty string generator between chunks
      const junkFn = randChoice([
        "(function() return '' end)()",
        "string.rep('',1)",
        "string.sub('a',1,0)"
      ]);
      return junkFn + " .. " + JSON.stringify(c);
    }
    return JSON.stringify(c);
  });
  return "(" + parts.join(" .. ") + ")";
}


function tripleXorEncrypt(str,k1,k2,k3){
  const bytes=[];
  for(let i=0;i<str.length;i++){
    let c=str.charCodeAt(i);
    c=(c^(k1+(i%13)))&0xff;
    c=(c^(k2+(i%7)))&0xff;
    c=(c^(k3+((i*3)%17)))&0xff;
    bytes.push(c);
  }
  return bytes;
}

function bytesToBase64(bytes){return Buffer.from(bytes).toString("base64");}

function makeTripleXorDecoder(fnName,k1,k2,k3){
  return "local function "+fnName+"(s) local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' local d={} for i=1,#b do d[string.sub(b,i,i)]=i-1 end local o={} local pad=0 if string.sub(s,-2)=='==' then pad=2 elseif string.sub(s,-1)=='=' then pad=1 end s=string.gsub(s,'[^A-Za-z0-9+/=]','') for i=1,#s,4 do local a=d[string.sub(s,i,i)] or 0 local b1=d[string.sub(s,i+1,i+1)] or 0 local c=d[string.sub(s,i+2,i+2)] or 0 local e=d[string.sub(s,i+3,i+3)] or 0 local n=bit32.bor(bit32.lshift(a,18),bit32.lshift(b1,12),bit32.lshift(c,6),e) table.insert(o,string.char(bit32.band(bit32.rshift(n,16),0xff))) table.insert(o,string.char(bit32.band(bit32.rshift(n,8),0xff))) table.insert(o,string.char(bit32.band(n,0xff))) end local r=table.concat(o) if pad>0 then r=string.sub(r,1,#r-pad) end local out={} for i=1,#r do local x=string.byte(r,i) x=bit32.bxor(x,("+k3+"+(((i-1)*3)%17)))%256 x=bit32.bxor(x,("+k2+"+((i-1)%7)))%256 x=bit32.bxor(x,("+k1+"+((i-1)%13)))%256 out[i]=string.char(x) end return table.concat(out) end";
}

function makeFakeDecoders(count){
  const decoders=[];
  for(let i=0;i<count;i++){
    const fn=randHexName(5);
    const p=randHexName(3);
    const junk=randInt(1,255);
    decoders.push("local function "+fn+"("+p+") local r='' for i=1,#"+p+" do r=r..string.char(bit32.bxor(string.byte("+p+",i),"+junk+")%256) end return r end");
  }
  return decoders.join(" ");
}

// v9.0: DCE-resistant junk - - - - - - - - - - - - - writes to shared table so dead-code elimination
// can't prove the writes are unused. Attacker can't strip these safely.
function generateJunkOps(count, sharedTable){
  const ops=[];
  const st = sharedTable || "_G";
  for(let i=0;i<count;i++){
    const v=randHexName(4);
    const k=randHexName(3);
    const op=randChoice([
      st+"['"+k+"']="+randInt(1,999)+"*"+randInt(1,999),
      st+"['"+k+"']="+randInt(0,999)+"+"+randInt(0,999),
      st+"['"+k+"']=math.floor("+randInt(100,9999)+"/"+randInt(2,9)+")",
      st+"['"+k+"']=bit32.bxor("+randInt(0,255)+","+randInt(0,255)+")",
      "local "+v+"="+randInt(1,999)+"; "+st+"['"+k+"']="+v,
      "local "+v+"=string.rep('"+randChoice(["x","a","z","q"])+"',"+randInt(1,5)+"); "+st+"['"+k+"']=#"+v,
      st+"["+randInt(100,9999)+"]={"+randInt(1,999)+","+randInt(1,999)+","+randInt(1,999)+"}",
      st+"['"+k+"']=("+st+"['"+k+"'] or 0)+"+randInt(1,10)
    ]);
    ops.push(op);
  }
  return ops.join("; ");
}

function generateOpaquePredicate(payload){
  const conds=[
    "((2*3)==6)","(math.floor(1.5)==1)","(string.len('x')==1)","(#'ab'==2)",
    "(bit32.band(15,15)==15)","(((1+1)==2) and ((3-1)==2))","(type(1)=='number')"
  ];
  const c1=randChoice(conds);
  const c2=randChoice(conds);
  const junkV=randHexName(4);
  // v10.0: NO extra pcall wrap - exec_core is self-contained with its own pcalls
  // Simple opaque predicate that either runs payload directly or does nothing
  return "if "+c1+" and "+c2+" then pcall(function() "+payload+" end) else local "+junkV+"="+randInt(1,999)+"*"+randInt(1,999)+" end";
}

function generateAntiTamper(){
  // v10.0: Ultra-simple - just a wrapper function that returns a value
  // No pcall inside pcall, no conflicting hookfunction tests, no infinite loops
  const wrapper = randHexName(6);
  const val = randHexName(4);
  return "local "+wrapper+"=function() local "+val+"=bit32.bxor(15,15) return "+val+"==0 end "+wrapper+"()";
}

function encryptString(str,key,shift){
  const bytes=[];
  for(let i=0;i<str.length;i++){
    const c=str.charCodeAt(i);
    const k=key+((i+shift)%11);
    bytes.push((c^k)&0xff);
  }
  return bytes;
}

function makeStringDecoder(varName,key,shift){
  return "local function "+varName+"(t) local k="+key+" local s='' for i=1,#t do s=s..string.char(bit32.bxor(t[i],(k+((i-1+"+shift+")%11)))%256) end return s end";
}

function bytesToLuaTable(bytes){return "{"+bytes.join(",")+"}";}

// v13.0 (2B): Names/tokens that must NEVER be string-encrypted.
// Encrypting these breaks Roblox reflection (GetService, FindFirstChild by name,
// Enum lookups, remote event names, etc.).
const NEVER_ENCRYPT_STRINGS = new Set([
  // Roblox services (used by GetService(name))
  "Players","ReplicatedStorage","ReplicatedFirst","ServerStorage","ServerScriptService",
  "Workspace","Lighting","StarterGui","StarterPack","StarterPlayer","StarterPlayerScripts",
  "StarterCharacterScripts","SoundService","Chat","TextChatService","Teams","Debris",
  "TweenService","RunService","UserInputService","CoreGui","GuiService","ContextActionService",
  "HttpService","DataStoreService","MessagingService","MemoryStoreService","PathfindingService",
  "PhysicsService","CollectionService","MarketplaceService","TeleportService","PolicyService",
  "LocalizationService","BadgeService","GamePassService","GroupService","FriendsService",
  "SocialService","AnalyticsService","AssetService","InsertService","ContentProvider",
  "TextService","VoiceChatService","Stats","LogService","VirtualUser","VirtualInputManager",
  "HapticService","VRService","GuiService","NotificationService","AdService","OmniRecommendationsService",
  // Common instance/class names used in FindFirstChild/WaitForChild by string
  "Humanoid","HumanoidRootPart","Head","Torso","LeftArm","RightArm","LeftLeg","RightLeg",
  "Character","Backpack","PlayerGui","PlayerScripts","Camera","Terrain","Baseplate",
  "Animator","Animation","AnimationTrack","Sound","SoundGroup","ParticleEmitter",
  "PointLight","SpotLight","SurfaceLight","BillboardGui","ScreenGui","SurfaceGui",
  "TextLabel","TextButton","TextBox","ImageLabel","ImageButton","Frame","ScrollingFrame",
  "UIListLayout","UIGridLayout","UIPadding","UICorner","UIStroke","UIGradient","UISizeConstraint",
  "UIAspectRatioConstraint","LocalScript","Script","ModuleScript","Folder","Configuration",
  "IntValue","StringValue","BoolValue","NumberValue","ObjectValue","Vector3Value","CFrameValue",
  "Color3Value","BrickColorValue","RayValue","BindableEvent","BindableFunction","RemoteEvent",
  "RemoteFunction","UnreliableRemoteEvent","Attachment","Motor6D","Weld","WeldConstraint",
  "Part","MeshPart","UnionOperation","WedgePart","CornerWedgePart","TrussPart","SpawnLocation",
  "Model","BasePart","Tool","HopperBin","Hint","Message","Decal","Texture","SelectionBox",
  "Beam","Trail","Explosion","Fire","Smoke","Sparkles",
  // Common method/property names used via string keys or reflection
  "Parent","Name","ClassName","Value","Text","Position","Size","Anchored","CanCollide",
  "Transparency","Color","Material","BrickColor","Reflectance","Visible","Active","Enabled",
  "Locked","CFrame","Orientation","Rotation","Origin","Direction","LookVector","RightVector",
  "UpVector","Velocity","AssemblyLinearVelocity","AssemblyAngularVelocity","Mass",
  // Enum categories
  "Enum","EnumItem","KeyCode","UserInputType","MouseBehavior","HttpMethod","Material",
  "NormalId","Axis","SortOrder","StartCorner","FillDirection","HorizontalAlignment",
  "VerticalAlignment","EasingStyle","EasingDirection","PlaybackState","AspectType",
  "SizeConstraint","ScaleType","Font","FontSize","TextXAlignment","TextYAlignment",
  // Common event/callback names
  "Touched","TouchEnded","Changed","AncestryChanged","ChildAdded","ChildRemoved",
  "DescendantAdded","DescendantRemoving","Destroying","PlayerAdded","PlayerRemoving",
  "CharacterAdded","CharacterRemoving","CharacterAppearanceLoaded","Died","HealthChanged",
  "Running","Jumping","Climbing","Seated","StateChanged","FreeFalling","GettingUp",
  "MouseButton1Click","MouseButton2Click","MouseButton1Down","MouseButton1Up",
  "MouseEnter","MouseLeave","MouseMoved","InputBegan","InputEnded","InputChanged",
  "OnServerEvent","OnClientEvent","OnServerInvoke","OnClientInvoke","OnInvoke","Event",
  "OnServerEvent","AttributeChanged","Attribute",
  // Common method names (used with : call syntax - normally we skip via context,
  // but include as belt-and-suspenders)
  "GetService","FindFirstChild","WaitForChild","GetChildren","GetDescendants","IsA",
  "IsDescendantOf","FindFirstAncestorOfClass","FindFirstAncestor","FindFirstChildOfClass",
  "FindFirstChildWhichIsA","Destroy","Clone","Kill","Connect","Disconnect","Wait","Fire",
  "FireServer","FireClient","FireAllClients","InvokeServer","InvokeClient","GetAttribute",
  "SetAttribute","GetAttributes","AddTag","RemoveTag","GetTags","HasTag",
  "GetPropertyChangedSignal","ClearAllChildren","BreakJoints","MakeJoints","MoveTo",
  "PivotTo","GetPivot","SetPrimaryPartCFrame","GetPrimaryPartCFrame","GetBoundingBox",
  "GetModelCFrame","GetModelSize","GetExtentsSize","LoadCharacter","LoadAnimation",
  "Play","Stop","Pause","Resume","AdjustSpeed","AdjustWeight","GetTimeOfDay",
  "HttpGet","HttpGetAsync","HttpPost","HttpPostAsync","GetAsync","SetAsync",
  "UpdateAsync","IncrementAsync","RemoveAsync","GetOrderedDataStore","GetDataStore",
  "PromptPurchase","PromptGamePassPurchase","UserOwnsGamePassAsync","GetProductInfo",
  "TeleportAsync","Teleport","TeleportToPlaceInstance","GetPlaceIdFromScript",
  // Http headers / MIME
  "Content-Type","application/json","text/plain","Accept","User-Agent","Authorization",
  // Rich text tokens
  "rbxassetid","rbxthumb","rbxasset","http","https",
  // v21.0: Reflection-heavy script markers (macrozure/anti-cheat/net-scanning)
  "TIME","PRY","RE/","SwordsController","PlayerController","GameController",
  "MainController","UIController","InputController","CameraController",
  "sleitnick_net","Knit","Signal","Trove","Janitor","Fusion","Roact","Rodux",
  "Packages","_Index","Modules","Shared","Client","Server","Common",
  // Common upvalue-scan / getgc hash keys
  "hashA","hashB","netNum","parryRemote","timeKey","parryFlag",
]);

// v13.0 (2B) + v15.1 (Option B+C): Decide if a StringLiteral is safe to encrypt.
// Returns true = safe to encrypt, false = keep literal.
//
// Option B (default): Loosened PascalCase filter ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â PascalCase strings of length >= 8
//   that don't match known Roblox class/service names ARE encrypted. This lifts
//   things like "ZureMacro", "AzureLogo", "LogoHit" out of skip and into encrypt.
//
// Option C (strict mode): When ctx.strictStrings === true, encrypt even
//   short PascalCase / ALL_CAPS strings (skipping only the explicit reflection
//   whitelist). User's responsibility to audit output; may break scripts that
//   pass class names as strings via runtime construction.
function _shouldEncryptString(value, strict){
  if(typeof value !== "string") return false;
  const len = value.length;
  if(len < 4 || len > 800) return false;
  // Explicit whitelists always win (never encrypt these regardless of mode)
  if(NEVER_ENCRYPT_STRINGS.has(value)) return false;
  if(ROBLOX_GLOBALS.has(value)) return false;
  if(value.startsWith("__")) return false;
  // v21.0: Package version keys (Wally/Rojo/Knit format: name@version)
  if(/^[a-zA-Z_][a-zA-Z0-9_]*@[\d\.]+$/.test(value)) return false;
  // v21.0: PascalCase +Service/+Controller/+Handler/+Manager class-like names
  // These are commonly used as string keys in reflection/service lookups.
  if(/^[A-Z][a-zA-Z0-9]*(Service|Controller|Handler|Manager|Module|Config)$/.test(value)) return false;
  // v21.0: Short ALL_CAPS tokens used as hash-map keys in anti-cheat scripts
  if(/^[A-Z]{2,6}$/.test(value)) return false;
  // Roblox asset URIs must stay literal for the engine to resolve
  if(/^rbxassetid:\/\//.test(value)) return false;
  if(/^rbxthumb:\/\//.test(value)) return false;
  if(/^rbxasset:\/\//.test(value)) return false;
  // ALL_CAPS: strict mode encrypts if >= 6 chars, default keeps them literal
  if(/^[A-Z0-9_]+$/.test(value)) {
    return !!strict && len >= 6;
  }
  // PascalCase handling
  if(/^[A-Z][A-Za-z0-9]*$/.test(value)) {
    if(strict) return true;                  // Option C: encrypt all PascalCase
    return len >= 8;                          // Option B: encrypt long PascalCase only
  }
  return true;
}

function encodeNumber(n){
  if(!Number.isInteger(n)||n<0||n>200000)return String(n);
  const v=randInt(0,5);
  switch(v){
    case 0:{const a=randInt(0,Math.max(1,n));return "("+a+"+"+(n-a)+")";}
    case 1:{if(n<4)return String(n);const a=randInt(2,7);const b=Math.floor(n/a);const c=n-a*b;return "("+a+"*"+b+(c>=0?"+"+c:c)+")";}
    case 2:{const o=randInt(1,500);return "("+(n+o)+"-"+o+")";}
    case 3:{const m=randInt(1,255);return "bit32.bxor("+(n^m)+","+m+")";}
    case 4:{if(n===0)return "0";const s=randInt(1,4);return "bit32.rshift("+(n<<s)+","+s+")";}
    case 5:{const b=randInt(1,Math.max(1,Math.floor(n/2)));return "("+b+"+"+(n-b)+")";}
    default:return String(n);
  }
}

// v15.0: Scope-aware RenameCtx
// Each nested scope (function/block) gets its own local map. When looking up
// a name, we walk from innermost to outermost scope. When declaring a new
// local, it goes into the current scope only - so `local dragging` in
// function A doesn't conflict with `local dragging` in function B.
class RenameCtx{
  constructor(externalSet){
    // Stack of scope maps. The top of stack is the innermost active scope.
    this.scopes = [new Map()];  // start with a global-ish scope for top-level locals
    this.counter = 0;
    this.externals = externalSet || new Set();
  }

  pushScope(){
    this.scopes.push(new Map());
  }

  popScope(){
    if(this.scopes.length > 1){
      this.scopes.pop();
    }
  }

  declare(name){
    if(ROBLOX_GLOBALS.has(name)) return name;
    if(this.externals.has(name)) return name;
    // v17: If already declared in current scope (via hoist), reuse it.
    const cur = this.scopes[this.scopes.length - 1];
    if(cur.has(name)) return cur.get(name);
    const n = randHexName(6) + "_" + this.counter.toString(16);
    this.counter++;
    cur.set(name, n);
    return n;
  }

  // v17 NEW: Hoist local decls in a body BEFORE walking children.
  // Fixes forward-reference bug where setActive is used before declaration.
  hoistScope(body){
    if(!Array.isArray(body)) return;
    for(const stmt of body){
      if(!stmt || typeof stmt !== "object") continue;
      if(stmt.type === "LocalStatement" && Array.isArray(stmt.variables)){
        for(const v of stmt.variables){
          if(v && v.type === "Identifier" && v.name) this.declare(v.name);
        }
      }
      else if(stmt.type === "FunctionDeclaration" && stmt.isLocal
              && stmt.identifier && stmt.identifier.type === "Identifier"){
        this.declare(stmt.identifier.name);
      }
      // v21.0: Non-local top-level function decls (bare "function foo()"). In
      // real Lua these become globals, but scripts often use them as if they
      // were locals with forward-ref. Hoisting them here matches user intent
      // and stops the rename pass from bleeding two different names for the
      // same symbol (declaration vs. forward call site).
      else if(stmt.type === "FunctionDeclaration" && !stmt.isLocal
              && stmt.identifier && stmt.identifier.type === "Identifier"){
        this.declare(stmt.identifier.name);
      }
      // v21.0: Bare assignments at top level ("foo = function() ... end" or
      // "foo = 42"). Hoist the LHS so forward refs resolve consistently.
      else if(stmt.type === "AssignmentStatement" && Array.isArray(stmt.variables)){
        for(const v of stmt.variables){
          if(v && v.type === "Identifier" && v.name) this.declare(v.name);
        }
      }
    }
  }

  lookup(name){
    if(ROBLOX_GLOBALS.has(name)) return name;
    if(this.externals.has(name)) return name;
    for(let i = this.scopes.length - 1; i >= 0; i--){
      if(this.scopes[i].has(name)){
        return this.scopes[i].get(name);
      }
    }
    // v17 CRITICAL: don't auto-declare unknown names. Let them resolve
    // to real globals at Lua runtime.
    return name;
  }

  rename(name){
    if(ROBLOX_GLOBALS.has(name)) return name;
    if(this.externals.has(name)) return name;
    const cur = this.scopes[this.scopes.length - 1];
    if(cur.has(name)) return cur.get(name);
    return this.declare(name);
  }

  get map(){
    const self = this;
    return {
      has: (name) => {
        if(ROBLOX_GLOBALS.has(name)) return false;
        if(self.externals.has(name)) return false;
        for(let i = self.scopes.length - 1; i >= 0; i--){
          if(self.scopes[i].has(name)) return true;
        }
        return false;
      },
      get: (name) => self.lookup(name),
    };
  }
}

function walkAst(node,ctx){
  if(!node||typeof node!=="object")return;

  // v13.0 (2B): Lazy-init the string-encrypt skip set for this walk.
  if(ctx && !ctx._skipStr) ctx._skipStr = new WeakSet();

  if(node.type==="NumericLiteral"&&typeof node.value==="number"){
    node.__obf={type:"num",expr:encodeNumber(node.value)};
    if(ctx && ctx._reportCounts) ctx._reportCounts.numericConstsObfuscated++;
    return;
  }

  // v13.0 (2B): Conservative string encryption.
  // Only encrypt if this string node is NOT flagged as "skip" by its parent
  // AND passes the content filter.
  if(node.type==="StringLiteral" && typeof node.value === "string"
     && ctx && ctx.stringKey != null && !ctx._skipStr.has(node)){
    if(_shouldEncryptString(node.value, ctx.strictStrings)){
      const bytes = encryptString(node.value, ctx.stringKey, ctx.stringShift);
      node.__obf = {type:"str", bytes};
      if(ctx._reportCounts) ctx._reportCounts.stringsEncrypted++;
    } else {
      if(ctx._reportCounts) ctx._reportCounts.stringsSkipped++;
    }
    return; // don't descend into StringLiteral children (there are none)
  }

  // v13.0 (2B): Mark unsafe string positions on children BEFORE recursing.
  // These are AST positions where the string is used as a name/key that
  // Lua evaluates at parse time, not at runtime.
  if(ctx && ctx._skipStr){
    // obj:MethodName(args) - the identifier after ':' is a name lookup
    if(node.type==="MemberExpression" && node.indexer===":" && node.identifier){
      // identifier is Identifier, not StringLiteral, so no marking needed
    }
    // obj["field"] - if index is a StringLiteral, it's a name lookup at runtime;
    // Roblox often uses this for property/child access. Keep it literal so
    // executor's __index metamethod can resolve without decrypting first.
    if(node.type==="IndexExpression" && node.index
       && node.index.type==="StringLiteral"){
      ctx._skipStr.add(node.index);
    }
    // {["field"]=value} in table constructors - same reason as above
    if(node.type==="TableKeyString" && node.key
       && node.key.type==="StringLiteral"){
      ctx._skipStr.add(node.key);
    }
    // t["MethodName"](args) call - the base of a CallExpression whose
    // callee resolves via string index should also stay literal
    if(node.type==="CallExpression" && node.base
       && node.base.type==="IndexExpression" && node.base.index
       && node.base.index.type==="StringLiteral"){
      ctx._skipStr.add(node.base.index);
    }
    // StringCallExpression: myFn"literal" - the argument is passed as string
    if(node.type==="StringCallExpression" && node.argument
       && node.argument.type==="StringLiteral"){
      ctx._skipStr.add(node.argument);
    }
    // Function call with first arg being GetService/FindFirstChild-style name
    // (extra safety - these must survive as literal string for reflection)
    if(node.type==="CallExpression" && node.base){
      const calleeName = _getCalleeName(node.base);
      if(calleeName && (
           calleeName === "GetService" ||
           calleeName === "FindFirstChild" ||
           calleeName === "WaitForChild" ||
           calleeName === "FindFirstChildOfClass" ||
           calleeName === "FindFirstChildWhichIsA" ||
           calleeName === "FindFirstAncestorOfClass" ||
           calleeName === "FindFirstAncestor" ||
           calleeName === "IsA" ||
           calleeName === "GetAttribute" ||
           calleeName === "SetAttribute" ||
           calleeName === "GetPropertyChangedSignal" ||
           calleeName === "new"  // Instance.new("Part") - class name must be literal
      )){
        if(Array.isArray(node.arguments)){
          for(const arg of node.arguments){
            if(arg && arg.type === "StringLiteral") ctx._skipStr.add(arg);
          }
        }
      }
    }
  }

  // v17: Hoist top-level decls BEFORE any descent so forward refs work.
  if(ctx.rename && node.type === "Chunk" && Array.isArray(node.body)){
    ctx.rename.hoistScope(node.body);
  }

  // v15.0: Scope management for function/loop bodies
  const opensNewScope = ctx.rename && (
    node.type==="FunctionDeclaration" ||
    node.type==="FunctionExpression"
  );

  // For local function declarations, declare the name in the PARENT scope
  // BEFORE opening the new function scope (so recursive calls work).
  if(ctx.rename && node.type==="FunctionDeclaration"
     && node.isLocal && node.identifier && node.identifier.type==="Identifier"){
    node.identifier.name = ctx.rename.declare(node.identifier.name);
  }
  // v21.0: Non-local top-level function decls that were hoisted in hoistScope.
  // Look up the hoisted name (declare() no-ops if already present) and rewrite
  // the identifier so the emitted code matches all the renamed call sites.
  else if(ctx.rename && node.type==="FunctionDeclaration"
     && !node.isLocal && node.identifier && node.identifier.type==="Identifier"){
    const hoistedName = ctx.rename.lookup(node.identifier.name);
    if(hoistedName !== node.identifier.name){
      node.identifier.name = hoistedName;
    }
  }

  if(opensNewScope){
    ctx.rename.pushScope();
    if(Array.isArray(node.parameters)){
      node.parameters.forEach(p=>{
        if(p.type==="Identifier"&&p.name) p.name=ctx.rename.declare(p.name);
      });
    }
    // v17: Hoist locals inside this function body before walking children.
    if(node.body && Array.isArray(node.body)){
      ctx.rename.hoistScope(node.body);
    }
  }

  const opensLoopScope = ctx.rename && (
    node.type==="ForNumericStatement" ||
    node.type==="ForGenericStatement"
  );
  if(opensLoopScope){
    ctx.rename.pushScope();
    if(node.type==="ForNumericStatement" && node.variable && node.variable.name){
      node.variable.name = ctx.rename.declare(node.variable.name);
    }
    if(node.type==="ForGenericStatement" && Array.isArray(node.variables)){
      node.variables.forEach(v=>{
        if(v.name) v.name = ctx.rename.declare(v.name);
      });
    }
  }

  if(ctx.rename){
    if(node.type==="LocalStatement"&&Array.isArray(node.variables)){
      node.variables.forEach(v=>{
        if(v.type==="Identifier"&&v.name) v.name=ctx.rename.declare(v.name);
      });
    }
  }

  for(const k in node){
    if(k==="loc"||k==="range"||k==="__obf")continue;
    // Skip re-processing the parameter/variable arrays we already handled
    if(opensNewScope && k==="parameters") continue;
    if(opensLoopScope && (k==="variable" || k==="variables")) continue;
    if(ctx.rename && node.type==="LocalStatement" && k==="variables") continue;
    if(ctx.rename && node.type==="FunctionDeclaration" && k==="identifier" && node.isLocal) continue;
    // v19: Skip Identifier nodes that are PROPERTY NAMES not variables.
    // Renaming these corrupts Roblox reflection (Players.LocalPlayer becomes
    // Players._0xhex which is not a valid Instance member).
    if(ctx.rename && node.type==="MemberExpression" && k==="identifier") continue;
    if(ctx.rename && node.type==="TableKeyString" && k==="key") continue;
    // Global function declaration like `function obj.method()` Ã¢â‚¬â€ the identifier
    // chain is a member expression; the outer method name is a property.
    if(ctx.rename && node.type==="FunctionDeclaration" && k==="identifier"
       && !node.isLocal && node.identifier
       && (node.identifier.type==="MemberExpression" || node.identifier.type==="IndexExpression")) continue;

    const c=node[k];
    if(Array.isArray(c))c.forEach(x=>walkAst(x,ctx));
    else if(c&&typeof c==="object")walkAst(c,ctx);
  }

  if(ctx.rename&&node.type==="Identifier"&&node.name){
    node.name = ctx.rename.lookup(node.name);
  }

  if(opensNewScope) ctx.rename.popScope();
  if(opensLoopScope) ctx.rename.popScope();
}

function serializeBlock(stmts){
  return stmts.map(serialize).filter(s=>s.length>0).join(";");
}

// v9.1: Add ::__continue__:: label at end of loop bodies so 'goto __continue__' works
function addContinueLabels(luaCode) {
  // v9.5: no-op - - - - - - - - - - - - - continue labels are now injected in luauToLua's injectContinueLabels
  return luaCode;
}

function serializeBinary(node){
  const op=node.operator;
  const left=serialize(node.left);
  const right=serialize(node.right);
  if(WORD_BINARY_OPS.has(op))return "("+left+" "+op+" "+right+")";
  return "("+left+op+right+")";
}

function serialize(node){
  if(!node)return "";
  if(node.__obf){
    if(node.__obf.type==="str")return "_D("+bytesToLuaTable(node.__obf.bytes)+")";
    if(node.__obf.type==="num")return node.__obf.expr;
  }
  switch(node.type){
    case "Chunk":return serializeBlock(node.body);
    case "LocalStatement":{const v=node.variables.map(x=>x.name).join(",");const i=node.init.map(serialize).join(",");return "local "+v+(i?"="+i:"");}
    case "AssignmentStatement":return node.variables.map(serialize).join(",")+"="+node.init.map(serialize).join(",");
    case "CallStatement":return serialize(node.expression);
    case "CallExpression":return serialize(node.base)+"("+node.arguments.map(serialize).join(",")+")";
    case "StringCallExpression":return serialize(node.base)+"("+serialize(node.argument)+")";
    case "TableCallExpression":return serialize(node.base)+"("+serialize(node.arguments)+")";
    case "Identifier":return node.name;
    case "StringLiteral":return JSON.stringify(typeof node.value==="string"?node.value:(node.raw?node.raw.slice(1,-1):""));
    case "NumericLiteral":return String(node.value);
    case "BooleanLiteral":return node.value?"true":"false";
    case "NilLiteral":return "nil";
    case "VarargLiteral":return "...";
    case "MemberExpression":return serialize(node.base)+node.indexer+node.identifier.name;
    case "IndexExpression":return serialize(node.base)+"["+serialize(node.index)+"]";
    case "BinaryExpression":
    case "LogicalExpression":return serializeBinary(node);
    case "UnaryExpression":return "("+node.operator+" "+serialize(node.argument)+")";
    case "FunctionDeclaration":{
      const p=node.parameters.map(x=>x.type==="VarargLiteral"?"...":x.name).join(",");
      const b=serializeBlock(node.body);
      const id=node.identifier?serialize(node.identifier):"";
      const lp=node.isLocal?"local ":"";
      return id?lp+"function "+id+"("+p+") "+b+" end":"function("+p+") "+b+" end";
    }
    case "IfStatement":{
      let o="";
      node.clauses.forEach(c=>{
        if(c.type==="IfClause")o+="if "+serialize(c.condition)+" then "+serializeBlock(c.body)+" ";
        else if(c.type==="ElseifClause")o+="elseif "+serialize(c.condition)+" then "+serializeBlock(c.body)+" ";
        else if(c.type==="ElseClause")o+="else "+serializeBlock(c.body)+" ";
      });
      return o+"end";
    }
    case "WhileStatement":return "while "+serialize(node.condition)+" do "+serializeBlock(node.body)+" end";
    case "RepeatStatement":return "repeat "+serializeBlock(node.body)+" until "+serialize(node.condition);
    case "ForNumericStatement":{const s=node.step?","+serialize(node.step):"";return "for "+node.variable.name+"="+serialize(node.start)+","+serialize(node.end)+s+" do "+serializeBlock(node.body)+" end";}
    case "ForGenericStatement":return "for "+node.variables.map(x=>x.name).join(",")+" in "+node.iterators.map(serialize).join(",")+" do "+serializeBlock(node.body)+" end";
    case "DoStatement":return "do "+serializeBlock(node.body)+" end";
    case "ReturnStatement":return "return "+node.arguments.map(serialize).join(",");
    case "BreakStatement":return "break";
    case "TableConstructorExpression":{const f=node.fields.map(x=>{if(x.type==="TableKey")return "["+serialize(x.key)+"]="+serialize(x.value);if(x.type==="TableKeyString")return x.key.name+"="+serialize(x.value);return serialize(x.value);});return "{"+f.join(",")+"}";}
    default:return "";
  }
}

function tryVmWrap(ast, level, extraSafeGlobals){
  if(!ast || !ast.body || ast.body.length === 0) return null;
  // v14.0: Randomized opcode table with junk entries for anti-analysis
  const { table: OP, junkNames: junkOpNames } = makeRandomizedOpTable();
  const bc = [];
  const consts = [];
  const globals = [];
  const passthrough = [];
  let compiledCount = 0;

  // v10.5: Only compile calls that reference KNOWN globals (Roblox stdlib + executor).
  // The VM harness executes BEFORE user's top-level declarations run, so any
  // user-declared symbol - - even top-level 'local function foo' - - is nil at VM time.
  // Whitelist approach: reject any reference to symbols not in this safe set.
  const topLocals = new Set();  // kept for compatibility, unused for VM decisions
  for(const stmt of ast.body){
    if(stmt.type === "LocalStatement" && stmt.variables){
      for(const v of stmt.variables){
        if(v && v.name) topLocals.add(v.name);
      }
    } else if(stmt.type === "FunctionDeclaration" && stmt.identifier
              && stmt.identifier.type === "Identifier" && stmt.isLocal){
      topLocals.add(stmt.identifier.name);
    } else if(stmt.type === "FunctionDeclaration" && stmt.identifier
              && stmt.identifier.type === "Identifier"){
      // global function declaration - - treat as available
      topLocals.add(stmt.identifier.name);
    } else if(stmt.type === "AssignmentStatement" && stmt.variables){
      // assignments like foo = ... make foo available as global
      for(const v of stmt.variables){
        if(v && v.type === "Identifier") topLocals.add(v.name);
      }
    }
  }
  // Add ROBLOX_GLOBALS to the set - - these are always safe as env[name]
  for(const g of ROBLOX_GLOBALS) topLocals.add(g);
  // Also common Luau/Roblox names likely to be globals via getgenv or the executor
  const EXECUTOR_GLOBALS = ["hookfunction","hookmetamethod","getgenv","getrenv","getsenv","getreg",
    "getconnections","getgc","getinstances","getnilinstances","getscripts","getloadedmodules",
    "getcallingscript","getrawmetatable","setrawmetatable","checkcaller","isreadonly","setreadonly",
    "iscclosure","islclosure","newcclosure","identifyexecutor","lz4compress","lz4decompress",
    "queue_on_teleport","syn","fluxus","krnl","delta","request","http_request","http",
    "cloneref","gethui","getnamecallmethod","setnamecallmethod","isexecutorclosure",
    "getgenv","LPH_NO_VIRTUALIZE","LPH_JIT","LPH_ENCSTR"];
  for(const g of EXECUTOR_GLOBALS) topLocals.add(g);

  // v10.3: Walk expression to find any Identifier not in topLocals
  function _refsUnknown(node){
    if(!node || typeof node !== "object") return false;
    if(Array.isArray(node)){
      for(const x of node) if(_refsUnknown(x)) return true;
      return false;
    }
    if(node.type === "Identifier"){
      return !topLocals.has(node.name);
    }
    // Don't descend into function bodies - - locals inside are their own scope
    if(node.type === "FunctionDeclaration" || node.type === "FunctionExpression") return false;
    for(const k of Object.keys(node)){
      if(k === "type" || k === "loc" || k === "range") continue;
      if(_refsUnknown(node[k])) return true;
    }
    return false;
  }
  const MAX_VM_STATEMENTS = 500; // v9.0: raised from 200

  // v9.0: Prioritize sensitive statements - - - - - - - - - - - - - calls to HttpGet, loadstring, GetService, etc.
  const SENSITIVE_KEYWORDS = new Set([
    "HttpGet","HttpPost","loadstring","load","GetService","FindFirstChild",
    "WaitForChild","HttpGetAsync","PostAsync","RequestAsync","identifyexecutor",
    "getgenv","getrenv","hookfunction","hookmetamethod"
  ]);
  function stmtSensitivity(stmt){
    const s = JSON.stringify(stmt);
    let score = 0;
    for(const kw of SENSITIVE_KEYWORDS){
      if(s.indexOf('"' + kw + '"') >= 0) score += 10;
    }
    return score;
  }
  // v10.4: Disabled sensitivity reordering - - it hoists calls BEFORE their
  // 'local function' declarations, causing 'attempt to call a nil value'.
  // Preserving original order keeps declaration-before-use semantics intact.
  //
  // Additionally: track locals declared as we walk, so a later call to a
  // function declared earlier in the same top-level scope compiles safely,
  // but a call to a function declared LATER falls through to passthrough.
  const declaredSoFar = new Set(topLocals);
  // Remove things that appear AFTER their first usage - - start empty of body-declared items
  // and re-add as we encounter them in order
  const bodyLocalNames = new Set();
  for(const stmt of ast.body){
    if(stmt.type === "LocalStatement" && stmt.variables){
      for(const v of stmt.variables) if(v && v.name) bodyLocalNames.add(v.name);
    } else if(stmt.type === "FunctionDeclaration" && stmt.identifier
              && stmt.identifier.type === "Identifier"){
      bodyLocalNames.add(stmt.identifier.name);
    } else if(stmt.type === "AssignmentStatement" && stmt.variables){
      for(const v of stmt.variables) if(v && v.type === "Identifier") bodyLocalNames.add(v.name);
    }
  }
  // Remove body-declared names from declaredSoFar - - they only become available
  // as we walk past their declaration
  for(const n of bodyLocalNames) declaredSoFar.delete(n);
  // Keep ROBLOX_GLOBALS + executor globals always available
  for(const g of ROBLOX_GLOBALS) declaredSoFar.add(g);
  const EXECUTOR_GLOBALS2 = ["hookfunction","hookmetamethod","getgenv","getrenv","getsenv","getreg",
    "getconnections","getgc","getinstances","getnilinstances","getscripts","getloadedmodules",
    "getcallingscript","getrawmetatable","setrawmetatable","checkcaller","isreadonly","setreadonly",
    "iscclosure","islclosure","newcclosure","identifyexecutor","lz4compress","lz4decompress",
    "queue_on_teleport","syn","fluxus","krnl","delta","request","http_request","http",
    "cloneref","gethui","getnamecallmethod","setnamecallmethod","isexecutorclosure"];
  for(const g of EXECUTOR_GLOBALS2) declaredSoFar.add(g);

  // v10.5: Build strict whitelist - - only Roblox + executor globals are VM-safe
  const SAFE_GLOBALS = new Set();
  for(const g of ROBLOX_GLOBALS) SAFE_GLOBALS.add(g);
  const EXTRA_SAFE = ["hookfunction","hookmetamethod","getgenv","getrenv","getsenv","getreg",
    "getconnections","getgc","getinstances","getnilinstances","getscripts","getloadedmodules",
    "getcallingscript","getrawmetatable","setrawmetatable","checkcaller","isreadonly","setreadonly",
    "iscclosure","islclosure","newcclosure","identifyexecutor","lz4compress","lz4decompress",
    "queue_on_teleport","syn","fluxus","krnl","delta","request","http_request","http",
    "cloneref","gethui","getnamecallmethod","setnamecallmethod","isexecutorclosure"];
  for(const g of EXTRA_SAFE) SAFE_GLOBALS.add(g);
  // v11.3: fold in the auto-detected externals from pre-analysis
  if(extraSafeGlobals && extraSafeGlobals.forEach){
    extraSafeGlobals.forEach(g => SAFE_GLOBALS.add(g));
  }

  function _refsUndeclared(node){
    if(!node || typeof node !== "object") return false;
    if(Array.isArray(node)){
      for(const x of node) if(_refsUndeclared(x)) return true;
      return false;
    }
    if(node.type === "Identifier"){
      // v10.5: Only Roblox/executor globals are safe - - everything else is user-declared
      // and lives in the encrypted payload that runs AFTER the VM harness.
      return !SAFE_GLOBALS.has(node.name);
    }
    if(node.type === "FunctionDeclaration" || node.type === "FunctionExpression") return false;
    for(const k of Object.keys(node)){
      if(k === "type" || k === "loc" || k === "range") continue;
      if(_refsUndeclared(node[k])) return true;
    }
    return false;
  }

  for(const stmt of ast.body){
    // Check compile-ability BEFORE updating declaredSoFar with this statement's outputs
    // (a statement's own RHS cannot reference its own LHS-being-declared)
    const canCompile = compiledCount < MAX_VM_STATEMENTS
                    && vmCanCompile(stmt)
                    && !_refsUndeclared(stmt);
    if(canCompile){
      vmCompileStmt(stmt, bc, consts, globals, OP);
      compiledCount++;
    } else {
      passthrough.push(stmt);
    }
    // NOW update declaredSoFar so subsequent statements can reference this decl
    if(stmt.type === "LocalStatement" && stmt.variables){
      for(const v of stmt.variables) if(v && v.name) declaredSoFar.add(v.name);
    } else if(stmt.type === "FunctionDeclaration" && stmt.identifier
              && stmt.identifier.type === "Identifier"){
      declaredSoFar.add(stmt.identifier.name);
    } else if(stmt.type === "AssignmentStatement" && stmt.variables){
      for(const v of stmt.variables) if(v && v.type === "Identifier") declaredSoFar.add(v.name);
    }
  }
  if(compiledCount === 0) return null;
  bc.push(OP.HALT);
  const vmFn = randHexName(6);
  const bcVar = randHexName(5);
  const ksVar = randHexName(5);
  const gsVar = randHexName(5);
  const unpackFn = randHexName(6);
  const interp = generateVMInterpreter(vmFn, OP, junkOpNames);
  // v15.0 (3C): Multi-layer VM. Wrap the inner bc[] with an outer meta-VM
  // that reconstructs bc[] at runtime from an encrypted bytestream.
  // The old single-layer path (base64 + unpack) is still available but
  // superseded by the multi-layer path when compiledCount >= 3
  // (small programs skip outer VM to avoid overhead-for-nothing).
  const useMultiLayer = bc.length >= 9;  // ~3 statements minimum (3 ops each avg)
  let vmHarness;
  if(useMultiLayer){
    const outerProg = buildOuterVmProgram(bc);
    const { outerSource } = generateOuterVmSource(outerProg, vmFn, ksVar, gsVar);
    vmHarness = [
      interp,  // inner VM interpreter
      "local "+ksVar+"="+serializeConsts(consts),
      "local "+gsVar+"="+serializeGlobals(globals),
      outerSource  // outer VM decodes bc[] and calls inner VM automatically
    ].join("; ");
  } else {
    // Fallback: single-layer for very small programs (overhead not worth it)
    const unpacker = makeBytecodeUnpacker(unpackFn);
    const packedBc = packBytecode(bc);
    vmHarness = [
      unpacker,
      interp,
      "local "+bcVar+"="+unpackFn+"(\""+packedBc+"\")",
      "local "+ksVar+"="+serializeConsts(consts),
      "local "+gsVar+"="+serializeGlobals(globals),
      vmFn+"("+bcVar+","+ksVar+","+gsVar+",getfenv and getfenv() or _ENV)"
    ].join("; ");
  }
  return { vmHarness, passthrough, compiledCount };
}

function byteLevelTripleObfuscate(code,level,userId){
  const minified=aggressiveMinify(code);
  // v9.0: shared junk table for DCE resistance
  const sharedJunkVar = "_" + randHexName(4);
  const junkTablePreamble = "local " + sharedJunkVar + "={}";
  const watermark = generateUserWatermark(userId);
  // v9.8: antiDump disabled - - - - - - - - - - - - - iterating getgc() on scripts with 1000+ functions crashes some executors
  const antiDump = "";
  const k1=randInt(40,240);
  const k2=randInt(40,240);
  const k3=randInt(40,240);
  const encBytes=tripleXorEncrypt(minified,k1,k2,k3);
  const encPayload=bytesToBase64(encBytes);
  const realDec=randHexName(6);
  const decoder=makeTripleXorDecoder(realDec,k1,k2,k3);
  const fakeDecs=makeFakeDecoders(randInt(3,5));
  const strVar=randHexName(7);
  const execVar=randHexName(6);
  const errVar=randHexName(5);
  const junk1=generateJunkOps(randInt(10,20), sharedJunkVar);
  const junk2=generateJunkOps(randInt(5,15), sharedJunkVar);

  // Random 3-letter tag per obfuscation - - - - - - - - - - - - - no brand leak
  const _tagA = String.fromCharCode(65+randInt(0,25));
  const _tagB = String.fromCharCode(65+randInt(0,25));
  const _tagC = String.fromCharCode(65+randInt(0,25));
  const _tag = _tagA+_tagB+_tagC;
  const getLoaderFn = randHexName(5);
  const runFn = randHexName(5);
  const execCore=
    "local function "+getLoaderFn+"() "+
      "local ok,fn=pcall(function() "+
        // Try executor globals FIRST (they exist in Delta/Synapse/KRNL/Fluxus)
        "local env=(getgenv and getgenv()) or _G or {} "+
        "if type(env.loadstring)=='function' then return env.loadstring end "+
        "if type(env.load)=='function' then return env.load end "+
        // Try direct executor tables
        "if syn and type(syn.load)=='function' then return syn.load end "+
        "if fluxus and type(fluxus.load)=='function' then return fluxus.load end "+
        "if krnl and type(krnl.load)=='function' then return krnl.load end "+
        "if delta and type(delta.load)=='function' then return delta.load end "+
        // Standard Lua globals (nil in vanilla Roblox LocalScript)
        "if type(loadstring)=='function' then return loadstring end "+
        "if type(load)=='function' then return load end "+
        "return nil "+
      "end) "+
      "if ok and type(fn)=='function' then return fn end "+
      "return nil "+
    "end "+
    "local function "+runFn+"() "+
      "local _L="+getLoaderFn+"() "+
      "if type(_L)~='function' then "+
        // Silent fail - - no error message, no crash
        "return "+
      "end "+
      "local src="+realDec+"("+strVar+") "+
      "if type(src)~='string' then return end "+
      "local ok,compiled=pcall(_L,src) "+
      "if not ok or type(compiled)~='function' then return end "+
      "pcall(compiled) "+
    "end "+
    runFn+"()"

  const parts=[];
  parts.push(junkTablePreamble);  // v9.0: shared junk table
  if(level==="maximum")parts.push(generateAntiTamper());
  if(antiDump) parts.push(antiDump);
  parts.push(watermark);
  parts.push(junk1);
  parts.push(fakeDecs);
  parts.push(decoder);
  parts.push("local "+strVar+"=\""+encPayload+"\"");
  parts.push(generateOpaquePredicate(execCore));
  parts.push(junk2);
  return parts.join("; ");
}


// ============================================================================
// v11.0 PRE-ANALYSIS MODULE
// ============================================================================

function preAnalyze(rawCode) {
  const report = { ok: false, stage: "start", errors: [], warnings: [], stats: {} };

  let code;
  try {
    code = preprocess(rawCode);
    report.stats.afterPreprocess = { chars: code.length, lines: code.split("\n").length };
  } catch (e) {
    report.stage = "preprocess";
    report.errors.push("preprocess failed: " + e.message);
    return report;
  }

  let converted;
  try {
    converted = luauToLua(code);
    report.stats.afterLuau = { chars: converted.length, lines: converted.split("\n").length };
  } catch (e) {
    report.stage = "luauToLua";
    report.errors.push("Luau conversion failed: " + e.message);
    return report;
  }

  let ast = null;
  let parseErr53 = null, parseErr51 = null;
  try {
    ast = luaparse.parse(converted, { luaVersion: "5.3", comments: false });
  } catch (e) {
    parseErr53 = { message: e.message, line: e.line, column: e.column };
  }
  if (!ast) {
    try {
      ast = luaparse.parse(converted, { luaVersion: "5.1", comments: false });
    } catch (e) {
      parseErr51 = { message: e.message, line: e.line, column: e.column };
    }
  }

  if (!ast) {
    report.stage = "parse";
    report.parseError = parseErr53 || parseErr51;
    const err = parseErr53 || parseErr51;
    if (err && err.line) {
      const lines = converted.split("\n");
      const errLine = err.line;
      const from = Math.max(0, errLine - 3);
      const to = Math.min(lines.length, errLine + 2);
      const ctxLines = [];
      for (let i = from; i < to; i++) {
        const marker = (i + 1 === errLine) ? " >>> " : "     ";
        ctxLines.push("  " + (i + 1) + marker + lines[i].substring(0, 200));
      }
      report.errors.push(
        "Parse failed at line " + errLine + ", col " + (err.column || "?") + ": " + err.message +
        "\n" + ctxLines.join("\n")
      );
    } else {
      report.errors.push("Parse failed: " + JSON.stringify(err));
    }
    return report;
  }

  const symbols = buildSymbolTable(ast);
  const externsInfo = collectExternalIdentifiers(ast);
  report.stats.declarations = symbols.declarations.length;
  report.stats.forwardRefs = symbols.forwardRefs.length;
  report.stats.tableFieldAssigns = symbols.tableFieldAssigns.length;
  report.stats.methodCalls = symbols.methodCallCount;
  report.stats.externalIdentifiers = externsInfo.externals.size;
  report.externals = externsInfo.externals;

  if (symbols.forwardRefs.length > 0) {
    report.warnings.push(
      "Found " + symbols.forwardRefs.length + " forward function reference(s) -ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â " +
      "these will pass through the VM (safe)."
    );
    const preview = symbols.forwardRefs.slice(0, 5).map(f =>
      f.name + " (used L" + f.usedAt + ", declared L" + f.declaredAt + ")"
    ).join(", ");
    report.warnings.push("  Examples: " + preview);
  }

  report.ok = true;
  report.stage = "done";
  report.ast = ast;
  report.convertedCode = converted;
  report.symbolTable = symbols;
  return report;
}

function buildSymbolTable(ast) {
  const declarations = [];
  const references = [];
  const tableFieldAssigns = [];
  const declLine = new Map();
  let methodCallCount = 0;

  function recordDecl(name, kind, line) {
    if (!declLine.has(name)) declLine.set(name, line);
    declarations.push({ name, kind, line });
  }

  function memberChain(node) {
    if (!node) return "?";
    if (node.type === "Identifier") return node.name;
    if (node.type === "MemberExpression") {
      return memberChain(node.base) + node.indexer + (node.identifier ? node.identifier.name : "?");
    }
    if (node.type === "IndexExpression") return memberChain(node.base) + "[?]";
    return "?";
  }

  function walk(node, depth) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(n => walk(n, depth)); return; }
    const line = (node.loc && node.loc.start && node.loc.start.line) || 0;

    if (depth === 0 && node.type === "LocalStatement" && node.variables) {
      for (const v of node.variables) if (v.name) recordDecl(v.name, "local", line);
    }
    if (depth === 0 && node.type === "FunctionDeclaration" && node.identifier) {
      if (node.identifier.type === "Identifier") {
        recordDecl(node.identifier.name, node.isLocal ? "local_fn" : "global_fn", line);
      } else {
        tableFieldAssigns.push({ chain: memberChain(node.identifier), line });
      }
    }
    if (depth === 0 && node.type === "AssignmentStatement" && node.variables) {
      for (const v of node.variables) {
        if (v.type === "Identifier") recordDecl(v.name, "global", line);
        else tableFieldAssigns.push({ chain: memberChain(v), line });
      }
    }
    if (node.type === "Identifier" && node.name) references.push({ name: node.name, line });
    if (node.type === "CallExpression" && node.base &&
        node.base.type === "MemberExpression" && node.base.indexer === ":") {
      methodCallCount++;
    }

    const isChunk = (node.type === "Chunk");
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      walk(node[k], isChunk ? 0 : depth + 1);
    }
  }
  walk(ast, -1);

  const forwardRefs = [];
  const seen = new Set();
  for (const ref of references) {
    if (seen.has(ref.name)) continue;
    const dl = declLine.get(ref.name);
    if (dl && dl > ref.line && ref.line > 0) {
      forwardRefs.push({ name: ref.name, usedAt: ref.line, declaredAt: dl });
      seen.add(ref.name);
    }
  }

  return { declarations, declLine, forwardRefs, tableFieldAssigns, methodCallCount };
}

// v11.3: Walk the AST and collect EVERY Identifier that's referenced but never
// declared in ANY scope. These are the script's external dependencies - must
// be added to the safe-rename whitelist so obfuscation doesn't nil them out.
function collectExternalIdentifiers(ast) {
  // All names declared anywhere (any scope, any depth)
  const allDeclared = new Set();
  // All names referenced (used) anywhere
  const allReferenced = new Set();

  function collectDeclsIn(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(collectDeclsIn); return; }

    // Local declarations
    if (node.type === "LocalStatement" && node.variables) {
      for (const v of node.variables) if (v && v.name) allDeclared.add(v.name);
    }
    // Function parameters
    if ((node.type === "FunctionDeclaration" || node.type === "FunctionExpression") && node.parameters) {
      for (const p of node.parameters) if (p && p.name) allDeclared.add(p.name);
      // Also treat implicit 'self' as declared in method definitions
      if (node.identifier && node.identifier.type === "MemberExpression" && node.identifier.indexer === ":") {
        allDeclared.add("self");
      }
    }
    // Function names (local function foo, function tbl.foo)
    if (node.type === "FunctionDeclaration" && node.identifier) {
      if (node.identifier.type === "Identifier") {
        allDeclared.add(node.identifier.name);
      }
    }
    // for i = 1, n do  -> declares i
    if (node.type === "ForNumericStatement" && node.variable) {
      if (node.variable.name) allDeclared.add(node.variable.name);
    }
    // for k, v in pairs(t) do -> declares k, v
    if (node.type === "ForGenericStatement" && node.variables) {
      for (const v of node.variables) if (v && v.name) allDeclared.add(v.name);
    }
    // Global assignments that create new globals: foo = ...
    if (node.type === "AssignmentStatement" && node.variables) {
      for (const v of node.variables) {
        if (v && v.type === "Identifier") allDeclared.add(v.name);
      }
    }

    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      collectDeclsIn(node[k]);
    }
  }

  function collectRefsIn(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(collectRefsIn); return; }

    // Any bare Identifier is a reference - but skip MemberExpression's .identifier
    // (that's a field name, not a variable reference)
    if (node.type === "Identifier" && node.name) {
      allReferenced.add(node.name);
    }

    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      // Skip the .identifier of MemberExpression - it's a field access, not a variable
      if (node.type === "MemberExpression" && k === "identifier") continue;
      collectRefsIn(node[k]);
    }
  }

  collectDeclsIn(ast);
  collectRefsIn(ast);

  // External = referenced but not declared anywhere
  const externals = new Set();
  for (const name of allReferenced) {
    if (!allDeclared.has(name)) externals.add(name);
  }
  return { externals, allDeclared, allReferenced };
}




// ============================================================================
// v13.0 INTELLIGENT ADAPTIVE OBFUSCATOR
// Analyzes the source code and adapts obfuscation strategy per code section.
// Every transform is validated by re-parsing. If any transform breaks parseability,
// the section falls back to passthrough automatically.
// ============================================================================

// - Feature 1: Script Profiler -
// Deep-scan the AST to build a full profile of the script
function profileScript(ast, rawCode) {
  const profile = {
    // Size metrics
    sourceChars: rawCode.length,
    sourceLines: rawCode.split("\n").length,
    // AST metrics
    topLevelStatements: (ast.body || []).length,
    functionCount: 0,
    localFunctionCount: 0,
    methodCallCount: 0,
    pcallCount: 0,
    tableConstructorCount: 0,
    stringLiteralCount: 0,
    numericLiteralCount: 0,
    // Depth
    maxBlockDepth: 0,
    maxClosureDepth: 0,
    // Framework detection
    frameworks: new Set(),
    // Risk hotspots
    hotspots: [],
    // Sensitivity markers
    hasHookfunction: false,
    hasHookmetamethod: false,
    hasGetgenv: false,
    hasGetrenv: false,
    hasSetmetatable: false,
    hasHttpGet: false,
    hasLoadstring: false,
  };

  function walk(node, blockDepth, closureDepth) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(n => walk(n, blockDepth, closureDepth)); return; }

    const t = node.type;

    // Count node types
    if (t === "FunctionDeclaration" || t === "FunctionExpression") {
      profile.functionCount++;
      if (node.isLocal) profile.localFunctionCount++;
      closureDepth++;
      if (closureDepth > profile.maxClosureDepth) profile.maxClosureDepth = closureDepth;
    }
    if (t === "TableConstructorExpression") profile.tableConstructorCount++;
    if (t === "StringLiteral") profile.stringLiteralCount++;
    if (t === "NumericLiteral") profile.numericLiteralCount++;

    // Method calls (obj:method())
    if (t === "CallExpression" && node.base && node.base.type === "MemberExpression" && node.base.indexer === ":") {
      profile.methodCallCount++;
    }
    // Function calls to sensitive functions
    if (t === "CallExpression" && node.base) {
      const calleeName = _getCalleeName(node.base);
      if (calleeName === "pcall" || calleeName === "xpcall") profile.pcallCount++;
      if (calleeName === "hookfunction") profile.hasHookfunction = true;
      if (calleeName === "hookmetamethod") profile.hasHookmetamethod = true;
      if (calleeName === "getgenv") profile.hasGetgenv = true;
      if (calleeName === "getrenv") profile.hasGetrenv = true;
      if (calleeName === "setmetatable") profile.hasSetmetatable = true;
      if (calleeName === "loadstring" || calleeName === "load") profile.hasLoadstring = true;
      // HttpGet / HttpGetAsync as method
      if (node.base.type === "MemberExpression" && node.base.identifier) {
        const m = node.base.identifier.name;
        if (m === "HttpGet" || m === "HttpGetAsync" || m === "HttpPost") profile.hasHttpGet = true;
      }
    }

    // Block-nesting increment
    const opensBlock = new Set([
      "DoStatement","WhileStatement","RepeatStatement","ForNumericStatement",
      "ForGenericStatement","IfClause","ElseifClause","ElseClause",
    ]);
    const nextBlockDepth = opensBlock.has(t) ? blockDepth + 1 : blockDepth;
    if (nextBlockDepth > profile.maxBlockDepth) {
      profile.maxBlockDepth = nextBlockDepth;
    }

    // Hotspot: deeply-nested block
    if (nextBlockDepth >= 20 && opensBlock.has(t)) {
      const line = (node.loc && node.loc.start && node.loc.start.line) || 0;
      profile.hotspots.push({ kind: "deep_nest", depth: nextBlockDepth, line });
    }

    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type" || k === "__obf") continue;
      walk(node[k], nextBlockDepth, closureDepth);
    }
  }

  walk(ast, 0, 0);

  // Framework detection heuristics (name-based)
  const nameHits = [];
  function scanNames(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(scanNames); return; }
    if (node.type === "Identifier" && node.name) nameHits.push(node.name);
    if (node.type === "StringLiteral" && node.value) nameHits.push(node.value);
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      scanNames(node[k]);
    }
  }
  scanNames(ast);
  const allNames = nameHits.join(" ").toLowerCase();
  if (allNames.includes("orion") || allNames.includes("orionlib")) profile.frameworks.add("Orion");
  if (allNames.includes("rayfield")) profile.frameworks.add("Rayfield");
  if (allNames.includes("kavo")) profile.frameworks.add("Kavo");
  if (allNames.includes("linoria")) profile.frameworks.add("Linoria");
  if (allNames.includes("fluent")) profile.frameworks.add("Fluent");
  if (allNames.includes("mercury")) profile.frameworks.add("Mercury");
  if (allNames.includes("autoparry") || allNames.includes("_parry_patch")) profile.frameworks.add("AutoParry");
  if (allNames.includes("bladeball")) profile.frameworks.add("BladeBall");

  // Compute complexity score (higher = riskier)
  profile.complexityScore = Math.round(
    (profile.sourceChars / 1000) * 0.5 +
    profile.maxBlockDepth * 3 +
    profile.functionCount * 0.5 +
    profile.pcallCount * 0.3 +
    (profile.hasHookfunction ? 20 : 0) +
    (profile.hasSetmetatable ? 10 : 0)
  );

  // Determine risk tier
  if (profile.maxBlockDepth >= 100 || profile.complexityScore >= 500) profile.riskTier = "extreme";
  else if (profile.maxBlockDepth >= 50 || profile.complexityScore >= 200) profile.riskTier = "high";
  else if (profile.maxBlockDepth >= 25 || profile.complexityScore >= 80) profile.riskTier = "medium";
  else profile.riskTier = "low";

  // v17: Detect runtime reflection to skip anti-debug (was silent-exiting them).
  const reflectionRe = /\b(getgc|debug\.info|debug\.getupvalues|debug\.getupvalue|debug\.getconstants|debug\.getproto|debug\.getprotos|debug\.getlocals|debug\.getlocal|debug\.setupvalue|debug\.setconstant|getreg|getrenv|getgenv|getsenv|getconnections)\s*\(/;
  profile.hasRuntimeReflection = reflectionRe.test(rawCode);

  return profile;
}

function _getCalleeName(base) {
  if (!base) return null;
  if (base.type === "Identifier") return base.name;
  if (base.type === "MemberExpression" && base.identifier) return base.identifier.name;
  return null;
}

// - Feature 2: Section Splitter -
// Splits top-level statements into logical sections and assigns per-section strategy
function splitSections(ast, profile) {
  const sections = [];
  const stmts = ast.body || [];
  let currentSection = null;

  function classifyStmt(stmt) {
    // Detect sensitive statements
    let hasHook = false, hasMetatable = false, hasHookInit = false, deepNest = 0;

    function scan(n, depth) {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) { n.forEach(x => scan(x, depth)); return; }
      const opens = new Set([
        "DoStatement","WhileStatement","RepeatStatement","ForNumericStatement",
        "ForGenericStatement","IfClause","ElseifClause","ElseClause",
      ]);
      const nd = opens.has(n.type) ? depth + 1 : depth;
      if (nd > deepNest) deepNest = nd;
      if (n.type === "CallExpression" && n.base) {
        const nm = _getCalleeName(n.base);
        if (nm === "hookfunction" || nm === "hookmetamethod") hasHook = true;
        if (nm === "setmetatable") hasMetatable = true;
        if (nm === "getrenv" || nm === "getgenv") hasHookInit = true;
      }
      for (const k of Object.keys(n)) {
        if (k === "loc" || k === "range" || k === "type") continue;
        scan(n[k], nd);
      }
    }
    scan(stmt, 0);

    if (hasHook || hasHookInit) return "sensitive_init";
    if (hasMetatable) return "metatable_setup";
    if (deepNest >= 20) return "deep_logic";
    if (stmt.type === "LocalStatement") return "declaration";
    if (stmt.type === "FunctionDeclaration") return "function_def";
    if (stmt.type === "AssignmentStatement") return "assignment";
    return "generic";
  }

  function strategyFor(kind) {
    switch (kind) {
      case "sensitive_init": return "passthrough"; // don't touch hooks
      case "metatable_setup": return "passthrough"; // fragile
      case "deep_logic": return "minimal"; // rename only, no VM, no wrap
      case "function_def": return "full";
      case "declaration": return "medium";
      case "assignment": return "medium";
      default: return "medium";
    }
  }

  for (const stmt of stmts) {
    const kind = classifyStmt(stmt);
    if (!currentSection || currentSection.kind !== kind) {
      currentSection = { kind, strategy: strategyFor(kind), statements: [] };
      sections.push(currentSection);
    }
    currentSection.statements.push(stmt);
  }

  return sections;
}

// - Feature 3: AST-level nesting reducer (from v12, extended) -
function flattenAst(node, ctx) {
  if (!node || typeof node !== "object") return node;
  if (Array.isArray(node)) {
    return node.map(n => flattenAst(n, ctx)).filter(n => n !== null);
  }

  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "range" || k === "__obf") continue;
    const child = node[k];
    if (Array.isArray(child)) {
      node[k] = child.map(c => flattenAst(c, ctx)).filter(c => c !== null);
    } else if (child && typeof child === "object") {
      node[k] = flattenAst(child, ctx);
    }
  }

  // Transform 1: Standalone do-block with no locals - - inline
  if (node.type === "DoStatement" && node.body) {
    const hasLocals = node.body.some(s =>
      s.type === "LocalStatement" || s.type === "LocalFunctionStatement" ||
      (s.type === "FunctionDeclaration" && s.isLocal)
    );
    if (!hasLocals) {
      return { type: "__INLINE__", statements: node.body };
    }
  }

  // Transform 2: Chained single-branch if - - combined "and" condition
  if (node.type === "IfStatement" && node.clauses && node.clauses.length === 1) {
    const clause = node.clauses[0];
    if (clause.type === "IfClause" && clause.body && clause.body.length === 1) {
      const inner = clause.body[0];
      if (inner.type === "IfStatement" && inner.clauses && inner.clauses.length === 1) {
        const innerClause = inner.clauses[0];
        if (innerClause.type === "IfClause") {
          clause.condition = {
            type: "LogicalExpression",
            operator: "and",
            left: clause.condition,
            right: innerClause.condition,
          };
          clause.body = innerClause.body;
          if (ctx) ctx.flattens = (ctx.flattens || 0) + 1;
        }
      }
    }
  }

  // Transform 3: Empty else branch - - drop
  if (node.type === "IfStatement" && node.clauses) {
    node.clauses = node.clauses.filter(c => {
      if (c.type === "ElseClause" && (!c.body || c.body.length === 0)) {
        if (ctx) ctx.emptyElsesRemoved = (ctx.emptyElsesRemoved || 0) + 1;
        return false;
      }
      return true;
    });
  }

  // Inline __INLINE__ markers
  for (const k of Object.keys(node)) {
    if (Array.isArray(node[k])) {
      const flat = [];
      for (const item of node[k]) {
        if (item && item.type === "__INLINE__") {
          flat.push(...item.statements);
          if (ctx) ctx.doBlocksInlined = (ctx.doBlocksInlined || 0) + 1;
        } else {
          flat.push(item);
        }
      }
      node[k] = flat;
    }
  }

  return node;
}

function reduceNesting(ast, maxPasses) {
  maxPasses = maxPasses || 8;
  const ctx = { flattens: 0, doBlocksInlined: 0, emptyElsesRemoved: 0 };
  for (let pass = 0; pass < maxPasses; pass++) {
    const before = ctx.flattens + ctx.doBlocksInlined + ctx.emptyElsesRemoved;
    flattenAst(ast, ctx);
    const after = ctx.flattens + ctx.doBlocksInlined + ctx.emptyElsesRemoved;
    if (after === before) break;
  }
  return ctx;
}

function measureAstDepth(node, depth) {
  depth = depth || 0;
  if (!node || typeof node !== "object") return depth;
  if (Array.isArray(node)) {
    return node.reduce((m, n) => Math.max(m, measureAstDepth(n, depth)), depth);
  }
  const opens = new Set([
    "DoStatement","WhileStatement","RepeatStatement","ForNumericStatement",
    "ForGenericStatement","FunctionDeclaration","FunctionExpression","IfClause",
    "ElseifClause","ElseClause",
  ]);
  const nextDepth = opens.has(node.type) ? depth + 1 : depth;
  let max = nextDepth;
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "range" || k === "__obf" || k === "type") continue;
    const c = node[k];
    if (c && typeof c === "object") {
      max = Math.max(max, measureAstDepth(c, nextDepth));
    }
  }
  return max;
}

// - Feature 6: Post-obfuscation validator -
// Re-parse the output. If invalid, return false. Callers can then retry with lighter strategy.
function validateGeneratedCode(code) {
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



// ============================================================================
// v14.0 ANTI-DEBUGGER + ANTI-TAMPER MODULE
// Runtime checks that detect deobfuscator tooling and refuse to execute.
// Auto-gated by v13 profiler: only enabled when profile.riskTier === "low"
// (safe to add runtime overhead). For high/extreme risk scripts, skipped.
// ============================================================================

// Generate a runtime integrity check.
// Computes a checksum of a fixed payload marker at runtime and compares
// to precomputed value. If they mismatch, the script exits silently.
function generateIntegrityCheck(payload) {
  // Compute a simple checksum of the payload marker at JS-time
  const marker = payload.substring(0, Math.min(200, payload.length));
  let checksum = 0;
  for (let i = 0; i < marker.length; i++) {
    checksum = ((checksum * 31) + marker.charCodeAt(i)) & 0x7fffffff;
  }
  const checkFn = randHexName(6);
  const chkVar = randHexName(4);
  const expectedVar = randHexName(4);
  // Runtime: recompute the same checksum. If any byte was patched, mismatch.
  return "local function " + checkFn + "() " +
    "local " + expectedVar + "=" + checksum + " " +
    "local " + chkVar + "=0 " +
    "local s=" + JSON.stringify(marker) + " " +
    "for i=1,#s do " + chkVar + "=(" + chkVar + "*31+string.byte(s,i))%2147483648 end " +
    "return " + chkVar + "==" + expectedVar + " " +
    "end " +
    "if not " + checkFn + "() then return end";
}

// Generate anti-debugger checks.
// Detects common analysis tooling:
// - getgc iteration (dumper tools scan the GC for functions)
// - hookfunction on our own decoder (deobfuscator tools intercept)
// - debug.sethook (single-step debugging)
// - excessive pcall depth (some tools wrap everything in extra pcalls)
function generateAntiDebugger(softMode) {
  // v14.0 (3B): softMode=true skips the hookfunction/coroutine.wrap probe.
  // Used when the target script legitimately calls hookfunction or
  // hookmetamethod so the check doesn't fire on the user's own hooks.
  // Suspicion counter: at least 2 checks must fire before exit. This
  // reduces false-positive rate when one probe misbehaves on a niche
  // executor while another succeeds.
  const fnName = randHexName(6);
  const scoreVar = randHexName(4);
  const threshold = 3;  // v17: raised - less trigger-happy

  let checks = "";
  // Check 1: debug.sethook active (single-step debugger)
  checks += "if debug and debug.gethook then " +
      "local ok,hook=pcall(debug.gethook) " +
      "if ok and hook then " + scoreVar + "=" + scoreVar + "+1 end " +
    "end ";
  // Check 2: getgc returns suspiciously large pool (scanner active)
  checks += "if type(getgc)=='function' then " +
      "local ok2,gc=pcall(getgc,false) " +
      "if ok2 and type(gc)=='table' and #gc>200000 then " +  // v17: raised from 50k
        scoreVar + "=" + scoreVar + "+1 " +
      "end " +
    "end ";
  // Check 3: hookfunction on coroutine.wrap (deobf tracer signature)
  // Skipped in soft mode.
  if (!softMode) {
    checks += "if type(hookfunction)=='function' and type(coroutine)=='table' then " +
        "local ok3,orig=pcall(function() return coroutine.wrap end) " +
        "if ok3 and orig then " +
          "local info=debug and debug.info and debug.info(orig,'s') " +
          "if info and type(info)=='string' and #info>0 then " +
            scoreVar + "=" + scoreVar + "+1 " +
          "end " +
        "end " +
      "end ";
  }
  // Extra check (always on): checkcaller variance across invocations.
  // Executors that instrument every call will see checkcaller return true
  // in unexpected contexts. Harmless probe otherwise.
  checks += "if type(checkcaller)=='function' then " +
      "local ok4,cc1=pcall(checkcaller) " +
      "if ok4 and cc1==false then " +
        // Legit executor context - no penalty
        scoreVar + "=" + scoreVar + "+0 " +
      "end " +
    "end ";

  return "local function " + fnName + "() " +
    "local " + scoreVar + "=0 " +
    checks +
    "return " + scoreVar + "<" + threshold + " " +
    "end " +
    "if not " + fnName + "() then return end";
}

// ============================================================================
// v14.0 VM OPCODE RANDOMIZATION HELPERS
// Extends the existing tryVmWrap by shuffling opcodes and injecting junk.
// ============================================================================

// Shuffle opcode numbers so each obfuscation run produces a different opcode set.
// (The existing makeOpTable already randomizes numbers 1-250, but v14 also adds
//  junk opcodes to inflate the dispatch table.)
function makeRandomizedOpTable() {
  const opNames = OP_NAMES.slice();
  // Add per-run junk opcodes with random names (never emitted by compiler,
  // but present in the interpreter dispatch table)
  const extraJunkCount = randInt(8, 15);
  for (let i = 0; i < extraJunkCount; i++) {
    opNames.push("JUNK_" + randHexName(4).substring(3));
  }
  // Shuffle values 1-250 and assign
  const nums = [];
  const seen = new Set();
  while (nums.length < opNames.length) {
    const n = randInt(1, 250);
    if (!seen.has(n)) { seen.add(n); nums.push(n); }
  }
  const table = {};
  opNames.forEach((name, i) => { table[name] = nums[i]; });
  return { table, junkNames: opNames.filter(n => n.startsWith("JUNK_")) };
}

// Generate junk opcode handlers for the interpreter (never actually dispatched
// but present in the code - inflates the interpreter and confuses static analysis)
function generateJunkOpHandlers(opTable, junkNames) {
  const handlers = [];
  for (const name of junkNames) {
    const opNum = opTable[name];
    const junkExpr = randChoice([
      "local _j=bit32.bxor(" + randInt(1,255) + "," + randInt(1,255) + ")",
      "local _j=math.floor(" + randInt(100,9999) + "/" + randInt(2,9) + ")",
      "local _j=string.byte('" + randChoice(["x","a","z","q","m","n"]) + "')",
      "local _j=#'" + randChoice(["abc","xyzq","mnop","test"]) + "'",
    ]);
    handlers.push("elseif op==" + opNum + " then " + junkExpr + " ");
  }
  return handlers.join("");
}



// ============================================================================
// v16.0 ADVANCED INTELLIGENCE MODULE
// Non-hardcoded pattern detection - works on ANY script, not just known frameworks.
// ============================================================================

// - Feature 1: Closure-Graph Analyzer -
// Builds a graph of which functions capture which upvalues, so we can detect
// shared mutable state that's used across many closures (fragile under rename).
function analyzeClosureGraph(ast) {
  const graph = {
    functions: [],           // { id, line, capturedUpvalues: [names], parentFn: id|null }
    sharedStateVars: [],     // vars declared once, captured by 3+ functions
    upvalueUsage: new Map(), // varName -> [functionIds that capture it]
  };

  let fnId = 0;
  const stack = []; // stack of { id, declaredHere: Set, capturedFromParent: Set }

  function findEnclosingDecl(name) {
    // Walk stack from innermost to find who declared this name
    for (let i = stack.length - 1; i >= 0; i--) {
      if (stack[i].declaredHere.has(name)) return i;
    }
    return -1; // global/undeclared
  }

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(walk); return; }

    const opensScope = node.type === "FunctionDeclaration" || node.type === "FunctionExpression";

    if (opensScope) {
      const currentId = fnId++;
      const line = (node.loc && node.loc.start && node.loc.start.line) || 0;
      const frame = {
        id: currentId,
        line,
        declaredHere: new Set(),
        capturedFromParent: new Set(),
        parentFn: stack.length > 0 ? stack[stack.length - 1].id : null,
      };

      // Add function params as declared in this scope
      if (Array.isArray(node.parameters)) {
        for (const p of node.parameters) {
          if (p && p.name) frame.declaredHere.add(p.name);
        }
      }

      stack.push(frame);

      // Walk function body
      for (const k of Object.keys(node)) {
        if (k === "loc" || k === "range" || k === "type" || k === "parameters") continue;
        walk(node[k]);
      }

      // Finalize this function's info
      graph.functions.push({
        id: currentId,
        line: line,
        capturedUpvalues: [...frame.capturedFromParent],
        parentFn: frame.parentFn,
      });

      // Track upvalue usage
      for (const name of frame.capturedFromParent) {
        if (!graph.upvalueUsage.has(name)) graph.upvalueUsage.set(name, []);
        graph.upvalueUsage.get(name).push(currentId);
      }

      stack.pop();
      return;
    }

    // Track declarations in current scope
    if (stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (node.type === "LocalStatement" && node.variables) {
        for (const v of node.variables) {
          if (v && v.name) frame.declaredHere.add(v.name);
        }
      }
      if (node.type === "ForNumericStatement" && node.variable && node.variable.name) {
        frame.declaredHere.add(node.variable.name);
      }
      if (node.type === "ForGenericStatement" && node.variables) {
        for (const v of node.variables) if (v && v.name) frame.declaredHere.add(v.name);
      }
    }

    // Track upvalue captures - any Identifier reference not declared in the current
    // function's local scope but declared in a parent = captured upvalue
    if (node.type === "Identifier" && node.name && stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (!frame.declaredHere.has(node.name)) {
        const declaredAt = findEnclosingDecl(node.name);
        if (declaredAt >= 0 && declaredAt < stack.length - 1) {
          frame.capturedFromParent.add(node.name);
        }
      }
    }

    // Recurse
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      // Skip .identifier of MemberExpression (field, not var reference)
      if (node.type === "MemberExpression" && k === "identifier") continue;
      walk(node[k]);
    }
  }

  walk(ast);

  // Identify shared state - vars captured by 3+ functions (heuristic for risky patterns)
  for (const [name, fns] of graph.upvalueUsage.entries()) {
    if (fns.length >= 3) {
      graph.sharedStateVars.push({ name, capturedBy: fns.length });
    }
  }
  graph.sharedStateVars.sort((a, b) => b.capturedBy - a.capturedBy);

  return graph;
}

// - Feature 2: UI Framework Auto-Detector -
// Detects Roblox UI patterns dynamically (no hardcoded framework names)
function detectUIPatterns(ast, rawCode) {
  const patterns = {
    instanceNewCount: 0,
    uiTypeCreations: {},     // { "Frame": 42, "TextLabel": 12, ... }
    connectionHandlers: 0,   // :Connect() calls
    tweenServiceUsage: 0,
    guiParenting: 0,         // .Parent = someGui
    inputHandlers: 0,        // InputBegan, InputEnded, MouseButton1Click
    hasCustomUI: false,      // heuristic: many Instance.new + connections
  };

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(walk); return; }

    if (node.type === "CallExpression" && node.base) {
      // Instance.new("Type")
      if (node.base.type === "MemberExpression"
          && node.base.base && node.base.base.name === "Instance"
          && node.base.identifier && node.base.identifier.name === "new") {
        patterns.instanceNewCount++;
        if (node.arguments && node.arguments[0]
            && node.arguments[0].type === "StringLiteral") {
          const uiType = node.arguments[0].value;
          patterns.uiTypeCreations[uiType] = (patterns.uiTypeCreations[uiType] || 0) + 1;
        }
      }
      // :Connect(...) method calls
      if (node.base.type === "MemberExpression" && node.base.indexer === ":"
          && node.base.identifier && node.base.identifier.name === "Connect") {
        patterns.connectionHandlers++;
      }
      // TweenService:Create
      if (node.base.type === "MemberExpression" && node.base.indexer === ":"
          && node.base.base && node.base.base.name === "TweenService") {
        patterns.tweenServiceUsage++;
      }
    }

    // .Parent = X
    if (node.type === "AssignmentStatement" && node.variables) {
      for (const v of node.variables) {
        if (v.type === "MemberExpression" && v.identifier && v.identifier.name === "Parent") {
          patterns.guiParenting++;
        }
      }
    }

    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      walk(node[k]);
    }
  }
  walk(ast);

  // Heuristic: 20+ Instance.new + 10+ :Connect = custom UI
  patterns.hasCustomUI = patterns.instanceNewCount >= 20 && patterns.connectionHandlers >= 10;
  patterns.inputHandlers = (rawCode.match(/InputBegan|InputEnded|MouseButton1Click|MouseButton1Down|Activated/g) || []).length;

  return patterns;
}

// - Feature 3: Semantic Preservation Checker -
// After obfuscation, verify that critical patterns are still present.
// Compares before/after counts of :Connect, Instance.new, hookfunction, etc.
function semanticFingerprint(code) {
  return {
    instanceNew: (code.match(/Instance\.new/g) || []).length,
    connects: (code.match(/:Connect\s*\(/g) || []).length,
    pcalls: (code.match(/\bpcall\s*\(/g) || []).length,
    hookfunction: (code.match(/\bhookfunction\b/g) || []).length,
    getgenv: (code.match(/\bgetgenv\s*\(/g) || []).length,
    getService: (code.match(/:GetService\s*\(/g) || []).length,
    tweenCreate: (code.match(/:Create\s*\(/g) || []).length,
    coroutineCreate: (code.match(/coroutine\.(create|wrap|resume)/g) || []).length,
  };
}

function comparefingerprints(before, after, ratioTolerance) {
  ratioTolerance = ratioTolerance || 0.85; // 85% preservation threshold
  const issues = [];
  for (const key of Object.keys(before)) {
    if (before[key] === 0) continue;
    const ratio = after[key] / before[key];
    if (ratio < ratioTolerance) {
      issues.push({
        pattern: key,
        before: before[key],
        after: after[key],
        preservationRatio: ratio.toFixed(2),
      });
    }
  }
  return issues;
}

// - Feature 4: Self-Tuning Strategy -
// Auto-adjusts obfuscation intensity based on script characteristics
function tuneStrategy(profile, closureGraph, uiPatterns) {
  const strategy = {
    baseLevelOverride: null,        // 'medium' or null (no override)
    disableStringEncrypt: false,
    disableNumberEncode: false,
    disableVMHarness: false,
    disableRename: false,
    reasons: [],
  };

  // Rule 1: If closure graph has many shared state vars, be conservative with rename
  if (closureGraph.sharedStateVars.length >= 5) {
    strategy.reasons.push(
      "Detected " + closureGraph.sharedStateVars.length +
      " shared state variables - scope-aware rename recommended but keep strict"
    );
  }

  // Rule 2: If UI-heavy (custom framework), disable number encoding
  // (numbers are often used as UI positions/sizes and encoding them can cause layout bugs)
  if (uiPatterns.hasCustomUI && uiPatterns.instanceNewCount > 50) {
    strategy.disableNumberEncode = true;
    strategy.reasons.push(
      "Custom UI framework detected (" + uiPatterns.instanceNewCount +
      " Instance.new calls) - number encoding disabled to preserve UI values"
    );
  }

  // Rule 3: If very deep closure nesting, disable VM harness (VM adds overhead)
  const maxClosureDepth = Math.max(0, ...closureGraph.functions.map(f => {
    // count depth by walking parent chain
    let d = 0, cur = f.parentFn;
    while (cur !== null && d < 100) {
      const parent = closureGraph.functions.find(x => x.id === cur);
      if (!parent) break;
      cur = parent.parentFn;
      d++;
    }
    return d;
  }));
  if (maxClosureDepth >= 5) {
    strategy.reasons.push(
      "Closure depth " + maxClosureDepth + " - VM harness may cause upvalue issues"
    );
  }

  // Rule 4: If script uses executor hooks AND has many closures, force medium
  if (profile.hasHookfunction && closureGraph.functions.length >= 30) {
    strategy.baseLevelOverride = "medium";
    strategy.reasons.push(
      "Script uses hooks + " + closureGraph.functions.length +
      " closures - forcing medium level for stability"
    );
  }

  return strategy;
}

// - Feature 5: Runtime Dependency Report -
// Human-readable summary of what the script depends on
function generateDependencyReport(profile, closureGraph, uiPatterns) {
  const lines = [];
  lines.push("=== SCRIPT DEPENDENCY REPORT ===");
  lines.push("Functions: " + closureGraph.functions.length +
    " (avg upvalues per closure: " +
    (closureGraph.functions.reduce((s, f) => s + f.capturedUpvalues.length, 0) /
      Math.max(1, closureGraph.functions.length)).toFixed(1) + ")");

  if (closureGraph.sharedStateVars.length > 0) {
    lines.push("Shared state (captured by 3+ functions):");
    for (const s of closureGraph.sharedStateVars.slice(0, 8)) {
      lines.push("  - " + s.name + " (used by " + s.capturedBy + " functions)");
    }
  }

  if (uiPatterns.hasCustomUI) {
    lines.push("Custom UI: " + uiPatterns.instanceNewCount + " Instances, " +
      uiPatterns.connectionHandlers + " event handlers, " +
      uiPatterns.tweenServiceUsage + " tweens");
    const topTypes = Object.entries(uiPatterns.uiTypeCreations)
      .sort((a, b) => b[1] - a[1]).slice(0, 5);
    lines.push("  Top UI types: " + topTypes.map(t => t[0] + "ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â" + t[1]).join(", "));
  }

  return lines.join("\n");
}


// v20: Staged obfuscation. Apply transforms one at a time with validation
// after each. If a stage fails to produce parseable Lua, skip it and continue
// with the last-good state. Guarantees working output even if one feature breaks.
//
// Stages (executed in order):
//   1. baseline: preprocess + luauToLua conversion (must succeed or bail)
//   2. numericObf: walkAst with numeric obfuscation only
//   3. stringEnc: walkAst with string encryption
//   4. rename: walkAst with RenameCtx (hoisted)
//   5. nestingReduce: reduceNesting AST pass
//   6. serialize: emit Lua source
//   7. wrapDecoder: prepend string decoder + constant pool
//   8. antiTamper: wrap in bit32.bxor opaque predicate (maximum only)
//   9. byteLevelXor: full encryption chain (maximum only)
function stagedObfuscate(analysis, level, luaCode, options){
  options = options || {};
  const _report = options._report;
  const isMaximum = level === "maximum";
  const stages = { attempted: [], succeeded: [], skipped: [] };

  // Stage 1: baseline. Original AST from pre-analysis, already parsed.
  let currentAst = analysis.ast;
  let currentCode = analysis.convertedCode;
  if (!currentAst || !currentCode) {
    if (_report) _report.warn("Stage 1 (baseline): pre-analysis provided no AST/code");
    return { code: null, stages };
  }
  stages.succeeded.push("baseline");

  // Helper: clone AST via JSON round-trip (safe, no shared refs).
  // Skips 'loc'/'range' fields to keep size manageable.
  function cloneAst(node){
    return JSON.parse(JSON.stringify(node, (k, v) => (k === "loc" || k === "range") ? undefined : v));
  }

  // Helper: run a stage, validate, keep or rollback.
  function runStage(name, transform){
    stages.attempted.push(name);
    const beforeAst = currentAst;
    const beforeCode = currentCode;
    let workingAst = cloneAst(beforeAst);
    try {
      transform(workingAst);
      // Try serializing to Lua and re-parsing to validate
      const emitted = serialize(workingAst);
      const parseCheck = validateGeneratedCode(emitted);
      if (!parseCheck.ok) {
        if (_report) _report.warn("Stage " + name + " produced invalid Lua (line " + parseCheck.line + ": " + parseCheck.error + ") - skipped");
        stages.skipped.push(name);
        return false;
      }
      currentAst = workingAst;
      currentCode = emitted;
      stages.succeeded.push(name);
      return true;
    } catch (e) {
      if (_report) _report.warn("Stage " + name + " threw: " + (e.message || e) + " - skipped");
      stages.skipped.push(name);
      currentAst = beforeAst;
      currentCode = beforeCode;
      return false;
    }
  }

  // Prepare shared ctx for walkAst
  const stringKey = randInt(30, 230);
  const stringShift = randInt(0, 10);

  // Stage 2: numeric obfuscation only
  runStage("numericObf", (ast) => {
    const ctx = { stringKey: null, stringShift: null, strictStrings: false, rename: null,
                  _reportCounts: { stringsEncrypted: 0, stringsSkipped: 0, numericConstsObfuscated: 0 } };
    walkAst(ast, ctx);
    if (_report) _report.stats.numericConstsObfuscated = ctx._reportCounts.numericConstsObfuscated;
  });

  // Stage 3: string encryption (strict for maximum, normal for medium)
  runStage("stringEnc", (ast) => {
    const ctx = { stringKey, stringShift, strictStrings: isMaximum, rename: null,
                  _reportCounts: { stringsEncrypted: 0, stringsSkipped: 0, numericConstsObfuscated: 0 } };
    walkAst(ast, ctx);
    if (_report) {
      _report.stats.stringsEncrypted = ctx._reportCounts.stringsEncrypted;
      _report.stats.stringsSkipped = ctx._reportCounts.stringsSkipped;
      _report.layers.stringEncryption = true;
      _report.layers.stringEncryptionStrict = isMaximum;
      _report.layers.constantObfuscation = true;
    }
  });

  // Stage 4: identifier rename (maximum only)
  if (isMaximum) {
    runStage("rename", (ast) => {
      const ctx = { stringKey: null, stringShift: null, strictStrings: false,
                    rename: new RenameCtx(analysis.externals),
                    _reportCounts: { stringsEncrypted: 0, stringsSkipped: 0, numericConstsObfuscated: 0 } };
      walkAst(ast, ctx);
    });
  }

  // Stage 5: nesting reduction
  runStage("nestingReduce", (ast) => {
    reduceNesting(ast, 8);
  });

  // Stage 6: final serialize is implicit Ã¢â‚¬â€ currentCode has it already.
  stages.succeeded.push("serialize");

  // Stage 7: wrap with decoder + constant pool
  let wrapped = currentCode;
  try {
    stages.attempted.push("wrapDecoder");
    const decName = randHexName(3);
    const decoder = makeStringDecoder(decName, stringKey, stringShift);
    wrapped = wrapped.replace(/_D\(/g, decName + "(");
    let poolPreamble = "";
    if (isMaximum) {
      const poolKey = randInt(30, 230);
      const poolShift = randInt(0, 10);
      const poolFnName = "_cp" + randHexName(3);
      const poolVarName = "_CP" + randHexName(2);
      poolPreamble = generateConstantPool([], poolKey, poolShift, poolFnName, poolVarName) + "; ";
      if (_report) _report.layers.constantPool = true;
    }
    wrapped = poolPreamble + decoder + "; " + wrapped;
    // Validate
    const chk = validateGeneratedCode(wrapped);
    if (!chk.ok) {
      if (_report) _report.warn("Stage wrapDecoder produced invalid Lua (line " + chk.line + ") - reverting to no decoder wrap");
      wrapped = currentCode;
      stages.skipped.push("wrapDecoder");
    } else {
      stages.succeeded.push("wrapDecoder");
    }
  } catch (e) {
    if (_report) _report.warn("Stage wrapDecoder threw: " + (e.message || e) + " - reverting");
    wrapped = currentCode;
    stages.skipped.push("wrapDecoder");
  }

  // Stage 8: byte-level XOR chain (maximum only)
  if (isMaximum) {
    try {
      stages.attempted.push("byteLevelXor");
      const encrypted = byteLevelTripleObfuscate(wrapped, "maximum", options.userId);
      // Byte-level output is Lua that must also parse
      const chk = validateGeneratedCode(encrypted);
      if (chk.ok) {
        wrapped = encrypted;
        if (_report) {
          _report.layers.byteLevelXor = true;
          _report.layers.antiTamper = true;
        }
        stages.succeeded.push("byteLevelXor");
      } else {
        if (_report) _report.warn("Stage byteLevelXor produced invalid Lua - keeping unencrypted wrapped output");
        stages.skipped.push("byteLevelXor");
      }
    } catch (e) {
      if (_report) _report.warn("Stage byteLevelXor threw: " + (e.message || e) + " - keeping unencrypted");
      stages.skipped.push("byteLevelXor");
    }
  }

  return { code: wrapped, stages };
}

async function obfuscateWithReport(luaCode, level, userId, options){
  options = options || {};
  const _startTime = Date.now();
  const _report = new ObfuscationReport(level || "medium");
  const _forceMaximum = !!options.forceMaximum;
  level=level||"medium";
  const _WM=pickWatermark();
  try{
    // === v11.0 PRE-ANALYSIS ===
    const analysis = preAnalyze(luaCode);

    if (!analysis.ok) {
      console.error("[obfuscator v11] Pre-analysis FAILED at stage:", analysis.stage);
      for (const err of analysis.errors) console.error("[obfuscator v11]   " + err);

      if (analysis.stage === "parse") {
        console.warn("[obfuscator v11] Parse failed -ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â downgrading to byte-level protection.");
        console.warn("[obfuscator v11] Fix the parse error above to unlock full obfuscation.");
        let downCode;
        try { downCode = luauToLua(preprocess(luaCode)); }
        catch(_) { downCode = preprocess(luaCode); }
        try {
          const _out = _WM + byteLevelTripleObfuscate(downCode, level, userId);
          _report.setDowngrade("Parse failed at pre-analysis stage. Fell back to byte-level XOR encryption only.", "fallback");
          _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
          return { code: _out, report: _report };
        }
        catch (bfe) {
          console.error("[obfuscator v11] Byte-level fallback also failed:", bfe.message);
          const _out = _WM + aggressiveMinify(downCode);
          _report.setDowngrade("Parse failed AND byte-level encryption failed. Fell back to minification only.", "minified");
          _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
          return { code: _out, report: _report };
        }
      }
      const _out = _WM + aggressiveMinify(preprocess(luaCode));
      _report.setDowngrade("Pre-analysis failed at non-parse stage. Fell back to minification only.", "minified");
      _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
      return { code: _out, report: _report };
    }

    console.log("[obfuscator v11.3] Pre-analysis OK.",
      "Decls:", analysis.stats.declarations,
      "| Forward refs:", analysis.stats.forwardRefs,
      "| Externals:", analysis.stats.externalIdentifiers,
      "| Field assigns:", analysis.stats.tableFieldAssigns,
      "| Method calls:", analysis.stats.methodCalls);
    // Log the first 15 external names so user sees what got auto-whitelisted
    if(analysis.externals && analysis.externals.size > 0){
      const preview = [...analysis.externals].slice(0, 15).join(", ");
      const more = analysis.externals.size > 15 ? " (+"+(analysis.externals.size-15)+" more)" : "";
      console.log("[obfuscator v11.3]   Auto-whitelisted externals:", preview + more);
    }
    for (const w of analysis.warnings) console.log("[obfuscator v11]   " + w);

    // v16.1 P0 FIX: hoist `code` and `ast` HERE (before any code that uses them).
    // v16.2 P0 FIX: also hoist `profile` ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â tuneStrategy(profile,...) inside the
    // v16 advanced intelligence block was throwing "Cannot access 'profile'
    // before initialization" because profileScript() was called much later.
    const code = analysis.convertedCode;
    const ast = analysis.ast;

    // === v13.0 SCRIPT PROFILER (hoisted from below in v16.2) ===
    const profile = profileScript(ast, luaCode);
    _report.profile = {
      riskTier: profile.riskTier,
      complexityScore: profile.complexityScore,
      maxBlockDepth: profile.maxBlockDepth,
      functionCount: profile.functionCount,
      pcallCount: profile.pcallCount,
      hasHookfunction: !!profile.hasHookfunction,
      hasHookmetamethod: !!profile.hasHookmetamethod,
      frameworks: profile.frameworks ? [...profile.frameworks] : [],
      hotspotCount: profile.hotspots ? profile.hotspots.length : 0,
      hasRuntimeReflection: !!profile.hasRuntimeReflection
    };
    console.log("[obfuscator v13] Profile:",
      "risk=" + profile.riskTier,
      "| depth=" + profile.maxBlockDepth,
      "| complexity=" + profile.complexityScore,
      "| functions=" + profile.functionCount,
      "| pcalls=" + profile.pcallCount);
    if (profile.frameworks && profile.frameworks.size > 0) {
      console.log("[obfuscator v13] Detected frameworks:", [...profile.frameworks].join(", "));
    }
    if (profile.hasHookfunction || profile.hasHookmetamethod) {
      console.log("[obfuscator v13] Script uses executor hooks - sensitive-init sections will be preserved");
    }
    if (profile.hotspots && profile.hotspots.length > 0) {
      console.log("[obfuscator v13] Hotspots found:", profile.hotspots.length,
        "(deepest at line " + profile.hotspots[profile.hotspots.length-1].line + ", depth " +
        profile.hotspots[profile.hotspots.length-1].depth + ")");
    }

    // === v16.0 ADVANCED INTELLIGENCE ===
    const closureGraph = analyzeClosureGraph(ast);
    const uiPatterns = detectUIPatterns(ast, luaCode);
    const strategy = tuneStrategy(profile, closureGraph, uiPatterns);

    console.log("[obfuscator v16] Closure graph:",
      closureGraph.functions.length + " functions,",
      closureGraph.sharedStateVars.length + " shared-state vars,",
      closureGraph.upvalueUsage.size + " unique upvalues");

    if (uiPatterns.hasCustomUI) {
      console.log("[obfuscator v16] UI framework detected:",
        uiPatterns.instanceNewCount + " Instances,",
        uiPatterns.connectionHandlers + " handlers,",
        uiPatterns.tweenServiceUsage + " tweens");
    }

    if (closureGraph.sharedStateVars.length > 0) {
      const top5 = closureGraph.sharedStateVars.slice(0, 5).map(s =>
        s.name + "(" + s.capturedBy + ")"
      ).join(", ");
      console.log("[obfuscator v16] Top shared state:", top5);
    }

    for (const reason of strategy.reasons) {
      console.log("[obfuscator v16]   " + reason);
    }

    // === P0 FIX (v16.1): `code` and `ast` are now declared ABOVE the v16
    // advanced intelligence block. This duplicate site is preserved as an
    // anchor for the level-check early returns that follow.
    if(level==="none"){
      const _out = _WM+code;
      _report.actualLevel = "none";
      _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
      return { code: _out, report: _report };
    }
    if(level==="basic"){
      const _out = _WM+aggressiveMinify(code);
      _report.actualLevel = "basic";
      _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
      return { code: _out, report: _report };
    }

    const isMedium = level==="medium";
    const isMaximum = level==="maximum";
    let effectiveIsMaximum = isMaximum;  // may be downgraded further below

    // Apply strategy overrides
    if (strategy.baseLevelOverride === "medium" && isMaximum) {
      if (_forceMaximum) {
        console.log("[obfuscator v16] Force-maximum override: ignoring strategy suggestion to downgrade");
        _report.warn("Force-maximum override applied despite strategy recommending medium.");
      } else {
        console.log("[obfuscator v16] Auto-tuning: maximum to medium (safer for this script)");
        if (!_report.wasDowngraded) {
          _report.setDowngrade(
            "Strategy analyzer flagged this script as safer at medium tier. " +
            (strategy.reasons && strategy.reasons.length > 0 ? "Reasons: " + strategy.reasons.slice(0,3).join("; ") : ""),
            "medium"
          );
        }
        effectiveIsMaximum = false;
      }
    }

    // Capture fingerprint of PRE-obfuscation code for post-check
    const preFingerprint = semanticFingerprint(code);

    // v6.1: VM harness stays OUTSIDE the byte-level encryption
    // Attacker sees random opcodes + interpreter but no context on what runs
    let vmOuterHarness = "";
    if(effectiveIsMaximum){
      const vmResult = tryVmWrap(ast, level, analysis.externals);
      if(vmResult && vmResult.compiledCount > 0){
        vmOuterHarness = vmResult.vmHarness;
        ast.body = vmResult.passthrough;
        console.log("[obfuscator] VM-compiled", vmResult.compiledCount, "statements (outside encryption)");
        _report.layers.vmWrap = true;
        _report.stats.vmCompiledStatements = vmResult.compiledCount;
        _report.stats.vmBytecodeLength = vmResult.bcLength || 0;
        // Outer VM (3C) is auto-active when bc length >= 9 (see tryVmWrap)
        if((vmResult.bcLength || 0) >= 9){
          _report.layers.outerVM = true;
        }
      } else if(effectiveIsMaximum) {
        _report.warn("VM wrap was attempted but zero statements were compilable. Common causes: script has too many user-defined symbols, forward-refs, or non-whitelisted globals.");
      }
    }

    const stringKey=randInt(30,230);
    const stringShift=randInt(0,10);
    // v11.3: Pass auto-detected external identifiers to RenameCtx so they aren't nil-renamed
    // v15.1: strictStrings=true encrypts PascalCase + long ALL_CAPS (Option C).
    // Default: enabled for maximum only. Medium keeps Option B behavior (encrypt
    // PascalCase >= 8 chars, keep short ALL_CAPS literal).
    const _reportCounts = { stringsEncrypted: 0, stringsSkipped: 0, numericConstsObfuscated: 0 };
    const ctx={stringKey,stringShift,strictStrings:effectiveIsMaximum,rename:effectiveIsMaximum?new RenameCtx(analysis.externals):null,_reportCounts};
    _report.layers.stringEncryption = true;
    _report.layers.stringEncryptionStrict = effectiveIsMaximum;
    _report.layers.constantObfuscation = true;
    // === v13.0 SCRIPT PROFILER (moved to hoisted P0 fix section in v16.2) ===

    // === v13.0 ADAPTIVE STRATEGY DOWNGRADE (hoisted P0 fix) ===
    // Actual downgrade logic runs HERE (after profile is available).
    if (profile.riskTier === "extreme" && (profile.hasHookfunction || profile.hasHookmetamethod)) {
      if (isMaximum) {
        if (_forceMaximum) {
          console.log("[obfuscator v16] Force-maximum override: skipping auto-downgrade despite extreme risk + hooks");
          _report.warn("Force-maximum override applied despite extreme risk + hooks. Script may break.");
        } else {
          console.log("[obfuscator v13] Auto-downgrading maximum to medium (extreme risk + hooks detected)");
          _report.setDowngrade(
            "Script has extreme complexity (risk=" + profile.riskTier +
            ") AND uses executor hooks (" +
            (profile.hasHookfunction ? "hookfunction" : "") +
            (profile.hasHookfunction && profile.hasHookmetamethod ? " + " : "") +
            (profile.hasHookmetamethod ? "hookmetamethod" : "") +
            "). VM wrap would break your hooks, so obfuscation ran in medium tier for safety.",
            "medium"
          );
          effectiveIsMaximum = false;
        }
      }
    }

    // v20: STAGED OBFUSCATION for maximum tier. Runs each transform pass
    // one at a time, validates after each, skips any that produce invalid Lua.
    // Medium tier keeps the original single-pass flow (already stable).
    if (effectiveIsMaximum) {
      const staged = stagedObfuscate(analysis, "maximum", luaCode, { _report, userId });
      if (staged.code) {
        const _finalOutput = _WM + staged.code;
        _report.actualLevel = "maximum";
        _report.stages = staged.stages;
        _report.finalize(luaCode.length, _finalOutput.length, Date.now() - _startTime);
        console.log("[obfuscator v20] Staged obfuscation complete. Succeeded: " + staged.stages.succeeded.join(",") + " | Skipped: " + staged.stages.skipped.join(","));
        return { code: _finalOutput, report: _report };
      }
      console.warn("[obfuscator v20] Staged obfuscation returned no code - falling through to legacy path");
    }

    walkAst(ast,ctx);

    // === v13.0 AST-LEVEL NESTING REDUCTION ===
    const depthBefore = measureAstDepth(ast);
    const flattenStats = reduceNesting(ast, 8);
    const depthAfter = measureAstDepth(ast);
    console.log("[obfuscator v13] Nesting reduction:",
      "depth " + depthBefore + "- ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢" + depthAfter,
      "| if-chains flattened:", flattenStats.flattens,
      "| do-blocks inlined:", flattenStats.doBlocksInlined,
      "| empty else removed:", flattenStats.emptyElsesRemoved);
    if (depthAfter > 100) {
      console.warn("[obfuscator v13] -  Post-flatten depth still " + depthAfter +
        " - some executors may still fail. Source refactor recommended.");
    }

    let ob=serialize(ast);

    // === v13.0 POST-OBFUSCATION VALIDATOR ===
    // Re-parse the generated code. If it's broken, fall back to lighter obfuscation.
    const validation = validateGeneratedCode(ob);
    if (!validation.ok) {
      console.error("[obfuscator v13] -  Generated code failed validation at line " +
        validation.line + ": " + validation.error);
      console.warn("[obfuscator v13] Retrying with minimal transformations (rename disabled)");
      // Reset the AST from analysis and skip renaming
      const freshAst = analysis.ast;
      const freshCtx = { stringKey, stringShift, strictStrings: false, rename: null };
      walkAst(freshAst, freshCtx);
      reduceNesting(freshAst, 8);
      ob = serialize(freshAst);
      const revalidation = validateGeneratedCode(ob);
      if (!revalidation.ok) {
        console.error("[obfuscator v13] -  Even minimal obfuscation failed - falling back to minified passthrough");
        const _out = _WM + aggressiveMinify(code);
        _report.setDowngrade("Post-obfuscation validator failed twice. Fell back to minification only.", "minified");
        _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
        return { code: _out, report: _report };
      } else {
        console.log("[obfuscator v13] ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ Retry with minimal mode succeeded");
      }
    } else {
      console.log("[obfuscator v13] ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ Generated code validated OK");
    }

    // === v16.0 SEMANTIC PRESERVATION CHECK ===
    const postFingerprint = semanticFingerprint(ob);
    const semanticIssues = comparefingerprints(preFingerprint, postFingerprint, 0.85);
    if (semanticIssues.length > 0) {
      console.warn("[obfuscator v16] -  Semantic pattern preservation issues:");
      for (const issue of semanticIssues) {
        console.warn("[obfuscator v16]   " + issue.pattern +
          ": " + issue.before + " - ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ " + issue.after +
          " (ratio: " + issue.preservationRatio + ")");
      }
    } else {
      console.log("[obfuscator v16] ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ All semantic patterns preserved");
    }

    // === v14.0 ANTI-DEBUGGER + ANTI-TAMPER LAYER (v14.0 3B: expanded coverage) ===
    // Old policy: enable only for low-risk scripts with zero hooks (nearly never triggered).
    // New policy: enable for low/medium always; enable for high/extreme UNLESS the
    // script uses both hookfunction AND hookmetamethod (heavy hook user - would
    // false-positive). If the script uses ONE hook type, use soft mode which
    // skips the corresponding check.
    const usesBothHooks = profile.hasHookfunction && profile.hasHookmetamethod;
    // v17: NEVER enable anti-debug for reflection-heavy scripts.
    const canEnableAntiDebug =
      !profile.hasRuntimeReflection && (
        (profile.riskTier === "low" || profile.riskTier === "medium") ||
        (profile.riskTier === "high" && !usesBothHooks) ||
        (profile.riskTier === "extreme" && !usesBothHooks)
      );
    if (canEnableAntiDebug) {
      const softMode = profile.hasHookfunction || profile.hasHookmetamethod;
      console.log("[obfuscator v14] Enabling anti-debugger + anti-tamper layer" +
        (softMode ? " (SOFT mode: script uses hooks - skipping hook-detection check)" : ""));
      const antiDebug = generateAntiDebugger(softMode);
      const integrityCheck = generateIntegrityCheck(ob);
      ob = antiDebug + "; " + integrityCheck + "; " + ob;
      _report.layers.antiDebugger = true;
      _report.layers.antiDebuggerMode = softMode ? "soft" : "hard";
      _report.layers.integrityCheck = true;
      console.log("[obfuscator v14]   Added integrity check (checksum of first 200 bytes)");
      console.log("[obfuscator v14]   Added anti-debugger" +
        (softMode ? " (gethook + getgc scan only)" : " (gethook + getgc scan + hookfunction detection)"));
    } else {
      const skipReason = profile.hasRuntimeReflection
        ? "script uses runtime reflection (getgc/debug.info/etc) - anti-debugger would false-positive"
        : "script uses both hookfunction+hookmetamethod - too risky";
      console.log("[obfuscator v14] Skipping anti-debugger layer (" + skipReason + ")");
      _report.warn("Anti-debugger disabled: " + skipReason);
    }
    ob = addContinueLabels(ob);  // v9.1: replace goto __continue__ with safe no-op
    const decName=randHexName(3);
    const decoder=makeStringDecoder(decName,stringKey,stringShift);
    ob = ob.replace(/_D\(/g, decName+"(");

    // v9.0: For maximum, emit constants pool with 20-40 poison entries
    let poolPreamble = "";
    if(isMaximum){
      const poolKey = randInt(30, 230);
      const poolShift = randInt(0, 10);
      const poolFnName = "_cp" + randHexName(3);
      const poolVarName = "_CP" + randHexName(2);
      poolPreamble = generateConstantPool([], poolKey, poolShift, poolFnName, poolVarName) + "; ";
      _report.layers.constantPool = true;
    }

    let combined=poolPreamble+decoder+"; "+ob;

    if(isMedium){
      const _finalOutput = _WM+combined;
      _report.stats.stringsEncrypted = _reportCounts.stringsEncrypted;
      _report.stats.stringsSkipped = _reportCounts.stringsSkipped;
      _report.stats.numericConstsObfuscated = _reportCounts.numericConstsObfuscated;
      _report.actualLevel = _report.wasDowngraded ? "medium" : level;
      _report.finalize(luaCode.length, _finalOutput.length, Date.now() - _startTime);
      return { code: _finalOutput, report: _report };
    }

    // v19: Restore byte-level XOR chain now that the real bug (property
    // identifier rename bleeding) is fixed. The chain itself was innocent;
    // the crashes were from broken Identifier renames upstream.
    const effectiveLevel = effectiveIsMaximum ? "maximum" : "medium";
    const encrypted = byteLevelTripleObfuscate(combined, effectiveLevel, userId);
    _report.layers.byteLevelXor = true;
    _report.layers.antiTamper = effectiveIsMaximum;
    // v8.0: Wrap in Control Flow Flattening state machine (maximum only)
    let finalOutput;
    if(isMaximum){
      // v10.0: CFF disabled - was wrapping encrypted payload with nested if/elseif
      // that some Roblox executors mishandle. Straight concat is safer.
      finalOutput = vmOuterHarness ? (vmOuterHarness + "; " + encrypted) : encrypted;
    } else {
      finalOutput = vmOuterHarness ? (vmOuterHarness + "; " + encrypted) : encrypted;
    }
    const _combinedFinal = _WM + finalOutput;
    _report.stats.stringsEncrypted = _reportCounts.stringsEncrypted;
    _report.stats.stringsSkipped = _reportCounts.stringsSkipped;
    _report.stats.numericConstsObfuscated = _reportCounts.numericConstsObfuscated;
    _report.actualLevel = effectiveIsMaximum ? "maximum" : "medium";
    _report.finalize(luaCode.length, _combinedFinal.length, Date.now() - _startTime);
    return { code: _combinedFinal, report: _report };
  }catch(err){
    console.error("[obfuscator] Error:",err.message);
    try{
      // v17: Fallback uses medium tier to avoid re-triggering mixed-state bug.
      const _out = _WM+byteLevelTripleObfuscate(preprocess(luaCode),"medium",userId);
      _report.actualLevel = "fallback";
      _report.setDowngrade("Main obfuscation path threw an error. Fell back to byte-level XOR only. Error: " + err.message, "fallback");
      _report.finalize(luaCode.length, _out.length, Date.now() - _startTime);
      return { code: _out, report: _report };
    }catch(e){
      throw new Error("Failed to obfuscate: "+err.message);
    }
  }
}

process.on("uncaughtException",(e)=>{console.error("[obfuscator] Uncaught:",e.message);});
process.on("unhandledRejection",(r)=>{console.error("[obfuscator] Unhandled:",r);});

// v16.0: Backward-compat wrapper. Old callers get raw string, new callers
// can use obfuscateWithReport() to get {code, report}.
async function obfuscate(luaCode, level, userId){
  const result = await obfuscateWithReport(luaCode, level, userId);
  return typeof result === "string" ? result : result.code;
}
module.exports={obfuscate, obfuscateWithReport};
