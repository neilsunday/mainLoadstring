// AzureVM Obfuscator v11.4 Ã¢â‚¬â€ line-break minifier for executor compatibility
// v11.4 changes:
//   - Aggressive minify now inserts newlines every ~500 chars at safe boundaries
//   - Prevents Delta/Synapse/Fluxus parsers from choking on massive single-line scripts
//   - Same code size and protection, just parseable
//   - Fixes "attempt to call nil value" caused by silent parser truncation
// v11.0 ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â pre-analysis + safer Luau conversion
// v11.0 changes:
//   - PRE-ANALYSIS PASS: symbol table, scope tree, forward-ref detection
//   - Compound assign: strips inline comments from RHS (fixes -- swallowing paren)
//   - Continue labels: safer function-boundary check
//   - Better parse-error reporting: exact line + context in logs
//   - Downgrades gracefully with loud warnings instead of silent byte-level fallback
// v10.6 ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â disabled buggy string encryption
// v10.5 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â VM whitelist: Roblox/executor globals only
// v10.4 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â declaration-order tracking, no reordering
// v10.3 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â top-local tracking, method-call passthrough
// v10.2 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â method-call passthrough, executor-aware loader
// v10.1 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â executor-aware loader chain)
// Original:  ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â v10.0 (Complete rewrite: simple exec_core, no nested returns, no CFF wrap)
// Improvements over v8.1:
//   1. Constants Pool with poison entries (was: unused/broken)
//   2. Position + prev-byte dependent stream cipher (was: triple XOR only)
//   3. VM expanded to 55+ opcodes with dummy variants (was: 35)
//   4. Randomized base64 alphabet per obfuscation (was: standard)
//   5. Junk with real side effects ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â DCE-resistant (was: pure locals)
//   6. Higher VM cap: 500 + smart sensitive-first sorting (was: 200)
const luaparse = require("luaparse");
const crypto = require("crypto");

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
  // v11.2: Extended executor globals ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â anti-detection, filesystem, cloning
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

// v6.2: Fake watermark rotation ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â decoy to mislead attackers into using
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



// v9.0: Expanded from 35 to 55+ opcodes ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â dummy variants confuse pattern analysis
const OP_NAMES = [
  "PUSH_CONST","PUSH_NIL","PUSH_TRUE","PUSH_FALSE","PUSH_GLOBAL","SET_GLOBAL",
  "DUP","POP","CALL","RETURN","ADD","SUB","MUL","DIV","MOD","POW","CONCAT",
  "EQ","NEQ","LT","LE","GT","GE","NOT","NEG","LEN","JMP","JMP_IF_FALSE","JMP_IF_TRUE",
  "NEW_TABLE","SET_INDEX","GET_INDEX","GET_MEMBER","SET_MEMBER","METHOD_CALL","HALT",
  // Dummy opcodes ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â never emitted by compiler but present in interpreter
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

// v9.0: Custom base64 alphabet ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â shuffled per obfuscation for anti-pattern-matching
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function makeCustomB64Alphabet(){
  const arr = B64_STD.split("");
  for(let i = arr.length - 1; i > 0; i--){
    const j = _secRand(0, i);
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  return arr.join("");
}

// v9.0: Stream cipher ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â position + prev-byte feedback (ChaCha20-inspired)
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

function makeOpTable(){
  const nums = [];
  const seen = new Set();
  while(nums.length < OP_NAMES.length){
    const n = randInt(1, 250);
    if(!seen.has(n)){ seen.add(n); nums.push(n); }
  }
  const table = {};
  OP_NAMES.forEach((name,i)=>{ table[name] = nums[i]; });
  return table;
}

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
  //   - Compound assignment precedence: wrap RHS in parens
  //     Before: a += b or c   ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢  a = a + b or c   (WRONG: parses as (a+b) or c)
  //     After:  a += b or c   ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢  a = a + (b or c) (correct)
  //   - continue: convert to 'goto __continue_N__' and inject matching label before loop's 'end'
  //     This preserves semantic behavior (actually skips iteration in Lua 5.3)

  const strings = [];
  let idx = 0;

  // ---- Step 1: Protect strings first (character tokenizer, safest) ----
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

  // ---- Step 2: Compound assignments with PRECEDENCE-SAFE wrapping ----
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
    // v11.0: Strip inline "--" comment from RHS before wrapping in parens.
    // Without this, "x += 5 -- note" would become "x = x + (5 -- note)" and
    // the -- swallows the closing paren, causing a silent parse error.
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

  // ---- Step 3: continue ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ goto __continue_N__ + inject matching labels ----
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
  //   - Split into tokens conceptually via a simple state machine
  //   - Track loop depth using keyword matching
  //   - Assign labels per loop

  work = injectContinueLabels(work);

  // ---- Step 4: Type annotations (safe: only in specific contexts) ----
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

  // ---- Step 5: Restore protected strings ----
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

      // Opening block keywords ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â each pushes exactly ONE block
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
        // 'then' is part of if/elseif clause ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â no block push
        // But 'if X then' needs to open the if body; the block for 'if' was already pushed
      } else if (kw === "elseif") {
        // Continuation of if ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â no block change
      } else if (kw === "else") {
        // Continuation of if ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â no block change
      } else if (kw === "end") {
        // Close the topmost block (regardless of type: for/while/if/function/do)
        const closing = blockStack.pop();
        if (closing && closing.type === "loop" && closing.needsLabel) {
          result.push({ kind: "raw", value: " ::" + closing.labelName + ":: " });
        }
        // Note: 'repeat' loops close with 'until', not 'end' ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â handled below
      } else if (kw === "until") {
        // Close a repeat_loop
        // If the top block isn't a repeat_loop, we have a bug ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â but pop anyway to stay in sync
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
          // continue outside a loop ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â safe no-op
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
        // Check word boundary ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â must not be preceded by identifier char
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
    // v10.2 FIX: Reject method calls (obj:method()) ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â VM compiler treats them
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
  return "local function "+vmFn+"(bc,ks,gs,env) local st={} local sp=0 local function ps(v) sp=sp+1 st[sp]=v end local function pp() local v=st[sp] st[sp]=nil sp=sp-1 return v end local pc=1 while true do local op=bc[pc] pc=pc+1 "
    +"if op=="+OP.PUSH_CONST+" then ps(ks[bc[pc]+1]) pc=pc+1 "
    +"elseif op=="+OP.PUSH_NIL+" then ps(nil) "
    +"elseif op=="+OP.PUSH_TRUE+" then ps(true) "
    +"elseif op=="+OP.PUSH_FALSE+" then ps(false) "
    +"elseif op=="+OP.PUSH_GLOBAL+" then ps(env[gs[bc[pc]+1]]) pc=pc+1 "
    +"elseif op=="+OP.SET_GLOBAL+" then env[gs[bc[pc]+1]]=pp() pc=pc+1 "
    +"elseif op=="+OP.DUP+" then ps(st[sp]) "
    +"elseif op=="+OP.POP+" then pp() "
    +"elseif op=="+OP.CALL+" then local na=bc[pc] pc=pc+1 local nr=bc[pc] pc=pc+1 local a={} for i=na,1,-1 do a[i]=pp() end local f=pp() local r={f(unpack(a))} if nr>0 then for i=1,nr do ps(r[i]) end end "
    +"elseif op=="+OP.RETURN+" then return "
    +"elseif op=="+OP.ADD+" then local b=pp() local a=pp() ps(a+b) "
    +"elseif op=="+OP.SUB+" then local b=pp() local a=pp() ps(a-b) "
    +"elseif op=="+OP.MUL+" then local b=pp() local a=pp() ps(a*b) "
    +"elseif op=="+OP.DIV+" then local b=pp() local a=pp() ps(a/b) "
    +"elseif op=="+OP.MOD+" then local b=pp() local a=pp() ps(a%b) "
    +"elseif op=="+OP.POW+" then local b=pp() local a=pp() ps(a^b) "
    +"elseif op=="+OP.CONCAT+" then local b=pp() local a=pp() ps(a..b) "
    +"elseif op=="+OP.EQ+" then local b=pp() local a=pp() ps(a==b) "
    +"elseif op=="+OP.NEQ+" then local b=pp() local a=pp() ps(a~=b) "
    +"elseif op=="+OP.LT+" then local b=pp() local a=pp() ps(a<b) "
    +"elseif op=="+OP.LE+" then local b=pp() local a=pp() ps(a<=b) "
    +"elseif op=="+OP.GT+" then local b=pp() local a=pp() ps(a>b) "
    +"elseif op=="+OP.GE+" then local b=pp() local a=pp() ps(a>=b) "
    +"elseif op=="+OP.NOT+" then ps(not pp()) "
    +"elseif op=="+OP.NEG+" then ps(-pp()) "
    +"elseif op=="+OP.LEN+" then ps(#pp()) "
    +"elseif op=="+OP.JMP+" then pc=pc+bc[pc] "
    +"elseif op=="+OP.JMP_IF_FALSE+" then local v=pp() local o=bc[pc] pc=pc+1 if not v then pc=pc+o end "
    +"elseif op=="+OP.JMP_IF_TRUE+" then local v=pp() local o=bc[pc] pc=pc+1 if v then pc=pc+o end "
    +"elseif op=="+OP.NEW_TABLE+" then ps({}) "
    +"elseif op=="+OP.SET_INDEX+" then local v=pp() local k=pp() local t=st[sp] t[k]=v "
    +"elseif op=="+OP.GET_INDEX+" then local k=pp() local t=pp() ps(t[k]) "
    +"elseif op=="+OP.GET_MEMBER+" then local m=ks[bc[pc]+1] pc=pc+1 local t=pp() ps(t[m]) "
    +"elseif op=="+OP.SET_MEMBER+" then local m=ks[bc[pc]+1] pc=pc+1 local v=pp() local t=pp() t[m]=v "
    +"elseif op=="+OP.METHOD_CALL+" then local m=ks[bc[pc]+1] pc=pc+1 local na=bc[pc] pc=pc+1 local nr=bc[pc] pc=pc+1 local a={} for i=na,1,-1 do a[i]=pp() end local t=pp() local r={t[m](t,unpack(a))} if nr>0 then for i=1,nr do ps(r[i]) end end "
    +"elseif op="+OP.HALT+" then break "
    +generateJunkOpHandlers(OP, junkOpNames || [])
    // v9.0: Dummy opcode handlers ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â dispatch table looks richer than it is
    +"elseif op=="+OP.NOP_A+" then local _n=1+2 "
    +"elseif op=="+OP.NOP_B+" then local _n=bit32.band(15,15) "
    +"elseif op=="+OP.NOP_C+" then local _n=math.floor(3.14) "
    +"elseif op=="+OP.NOP_D+" then local _n=#'x' "
    +"elseif op=="+OP.NOP_E+" then local _n=string.byte('a') "
    +"elseif op=="+OP.SWAP+" then local a=pp() local b=pp() ps(a) ps(b) "
    +"elseif op=="+OP.ROT3+" then local a=pp() local b=pp() local c=pp() ps(b) ps(a) ps(c) "
    +"elseif op=="+OP.PUSH_ZERO+" then ps(0) "
    +"elseif op=="+OP.PUSH_ONE+" then ps(1) "
    +"elseif op=="+OP.PUSH_NEG_ONE+" then ps(-1) "
    +"elseif op=="+OP.INC+" then local a=pp() ps(a+1) "
    +"elseif op=="+OP.DEC+" then local a=pp() ps(a-1) "
    +"elseif op=="+OP.DOUBLE+" then local a=pp() ps(a*2) "
    +"elseif op=="+OP.HALVE+" then local a=pp() ps(a/2) "
    +"elseif op=="+OP.SQUARE+" then local a=pp() ps(a*a) "
    +"elseif op=="+OP.STR_LEN+" then local a=pp() ps(#tostring(a)) "
    +"elseif op=="+OP.STR_UPPER+" then local a=pp() ps(string.upper(tostring(a))) "
    +"elseif op=="+OP.STR_LOWER+" then local a=pp() ps(string.lower(tostring(a))) "
    +"elseif op=="+OP.STR_REVERSE+" then local a=pp() ps(string.reverse(tostring(a))) "
    +"elseif op=="+OP.BITWISE_XOR+" then local b=pp() local a=pp() ps(bit32.bxor(a,b)) "
    +"end end end";
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

function serializeConsts(consts){
  const parts = consts.map(c=>{
    if(c.type==="s")return JSON.stringify(c.value);
    if(c.type==="n")return String(c.value);
    return "nil";
  });
  return "{"+parts.join(",")+"}";
}

function serializeGlobals(globals){
  return "{"+globals.map(g=>JSON.stringify(g)).join(",")+"}";
}


// v7.0: Constant Pool ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â global encrypted table with real + poison entries
// Deobfuscator sees _CP[47] but has no clue what index 47 decodes to
// without emulating the entire pool decryption
function generateConstantPool(entries, poolKey, poolShift, fnName, varName){
  fnName = fnName || "_cp" + randHexName(3);
  varName = varName || "_CP" + randHexName(2);

  const allEntries = [];
  for(const entry of (entries || [])){
    allEntries.push({real: true, value: entry});
  }

  // 20-40 poison decoy entries ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â realistic Roblox strings to waste analyst time
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


// v7.0: Real Watermarking ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â user-specific fingerprint scattered as junk vars
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
    // Random prefix per var ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â no regex signature
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



// v8.0: Control Flow Flattening ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â wraps execution in state-machine dispatcher
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
  // Fake state branches (never reached ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â dead code)
  fakeStates.forEach(s=>{
    dispatcher += "elseif " + stateVar + "==" + s.stateNum + " then " + s.code + "; " + stateVar + "=" + s.nextState + " ";
  });
  dispatcher += "else " + doneFlag + "=true end end";
  return dispatcher;
}


// v8.0: Self-Modifying Bytecode ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â bytecode is XOR-scrambled at rest
// Runtime unscrambles it just before execution. Static disassembly = garbage.
function scrambleBytecode(bcArr, scrambleKey){
  const scrambled = bcArr.map((byte, i) => (byte ^ (scrambleKey + (i % 23))) & 0xff);
  return scrambled;
}

function generateBytecodeUnscrambler(fnName, scrambleKey){
  return "local function " + fnName + "(arr) local out={} for i=1,#arr do out[i]=bit32.bxor(arr[i],(" + scrambleKey + "+((i-1)%23)))%256 end return out end";
}


// v8.0: String Chunking ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬ ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â splits strings into pieces, concats at runtime
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

// v9.0: DCE-resistant junk ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â writes to shared table so dead-code elimination
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
// local, it goes into the current scope only â€” so `local dragging` in
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
    const n = randHexName(6) + "_" + this.counter.toString(16);
    this.counter++;
    this.scopes[this.scopes.length - 1].set(name, n);
    return n;
  }

  lookup(name){
    if(ROBLOX_GLOBALS.has(name)) return name;
    if(this.externals.has(name)) return name;
    for(let i = this.scopes.length - 1; i >= 0; i--){
      if(this.scopes[i].has(name)){
        return this.scopes[i].get(name);
      }
    }
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
}

function walkAst(node,ctx){
  if(!node||typeof node!=="object")return;

  if(node.type==="NumericLiteral"&&typeof node.value==="number"){
    node.__obf={type:"num",expr:encodeNumber(node.value)};
    return;
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

  if(opensNewScope){
    ctx.rename.pushScope();
    if(Array.isArray(node.parameters)){
      node.parameters.forEach(p=>{
        if(p.type==="Identifier"&&p.name) p.name=ctx.rename.declare(p.name);
      });
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
  // v9.5: no-op ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â continue labels are now injected in luauToLua's injectContinueLabels
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
  // user-declared symbol ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â even top-level 'local function foo' ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â is nil at VM time.
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
      // global function declaration ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â treat as available
      topLocals.add(stmt.identifier.name);
    } else if(stmt.type === "AssignmentStatement" && stmt.variables){
      // assignments like foo = ... make foo available as global
      for(const v of stmt.variables){
        if(v && v.type === "Identifier") topLocals.add(v.name);
      }
    }
  }
  // Add ROBLOX_GLOBALS to the set ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â these are always safe as env[name]
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
    // Don't descend into function bodies ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â locals inside are their own scope
    if(node.type === "FunctionDeclaration" || node.type === "FunctionExpression") return false;
    for(const k of Object.keys(node)){
      if(k === "type" || k === "loc" || k === "range") continue;
      if(_refsUnknown(node[k])) return true;
    }
    return false;
  }
  const MAX_VM_STATEMENTS = 500; // v9.0: raised from 200

  // v9.0: Prioritize sensitive statements ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â calls to HttpGet, loadstring, GetService, etc.
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
  // v10.4: Disabled sensitivity reordering ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â it hoists calls BEFORE their
  // 'local function' declarations, causing 'attempt to call a nil value'.
  // Preserving original order keeps declaration-before-use semantics intact.
  //
  // Additionally: track locals declared as we walk, so a later call to a
  // function declared earlier in the same top-level scope compiles safely,
  // but a call to a function declared LATER falls through to passthrough.
  const declaredSoFar = new Set(topLocals);
  // Remove things that appear AFTER their first usage ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â start empty of body-declared items
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
  // Remove body-declared names from declaredSoFar ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â they only become available
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

  // v10.5: Build strict whitelist ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â only Roblox + executor globals are VM-safe
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
      // v10.5: Only Roblox/executor globals are safe ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â everything else is user-declared
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
  const unpacker = makeBytecodeUnpacker(unpackFn);
  const packedBc = packBytecode(bc);
  const vmHarness = [
    unpacker,
    interp,
    "local "+bcVar+"="+unpackFn+"(\""+packedBc+"\")",
    "local "+ksVar+"="+serializeConsts(consts),
    "local "+gsVar+"="+serializeGlobals(globals),
    vmFn+"("+bcVar+","+ksVar+","+gsVar+",getfenv and getfenv() or _ENV)"
  ].join("; ");
  return { vmHarness, passthrough, compiledCount };
}

function byteLevelTripleObfuscate(code,level,userId){
  const minified=aggressiveMinify(code);
  // v9.0: shared junk table for DCE resistance
  const sharedJunkVar = "_" + randHexName(4);
  const junkTablePreamble = "local " + sharedJunkVar + "={}";
  const watermark = generateUserWatermark(userId);
  // v9.8: antiDump disabled ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â iterating getgc() on scripts with 1000+ functions crashes some executors
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

  // Random 3-letter tag per obfuscation ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦Ãƒâ€šÃ‚Â¡ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â no brand leak
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
        // Silent fail ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â no error message, no crash
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
      "Found " + symbols.forwardRefs.length + " forward function reference(s) ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â " +
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
// declared in ANY scope. These are the script's external dependencies ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â must
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

    // Any bare Identifier is a reference ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â but skip MemberExpression's .identifier
    // (that's a field name, not a variable reference)
    if (node.type === "Identifier" && node.name) {
      allReferenced.add(node.name);
    }

    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      // Skip the .identifier of MemberExpression ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â it's a field access, not a variable
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

// ---- Feature 1: Script Profiler ----
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

  return profile;
}

function _getCalleeName(base) {
  if (!base) return null;
  if (base.type === "Identifier") return base.name;
  if (base.type === "MemberExpression" && base.identifier) return base.identifier.name;
  return null;
}

// ---- Feature 2: Section Splitter ----
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

// ---- Feature 3: AST-level nesting reducer (from v12, extended) ----
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

  // Transform 1: Standalone do-block with no locals â†’ inline
  if (node.type === "DoStatement" && node.body) {
    const hasLocals = node.body.some(s =>
      s.type === "LocalStatement" || s.type === "LocalFunctionStatement" ||
      (s.type === "FunctionDeclaration" && s.isLocal)
    );
    if (!hasLocals) {
      return { type: "__INLINE__", statements: node.body };
    }
  }

  // Transform 2: Chained single-branch if â†’ combined "and" condition
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

  // Transform 3: Empty else branch â†’ drop
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

// ---- Feature 6: Post-obfuscation validator ----
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
//   - getgc iteration (dumper tools scan the GC for functions)
//   - hookfunction on our own decoder (deobfuscator tools intercept)
//   - debug.sethook (single-step debugging)
//   - excessive pcall depth (some tools wrap everything in extra pcalls)
function generateAntiDebugger() {
  const fnName = randHexName(6);
  const flagVar = randHexName(4);
  const gcVar = randHexName(4);

  return "local function " + fnName + "() " +
    "local " + flagVar + "=false " +
    // Check 1: is debug.sethook active? (single-step debugger)
    "if debug and debug.gethook then " +
      "local ok,hook=pcall(debug.gethook) " +
      "if ok and hook then " + flagVar + "=true end " +
    "end " +
    // Check 2: is our own execution being watched via getgc?
    "if type(getgc)=='function' then " +
      "local ok2,gc=pcall(getgc,false) " +
      "if ok2 and type(gc)=='table' and #gc>50000 then " +
        // Suspiciously large GC pool â€” probably a scanning tool active
        flagVar + "=true " +
      "end " +
    "end " +
    // Check 3: is coroutine.wrap being hooked? (common for tracers)
    "if type(hookfunction)=='function' and type(coroutine)=='table' then " +
      "local ok3,orig=pcall(function() return coroutine.wrap end) " +
      "if ok3 and orig then " +
        "local info=debug and debug.info and debug.info(orig,'s') " +
        "if info and type(info)=='string' and #info>0 then " +
          flagVar + "=true " +
        "end " +
      "end " +
    "end " +
    "return not " + flagVar + " " +
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
// but present in the code â€” inflates the interpreter and confuses static analysis)
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


async function obfuscate(luaCode,level,userId){
  level=level||"medium";
  const _WM=pickWatermark();
  try{
    // === v11.0 PRE-ANALYSIS ===
    const analysis = preAnalyze(luaCode);

    if (!analysis.ok) {
      console.error("[obfuscator v11] Pre-analysis FAILED at stage:", analysis.stage);
      for (const err of analysis.errors) console.error("[obfuscator v11]   " + err);

      if (analysis.stage === "parse") {
        console.warn("[obfuscator v11] Parse failed ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â downgrading to byte-level protection.");
        console.warn("[obfuscator v11] Fix the parse error above to unlock full obfuscation.");
        let downCode;
        try { downCode = luauToLua(preprocess(luaCode)); }
        catch(_) { downCode = preprocess(luaCode); }
        try { return _WM + byteLevelTripleObfuscate(downCode, level, userId); }
        catch (bfe) {
          console.error("[obfuscator v11] Byte-level fallback also failed:", bfe.message);
          return _WM + aggressiveMinify(downCode);
        }
      }
      return _WM + aggressiveMinify(preprocess(luaCode));
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

    const code = analysis.convertedCode;
    const ast = analysis.ast;

    if(level==="none")return _WM+code;
    if(level==="basic")return _WM+aggressiveMinify(code);


    const isMedium=level==="medium";
    const isMaximum=level==="maximum";

    // v6.1: VM harness stays OUTSIDE the byte-level encryption
    // Attacker sees random opcodes + interpreter but no context on what runs
    let vmOuterHarness = "";
    if(effectiveIsMaximum){
      const vmResult = tryVmWrap(ast, level, analysis.externals);
      if(vmResult && vmResult.compiledCount > 0){
        vmOuterHarness = vmResult.vmHarness;
        ast.body = vmResult.passthrough;
        console.log("[obfuscator] VM-compiled", vmResult.compiledCount, "statements (outside encryption)");
      }
    }

    const stringKey=randInt(30,230);
    const stringShift=randInt(0,10);
    // v11.3: Pass auto-detected external identifiers to RenameCtx so they aren't nil-renamed
    const ctx={stringKey,stringShift,rename:effectiveIsMaximum?new RenameCtx(analysis.externals):null};
    // === v13.0 SCRIPT PROFILER ===
    const profile = profileScript(ast, luaCode);
    console.log("[obfuscator v13] Profile:",
      "risk=" + profile.riskTier,
      "| depth=" + profile.maxBlockDepth,
      "| complexity=" + profile.complexityScore,
      "| functions=" + profile.functionCount,
      "| pcalls=" + profile.pcallCount);
    if (profile.frameworks.size > 0) {
      console.log("[obfuscator v13] Detected frameworks:", [...profile.frameworks].join(", "));
    }
    if (profile.hasHookfunction || profile.hasHookmetamethod) {
      console.log("[obfuscator v13] âš  Script uses executor hooks â€” sensitive-init sections will be preserved");
    }
    if (profile.hotspots.length > 0) {
      console.log("[obfuscator v13] Hotspots found:", profile.hotspots.length,
        "(deepest at line " + profile.hotspots[profile.hotspots.length-1].line + ", depth " +
        profile.hotspots[profile.hotspots.length-1].depth + ")");
    }

    // === v13.0 ADAPTIVE STRATEGY DOWNGRADE ===
    // If the script has extreme complexity + uses hooks, force lighter obfuscation
    // to avoid runtime breakage of sensitive constructs.
    let effectiveIsMaximum = isMaximum;
    if (profile.riskTier === "extreme" && (profile.hasHookfunction || profile.hasHookmetamethod)) {
      if (isMaximum) {
        console.log("[obfuscator v13] Auto-downgrading maximumâ†’medium (extreme risk + hooks detected)");
        effectiveIsMaximum = false;
      }
    }

    walkAst(ast,ctx);

    // === v13.0 AST-LEVEL NESTING REDUCTION ===
    const depthBefore = measureAstDepth(ast);
    const flattenStats = reduceNesting(ast, 8);
    const depthAfter = measureAstDepth(ast);
    console.log("[obfuscator v13] Nesting reduction:",
      "depth " + depthBefore + "â†’" + depthAfter,
      "| if-chains flattened:", flattenStats.flattens,
      "| do-blocks inlined:", flattenStats.doBlocksInlined,
      "| empty else removed:", flattenStats.emptyElsesRemoved);
    if (depthAfter > 100) {
      console.warn("[obfuscator v13] âš  Post-flatten depth still " + depthAfter +
        " â€” some executors may still fail. Source refactor recommended.");
    }

    let ob=serialize(ast);

    // === v13.0 POST-OBFUSCATION VALIDATOR ===
    // Re-parse the generated code. If it's broken, fall back to lighter obfuscation.
    const validation = validateGeneratedCode(ob);
    if (!validation.ok) {
      console.error("[obfuscator v13] âš  Generated code failed validation at line " +
        validation.line + ": " + validation.error);
      console.warn("[obfuscator v13] Retrying with minimal transformations (rename disabled)");
      // Reset the AST from analysis and skip renaming
      const freshAst = analysis.ast;
      const freshCtx = { stringKey, stringShift, rename: null };
      walkAst(freshAst, freshCtx);
      reduceNesting(freshAst, 8);
      ob = serialize(freshAst);
      const revalidation = validateGeneratedCode(ob);
      if (!revalidation.ok) {
        console.error("[obfuscator v13] âš  Even minimal obfuscation failed â€” falling back to minified passthrough");
        return _WM + aggressiveMinify(code);
      } else {
        console.log("[obfuscator v13] âœ“ Retry with minimal mode succeeded");
      }
    } else {
      console.log("[obfuscator v13] âœ“ Generated code validated OK");
    }

    // === v14.0 ANTI-DEBUGGER + ANTI-TAMPER LAYER ===
    // Only enabled for low-risk scripts (adding runtime checks to a script that
    // already uses hooks would break it â€” the checks would false-positive on
    // the user's own hookfunction calls).
    if (profile.riskTier === "low" && !profile.hasHookfunction && !profile.hasHookmetamethod) {
      console.log("[obfuscator v14] Enabling anti-debugger + anti-tamper layer (safe: low-risk script)");
      const antiDebug = generateAntiDebugger();
      const integrityCheck = generateIntegrityCheck(ob);
      // Prepend runtime checks. If any detects tooling, script silently exits.
      ob = antiDebug + "; " + integrityCheck + "; " + ob;
      console.log("[obfuscator v14]   Added integrity check (checksum of first 200 bytes)");
      console.log("[obfuscator v14]   Added anti-debugger (gethook + getgc scan + hookfunction detection)");
    } else {
      const reason = profile.riskTier !== "low"
        ? "risk=" + profile.riskTier
        : "script uses hooks (would false-positive)";
      console.log("[obfuscator v14] Skipping anti-debugger layer (" + reason + ")");
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
    }

    let combined=poolPreamble+decoder+"; "+ob;

    if(isMedium)return _WM+combined;

    const encrypted = byteLevelTripleObfuscate(combined, level, userId);
    // v8.0: Wrap in Control Flow Flattening state machine (maximum only)
    let finalOutput;
    if(isMaximum){
      // v10.0: CFF disabled - was wrapping encrypted payload with nested if/elseif
      // that some Roblox executors mishandle. Straight concat is safer.
      finalOutput = vmOuterHarness ? (vmOuterHarness + "; " + encrypted) : encrypted;
    } else {
      finalOutput = vmOuterHarness ? (vmOuterHarness + "; " + encrypted) : encrypted;
    }
    return _WM + finalOutput;
  }catch(err){
    console.error("[obfuscator] Error:",err.message);
    try{
      return _WM+byteLevelTripleObfuscate(preprocess(luaCode),level,userId);
    }catch(e){
      throw new Error("Failed to obfuscate: "+err.message);
    }
  }
}

process.on("uncaughtException",(e)=>{console.error("[obfuscator] Uncaught:",e.message);});
process.on("unhandledRejection",(r)=>{console.error("[obfuscator] Unhandled:",r);});

module.exports={obfuscate};
