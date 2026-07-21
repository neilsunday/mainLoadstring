// AzureVM Obfuscator â€” v9.7 (Phase 3 hotfix 7: safer anti-tamper + robust loadstring fallback)
// Improvements over v8.1:
//   1. Constants Pool with poison entries (was: unused/broken)
//   2. Position + prev-byte dependent stream cipher (was: triple XOR only)
//   3. VM expanded to 55+ opcodes with dummy variants (was: 35)
//   4. Randomized base64 alphabet per obfuscation (was: standard)
//   5. Junk with real side effects â€” DCE-resistant (was: pure locals)
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
  "syn","fluxus","krnl","self","true","false","nil",
  "and","or","not","if","then","else","elseif","end","do","while","repeat","until",
  "for","in","function","return","break","goto","continue","local"
]);

const WORD_BINARY_OPS = new Set(["and","or",".."]);

// v6.2: Fake watermark rotation Ã¢â‚¬â€ decoy to mislead attackers into using
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



// v9.0: Expanded from 35 to 55+ opcodes â€” dummy variants confuse pattern analysis
const OP_NAMES = [
  "PUSH_CONST","PUSH_NIL","PUSH_TRUE","PUSH_FALSE","PUSH_GLOBAL","SET_GLOBAL",
  "DUP","POP","CALL","RETURN","ADD","SUB","MUL","DIV","MOD","POW","CONCAT",
  "EQ","NEQ","LT","LE","GT","GE","NOT","NEG","LEN","JMP","JMP_IF_FALSE","JMP_IF_TRUE",
  "NEW_TABLE","SET_INDEX","GET_INDEX","GET_MEMBER","SET_MEMBER","METHOD_CALL","HALT",
  // Dummy opcodes â€” never emitted by compiler but present in interpreter
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

// v9.0: Custom base64 alphabet â€” shuffled per obfuscation for anti-pattern-matching
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function makeCustomB64Alphabet(){
  const arr = B64_STD.split("");
  for(let i = arr.length - 1; i > 0; i--){
    const j = _secRand(0, i);
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  return arr.join("");
}

// v9.0: Stream cipher â€” position + prev-byte feedback (ChaCha20-inspired)
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
  //     Before: a += b or c   â†’  a = a + b or c   (WRONG: parses as (a+b) or c)
  //     After:  a += b or c   â†’  a = a + (b or c) (correct)
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
    // Wrap RHS in parens to preserve semantics: a += b or c  â†’  a = a + (b or c)
    return lhs + " = " + lhs + " " + op + " (" + rhs.trim() + ")";
  });

  // ---- Step 3: continue â†’ goto __continue_N__ + inject matching labels ----
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

      // Opening block keywords â€” each pushes exactly ONE block
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
        // 'then' is part of if/elseif clause â€” no block push
        // But 'if X then' needs to open the if body; the block for 'if' was already pushed
      } else if (kw === "elseif") {
        // Continuation of if â€” no block change
      } else if (kw === "else") {
        // Continuation of if â€” no block change
      } else if (kw === "end") {
        // Close the topmost block (regardless of type: for/while/if/function/do)
        const closing = blockStack.pop();
        if (closing && closing.type === "loop" && closing.needsLabel) {
          result.push({ kind: "raw", value: " ::" + closing.labelName + ":: " });
        }
        // Note: 'repeat' loops close with 'until', not 'end' â€” handled below
      } else if (kw === "until") {
        // Close a repeat_loop
        // If the top block isn't a repeat_loop, we have a bug â€” but pop anyway to stay in sync
        const closing = blockStack.pop();
        if (closing && closing.type === "repeat_loop" && closing.needsLabel) {
          // For 'repeat body until cond', the label goes BEFORE 'until'
          result.push({ kind: "raw", value: " ::" + closing.labelName + ":: " });
        }
      } else if (kw === "continue") {
        // Find topmost loop (regular or repeat)
        let loopBlock = null;
        for (let bi = blockStack.length - 1; bi >= 0; bi--) {
          const b = blockStack[bi];
          if (b.type === "loop" || b.type === "repeat_loop") {
            loopBlock = b;
            break;
          }
          // Stop searching if we hit a function boundary
          if (b.type === "function") break;
        }
        if (loopBlock) {
          if (!loopBlock.labelName) {
            loopBlock.labelName = "__continue_" + (labelCounter++) + "__";
            loopBlock.needsLabel = true;
          }
          result.push({ kind: "raw", value: "goto " + loopBlock.labelName });
          continue;
        } else {
          // continue outside a loop â€” safe no-op
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
        // Check word boundary â€” must not be preceded by identifier char
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
  return out.trim();
}

function vmCanCompile(node){
  if(!node)return false;
  const t=node.type;
  if(t==="CallStatement"){
    const e=node.expression;
    if(!e)return false;
    if(e.type==="CallExpression")return vmCanCompile(e.base)&&e.arguments.every(a=>vmCanCompileExpr(a));
    if(e.type==="StringCallExpression")return vmCanCompile(e.base)&&vmCanCompileExpr(e.argument);
    return false;
  }
  if(t==="Identifier"||t==="MemberExpression")return true;
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
  if(t==="CallExpression")return vmCanCompileExpr(node.base)&&node.arguments.every(a=>vmCanCompileExpr(a));
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

function generateVMInterpreter(vmFn,OP){
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
    +"elseif op=="+OP.HALT+" then break "
    // v9.0: Dummy opcode handlers â€” dispatch table looks richer than it is
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


// v7.0: Constant Pool Ã¢â‚¬â€ global encrypted table with real + poison entries
// Deobfuscator sees _CP[47] but has no clue what index 47 decodes to
// without emulating the entire pool decryption
function generateConstantPool(entries, poolKey, poolShift, fnName, varName){
  fnName = fnName || "_cp" + randHexName(3);
  varName = varName || "_CP" + randHexName(2);

  const allEntries = [];
  for(const entry of (entries || [])){
    allEntries.push({real: true, value: entry});
  }

  // 20-40 poison decoy entries â€” realistic Roblox strings to waste analyst time
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


// v7.0: Real Watermarking Ã¢â‚¬â€ user-specific fingerprint scattered as junk vars
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
    // Random prefix per var â€” no regex signature
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



// v8.0: Control Flow Flattening Ã¢â‚¬â€ wraps execution in state-machine dispatcher
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
  // Fake state branches (never reached Ã¢â‚¬â€ dead code)
  fakeStates.forEach(s=>{
    dispatcher += "elseif " + stateVar + "==" + s.stateNum + " then " + s.code + "; " + stateVar + "=" + s.nextState + " ";
  });
  dispatcher += "else " + doneFlag + "=true end end";
  return dispatcher;
}


// v8.0: Self-Modifying Bytecode Ã¢â‚¬â€ bytecode is XOR-scrambled at rest
// Runtime unscrambles it just before execution. Static disassembly = garbage.
function scrambleBytecode(bcArr, scrambleKey){
  const scrambled = bcArr.map((byte, i) => (byte ^ (scrambleKey + (i % 23))) & 0xff);
  return scrambled;
}

function generateBytecodeUnscrambler(fnName, scrambleKey){
  return "local function " + fnName + "(arr) local out={} for i=1,#arr do out[i]=bit32.bxor(arr[i],(" + scrambleKey + "+((i-1)%23)))%256 end return out end";
}


// v8.0: String Chunking Ã¢â‚¬â€ splits strings into pieces, concats at runtime
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

// v9.0: DCE-resistant junk â€” writes to shared table so dead-code elimination
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
  // v9.7: wrap payload in pcall so nil-indexing errors don't crash whole script
  // Roblox executors are inconsistent about global availability
  return "if "+c1+" and "+c2+" then pcall(function() "+payload+" end) else local "+junkV+"="+randInt(1,999)+"*"+randInt(1,999)+" end";
}

function generateAntiTamper(){
  const wrapper=randHexName(6);
  const chk1=randHexName(5);
  const chk2=randHexName(5);
  const flag=randHexName(4);
  // v9.7: NO longer invokes hookfunction as a test (conflicts with user scripts that
  // hook things themselves). Just check for existence and expected type/behavior of core Lua.
  return "local "+wrapper+"=function() local "+flag+"=true "+
    "local "+chk1+"=pcall(function() return bit32.bxor(15,15)==0 end) "+
    "local "+chk2+"=pcall(function() return (type(game)=='userdata') or (type(game)=='table') or true end) "+
    "if not "+chk1+" then "+flag+"=false end "+
    "if not "+chk2+" then "+flag+"=false end "+
    // Soft tamper response â€” instead of infinite loop that could softlock Roblox,
    // just returns false. Downstream code checks _L existence anyway.
    "return "+flag+" end "+wrapper+"()";
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

class RenameCtx{
  constructor(){this.map=new Map();this.counter=0;}
  rename(name){
    if(ROBLOX_GLOBALS.has(name))return name;
    if(this.map.has(name))return this.map.get(name);
    const n=randHexName(6)+"_"+this.counter.toString(16);
    this.counter++;
    this.map.set(name,n);
    return n;
  }
}

function walkAst(node,ctx){
  if(!node||typeof node!=="object")return;
  if(node.type==="StringLiteral"&&typeof node.value==="string"){
    node.__obf={type:"str",bytes:encryptString(node.value,ctx.stringKey,ctx.stringShift)};
    return;
  }
  if(node.type==="NumericLiteral"&&typeof node.value==="number"){
    node.__obf={type:"num",expr:encodeNumber(node.value)};
    return;
  }
  if(ctx.rename){
    if(node.type==="LocalStatement"&&Array.isArray(node.variables)){
      node.variables.forEach(v=>{if(v.type==="Identifier"&&v.name)v.name=ctx.rename.rename(v.name);});
    }
    if(node.type==="FunctionDeclaration"){
      if(node.isLocal&&node.identifier&&node.identifier.type==="Identifier"){
        node.identifier.name=ctx.rename.rename(node.identifier.name);
      }
      if(Array.isArray(node.parameters)){
        node.parameters.forEach(p=>{if(p.type==="Identifier"&&p.name)p.name=ctx.rename.rename(p.name);});
      }
    }
    if(node.type==="ForNumericStatement"&&node.variable){
      node.variable.name=ctx.rename.rename(node.variable.name);
    }
    if(node.type==="ForGenericStatement"&&Array.isArray(node.variables)){
      node.variables.forEach(v=>{v.name=ctx.rename.rename(v.name);});
    }
  }
  for(const k in node){
    if(k==="loc"||k==="range"||k==="__obf")continue;
    const c=node[k];
    if(Array.isArray(c))c.forEach(x=>walkAst(x,ctx));
    else if(c&&typeof c==="object")walkAst(c,ctx);
  }
  if(ctx.rename&&node.type==="Identifier"&&node.name&&ctx.rename.map.has(node.name)){
    node.name=ctx.rename.map.get(node.name);
  }
}

function serializeBlock(stmts){
  return stmts.map(serialize).filter(s=>s.length>0).join(";");
}

// v9.1: Add ::__continue__:: label at end of loop bodies so 'goto __continue__' works
function addContinueLabels(luaCode) {
  // v9.5: no-op â€” continue labels are now injected in luauToLua's injectContinueLabels
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
    case "StringLiteral":return JSON.stringify(node.value);
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

function tryVmWrap(ast, level){
  if(!ast || !ast.body || ast.body.length === 0) return null;
  const OP = makeOpTable();
  const bc = [];
  const consts = [];
  const globals = [];
  const passthrough = [];
  let compiledCount = 0;
  const MAX_VM_STATEMENTS = 500; // v9.0: raised from 200

  // v9.0: Prioritize sensitive statements â€” calls to HttpGet, loadstring, GetService, etc.
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
  const indexed = ast.body.map((stmt, i) => ({ stmt, i, score: stmtSensitivity(stmt) }));
  indexed.sort((a, b) => b.score - a.score || a.i - b.i);
  ast.body = indexed.map(x => x.stmt);
  for(const stmt of ast.body){
    if(compiledCount < MAX_VM_STATEMENTS && vmCanCompile(stmt)){
      vmCompileStmt(stmt, bc, consts, globals, OP);
      compiledCount++;
    } else {
      passthrough.push(stmt);
    }
  }
  if(compiledCount === 0) return null;
  bc.push(OP.HALT);
  const vmFn = randHexName(6);
  const bcVar = randHexName(5);
  const ksVar = randHexName(5);
  const gsVar = randHexName(5);
  const unpackFn = randHexName(6);
  const interp = generateVMInterpreter(vmFn, OP);
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
  const antiDump = level === "maximum" ? generateAntiDump() : "";
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

  // Random 3-letter tag per obfuscation â€” no brand leak
  const _tagA = String.fromCharCode(65+randInt(0,25));
  const _tagB = String.fromCharCode(65+randInt(0,25));
  const _tagC = String.fromCharCode(65+randInt(0,25));
  const _tag = _tagA+_tagB+_tagC;
  const execCore="local _L=loadstring or load; local "+execVar+","+errVar+"=_L("+realDec+"("+strVar+")); if "+execVar+" then local _ok,_err=pcall("+execVar+"); if (not _ok) and _err then warn('["+_tag+"] R: '..tostring(_err)) end else if "+errVar+" then warn('["+_tag+"] C: '..tostring("+errVar+")) end end";

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

async function obfuscate(luaCode,level,userId){
  level=level||"medium";
  const _WM=pickWatermark();
  try{
    let code=preprocess(luaCode);
    // v9.1: Preprocess Luau-specific syntax so luaparse can handle Roblox scripts
    code = luauToLua(code);
    if(level==="none")return _WM+code;
    if(level==="basic")return _WM+aggressiveMinify(code);

    let ast=null;
    let parseErrMsg = "";
    try{
      // v9.1: Try Lua 5.3 first (supports goto for continue-workaround)
      ast=luaparse.parse(code,{luaVersion:"5.3",comments:false});
    }catch(e1){
      parseErrMsg = e1.message;
      try{
        ast=luaparse.parse(code,{luaVersion:"5.1",comments:false});
      }catch(e2){
        console.warn("[obfuscator] Parse failed for both 5.1 and 5.3, using byte-level fallback. Error:", parseErrMsg);
      }
    }

    if(!ast){
      console.warn("[obfuscator] Falling back to byte-level (no AST). Script size:", code.length);
      // v9.1: byte-level fallback works for ANY input â€” even if AST parse fails
      try {
        return _WM+byteLevelTripleObfuscate(code,level,userId);
      } catch(fbErr) {
        console.error("[obfuscator] Byte-level fallback ALSO failed:", fbErr.message);
        // Last resort: just return minified code
        return _WM + aggressiveMinify(code);
      }
    }

    const isMedium=level==="medium";
    const isMaximum=level==="maximum";

    // v6.1: VM harness stays OUTSIDE the byte-level encryption
    // Attacker sees random opcodes + interpreter but no context on what runs
    let vmOuterHarness = "";
    if(isMaximum){
      const vmResult = tryVmWrap(ast, level);
      if(vmResult && vmResult.compiledCount > 0){
        vmOuterHarness = vmResult.vmHarness;
        ast.body = vmResult.passthrough;
        console.log("[obfuscator] VM-compiled", vmResult.compiledCount, "statements (outside encryption)");
      }
    }

    const stringKey=randInt(30,230);
    const stringShift=randInt(0,10);
    const ctx={stringKey,stringShift,rename:isMaximum?new RenameCtx():null};
    walkAst(ast,ctx);
    let ob=serialize(ast);
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
      const states = [];
      if(vmOuterHarness) states.push(vmOuterHarness);
      states.push(encrypted);
      const cffWrapped = generateCFFDispatcher(states);
      finalOutput = cffWrapped;
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
