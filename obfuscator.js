const luaparse = require("luaparse");
const crypto = require("crypto");

const ROBLOX_GLOBALS = new Set([
  "game", "workspace", "script", "plugin", "shared", "_G", "_ENV",
  "Enum", "Instance", "Vector2", "Vector3", "CFrame", "Color3", "UDim", "UDim2",
  "Rect", "Region3", "Ray", "BrickColor", "NumberSequence", "NumberSequenceKeypoint",
  "ColorSequence", "ColorSequenceKeypoint", "NumberRange", "TweenInfo", "PhysicalProperties",
  "Random", "Faces", "Axes", "Vector2int16", "Vector3int16", "Font",
  "wait", "spawn", "delay", "tick", "time", "elapsedTime", "print", "warn", "error",
  "assert", "pcall", "xpcall", "select", "typeof", "type", "next", "pairs", "ipairs",
  "unpack", "tostring", "tonumber", "setmetatable", "getmetatable", "rawget", "rawset",
  "rawequal", "rawlen", "collectgarbage", "loadstring", "load", "require", "dofile",
  "loadfile", "getfenv", "setfenv", "newproxy", "coroutine",
  "string", "table", "math", "os", "io", "debug", "bit32", "utf8",
  "task", "buffer", "getgenv", "getrenv", "getsenv", "getreg",
  "hookfunction", "hookmetamethod", "getnamecallmethod", "getconnections",
  "getgc", "getinstances", "getnilinstances", "getscripts", "getloadedmodules",
  "getcallingscript", "getrawmetatable", "setrawmetatable", "checkcaller",
  "isreadonly", "setreadonly", "iscclosure", "islclosure", "newcclosure",
  "identifyexecutor", "lz4compress", "lz4decompress", "queue_on_teleport",
  "syn", "fluxus", "krnl", "self", "true", "false", "nil"
]);

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

function randChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randHexName(length = 6) {
  const chars = "0123456789abcdef";
  let out = "_0x";
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function preprocess(code) {
  code = code.replace(/--\[\[[\s\S]*?\]\]/g, "");
  code = code.replace(/--[^\n]*/g, "");
  code = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  code = code.split("\n").map(l => l.replace(/\s+$/, "")).join("\n");
  return code.trim();
}

function minify(code) {
  code = code.replace(/[ \t]+/g, " ");
  code = code.replace(/\n\s*\n/g, "\n");
  code = code.replace(/^\s+|\s+$/gm, "");
  return code;
}

function encryptString(str, key, shift) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    const k = key + ((i + shift) % 11);
    bytes.push((c ^ k) & 0xff);
  }
  return bytes;
}

function makeStringDecoder(varName, key, shift) {
  return `local function ${varName}(t) local k=${key} local s="" for i=1,#t do s=s..string.char(bit32.bxor(t[i],(k+((i-1+${shift})%11)))%256) end return s end`;
}

function bytesToLuaTable(bytes) {
  return "{" + bytes.join(",") + "}";
}

function encodeNumber(n) {
  if (!Number.isInteger(n) || n < 0 || n > 200000) return String(n);
  const variant = randInt(0, 5);
  switch (variant) {
    case 0: {
      const a = randInt(0, Math.max(1, n));
      return `(${a}+${n - a})`;
    }
    case 1: {
      if (n < 4) return String(n);
      const a = randInt(2, 7);
      const b = Math.floor(n / a);
      const c = n - a * b;
      return `(${a}*${b}${c >= 0 ? "+" + c : c})`;
    }
    case 2: {
      const offset = randInt(1, 500);
      return `(${n + offset}-${offset})`;
    }
    case 3: {
      const mask = randInt(1, 255);
      return `bit32.bxor(${n ^ mask},${mask})`;
    }
    case 4: {
      if (n === 0) return "0";
      const shift = randInt(1, 4);
      return `bit32.rshift(${n << shift},${shift})`;
    }
    case 5: {
      const base = randInt(1, Math.max(1, Math.floor(n / 2)));
      return `(${base}+${n - base})`;
    }
    default: return String(n);
  }
}

class RenameCtx {
  constructor() {
    this.map = new Map();
    this.counter = 0;
  }
  rename(name) {
    if (ROBLOX_GLOBALS.has(name)) return name;
    if (this.map.has(name)) return this.map.get(name);
    const newName = randHexName(6) + "_" + this.counter.toString(16);
    this.counter++;
    this.map.set(name, newName);
    return newName;
  }
  get(name) {
    if (ROBLOX_GLOBALS.has(name)) return name;
    return this.map.get(name) || name;
  }
}

function walkAst(node, ctx) {
  if (!node || typeof node !== "object") return;

  if (node.type === "StringLiteral" && typeof node.value === "string") {
    node.__obf = { type: "str", bytes: encryptString(node.value, ctx.stringKey, ctx.stringShift) };
    return;
  }

  if (node.type === "NumericLiteral" && typeof node.value === "number") {
    node.__obf = { type: "num", expr: encodeNumber(node.value) };
    return;
  }

  if (ctx.rename) {
    if (node.type === "LocalStatement" && Array.isArray(node.variables)) {
      node.variables.forEach(v => {
        if (v.type === "Identifier" && v.name) v.name = ctx.rename.rename(v.name);
      });
    }
    if (node.type === "FunctionDeclaration") {
      if (node.isLocal && node.identifier && node.identifier.type === "Identifier") {
        node.identifier.name = ctx.rename.rename(node.identifier.name);
      }
      if (Array.isArray(node.parameters)) {
        node.parameters.forEach(p => {
          if (p.type === "Identifier" && p.name) p.name = ctx.rename.rename(p.name);
        });
      }
    }
    if (node.type === "ForNumericStatement" && node.variable) {
      node.variable.name = ctx.rename.rename(node.variable.name);
    }
    if (node.type === "ForGenericStatement" && Array.isArray(node.variables)) {
      node.variables.forEach(v => { v.name = ctx.rename.rename(v.name); });
    }
  }

  for (const key in node) {
    if (key === "loc" || key === "range" || key === "__obf") continue;
    const child = node[key];
    if (Array.isArray(child)) child.forEach(c => walkAst(c, ctx));
    else if (child && typeof child === "object") walkAst(child, ctx);
  }

  if (ctx.rename && node.type === "Identifier" && node.name && ctx.rename.map.has(node.name)) {
    node.name = ctx.rename.map.get(node.name);
  }
}

function serialize(node) {
  if (!node) return "";
  if (node.__obf) {
    if (node.__obf.type === "str") return `_D(${bytesToLuaTable(node.__obf.bytes)})`;
    if (node.__obf.type === "num") return node.__obf.expr;
  }
  switch (node.type) {
    case "Chunk": return node.body.map(serialize).join("\n");
    case "LocalStatement": {
      const vars = node.variables.map(v => v.name).join(",");
      const inits = node.init.map(serialize).join(",");
      return `local ${vars}${inits ? "=" + inits : ""}`;
    }
    case "AssignmentStatement":
      return `${node.variables.map(serialize).join(",")}=${node.init.map(serialize).join(",")}`;
    case "CallStatement": return serialize(node.expression);
    case "CallExpression":
      return `${serialize(node.base)}(${node.arguments.map(serialize).join(",")})`;
    case "StringCallExpression": return `${serialize(node.base)}(${serialize(node.argument)})`;
    case "TableCallExpression": return `${serialize(node.base)}(${serialize(node.arguments)})`;
    case "Identifier": return node.name;
    case "StringLiteral": return JSON.stringify(node.value);
    case "NumericLiteral": return String(node.value);
    case "BooleanLiteral": return node.value ? "true" : "false";
    case "NilLiteral": return "nil";
    case "VarargLiteral": return "...";
    case "MemberExpression": return `${serialize(node.base)}${node.indexer}${node.identifier.name}`;
    case "IndexExpression": return `${serialize(node.base)}[${serialize(node.index)}]`;
    case "BinaryExpression":
    case "LogicalExpression":
      return `(${serialize(node.left)}${node.operator}${serialize(node.right)})`;
    case "UnaryExpression": return `(${node.operator} ${serialize(node.argument)})`;
    case "FunctionDeclaration": {
      const params = node.parameters.map(p => p.type === "VarargLiteral" ? "..." : p.name).join(",");
      const body = node.body.map(serialize).join("\n");
      const id = node.identifier ? serialize(node.identifier) : "";
      const localPrefix = node.isLocal ? "local " : "";
      return id ? `${localPrefix}function ${id}(${params})\n${body}\nend` : `function(${params})\n${body}\nend`;
    }
    case "IfStatement": {
      let out = "";
      node.clauses.forEach(clause => {
        if (clause.type === "IfClause") out += `if ${serialize(clause.condition)} then\n${clause.body.map(serialize).join("\n")}\n`;
        else if (clause.type === "ElseifClause") out += `elseif ${serialize(clause.condition)} then\n${clause.body.map(serialize).join("\n")}\n`;
        else if (clause.type === "ElseClause") out += `else\n${clause.body.map(serialize).join("\n")}\n`;
      });
      return out + "end";
    }
    case "WhileStatement":
      return `while ${serialize(node.condition)} do\n${node.body.map(serialize).join("\n")}\nend`;
    case "RepeatStatement":
      return `repeat\n${node.body.map(serialize).join("\n")}\nuntil ${serialize(node.condition)}`;
    case "ForNumericStatement": {
      const step = node.step ? "," + serialize(node.step) : "";
      return `for ${node.variable.name}=${serialize(node.start)},${serialize(node.end)}${step} do\n${node.body.map(serialize).join("\n")}\nend`;
    }
    case "ForGenericStatement":
      return `for ${node.variables.map(v => v.name).join(",")} in ${node.iterators.map(serialize).join(",")} do\n${node.body.map(serialize).join("\n")}\nend`;
    case "DoStatement": return `do\n${node.body.map(serialize).join("\n")}\nend`;
    case "ReturnStatement": return `return ${node.arguments.map(serialize).join(",")}`;
    case "BreakStatement": return "break";
    case "TableConstructorExpression": {
      const fields = node.fields.map(f => {
        if (f.type === "TableKey") return `[${serialize(f.key)}]=${serialize(f.value)}`;
        if (f.type === "TableKeyString") return `${f.key.name}=${serialize(f.value)}`;
        return serialize(f.value);
      });
      return `{${fields.join(",")}}`;
    }
    default: return "";
  }
}

function wrapOpaquePredicate(code) {
  const trueConds = [
    "(#\"\"==0)",
    "((1+1)==2)",
    "((5*5)==25)",
    "((\"a\"..\"b\")==\"ab\")",
    "(type(1)==\"number\")",
    "(math.floor(1.5)==1)",
    "(string.len(\"x\")==1)"
  ];
  const cond = randChoice(trueConds);
  const junkVar = randHexName(5);
  const junk = `local ${junkVar}=${randInt(1, 999)}*${randInt(1, 999)} local ${randHexName(5)}=${randInt(0, 999)}+${randInt(0, 999)}`;
  return `if ${cond} then\n${code}\nelse\n${junk}\nend`;
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function encryptPayload(code, xorKey) {
  const bytes = [];
  for (let i = 0; i < code.length; i++) {
    const c = code.charCodeAt(i);
    const k = xorKey + (i % 17);
    bytes.push((c ^ k) & 0xff);
  }
  return bytesToBase64(bytes);
}

function makePayloadDecoder(varName, xorKey) {
  return [
    `local function ${varName}(s)`,
    `local b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"`,
    `local d={}`,
    `for i=1,#b do d[string.sub(b,i,i)]=i-1 end`,
    `local o={} local pad=0`,
    `if string.sub(s,-2)=="==" then pad=2 elseif string.sub(s,-1)=="=" then pad=1 end`,
    `s=string.gsub(s,"[^A-Za-z0-9+/=]","")`,
    `for i=1,#s,4 do`,
    `local a=d[string.sub(s,i,i)] or 0`,
    `local b1=d[string.sub(s,i+1,i+1)] or 0`,
    `local c=d[string.sub(s,i+2,i+2)] or 0`,
    `local e=d[string.sub(s,i+3,i+3)] or 0`,
    `local n=bit32.bor(bit32.lshift(a,18),bit32.lshift(b1,12),bit32.lshift(c,6),e)`,
    `table.insert(o,string.char(bit32.band(bit32.rshift(n,16),0xff)))`,
    `table.insert(o,string.char(bit32.band(bit32.rshift(n,8),0xff)))`,
    `table.insert(o,string.char(bit32.band(n,0xff)))`,
    `end`,
    `local r=table.concat(o)`,
    `if pad>0 then r=string.sub(r,1,#r-pad) end`,
    `local out={}`,
    `for i=1,#r do`,
    `out[i]=string.char(bit32.bxor(string.byte(r,i),(${xorKey}+((i-1)%17)))%256)`,
    `end`,
    `return table.concat(out)`,
    `end`
  ].join(" ");
}

async function obfuscate(luaCode, level = "medium") {
  try {
    let code = preprocess(luaCode);

    if (level === "none") return code;
    if (level === "basic") return minify(code);

    const ast = luaparse.parse(code, { luaVersion: "5.1", comments: false });

    const isMedium = level === "medium";
    const isMaximum = level === "maximum";

    const stringKey = randInt(30, 230);
    const stringShift = randInt(0, 10);
    const ctx = {
      stringKey,
      stringShift,
      rename: isMaximum ? new RenameCtx() : null,
    };
    walkAst(ast, ctx);

    let obfuscated = serialize(ast);
    const decoder = makeStringDecoder("_D", stringKey, stringShift);
    let combined = `${decoder}\n${obfuscated}`;

    if (isMedium) {
      return minify(combined);
    }

    combined = wrapOpaquePredicate(combined);
    combined = wrapOpaquePredicate(combined);

    const payloadXor = randInt(40, 240);
    const encPayload = encryptPayload(combined, payloadXor);
    const payloadDec = makePayloadDecoder("_P", payloadXor);
    const strVar = randHexName(7);
    const fnVar = randHexName(6);

    const finalCode = [
      payloadDec,
      `local ${strVar}="${encPayload}"`,
      `local _L=loadstring or load`,
      `local ${fnVar}=_L(_P(${strVar}))`,
      `if ${fnVar} then ${fnVar}() end`
    ].join("\n");

    return minify(finalCode);
  } catch (err) {
    console.error("[obfuscator] Error:", err.message);
    throw new Error("Failed to obfuscate: " + err.message);
  }
}

process.on("uncaughtException", (err) => {
  console.error("[obfuscator] Uncaught:", err.message);
});
process.on("unhandledRejection", (reason) => {
  console.error("[obfuscator] Unhandled:", reason);
});

module.exports = { obfuscate };
