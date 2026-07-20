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
  "loadfile", "getfenv", "setfenv", "newproxy",
  "string", "table", "math", "os", "io", "coroutine", "debug", "bit32", "utf8",
  "task", "buffer",
  "self",
]);

function randKey(bits = 8) {
  return crypto.randomBytes(bits)[0];
}

function randInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

function randChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function preprocess(code) {
  code = code.replace(/--\[\[[\s\S]*?\]\]/g, "");
  code = code.replace(/--[^\n]*/g, "");
  code = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return code.trim();
}

function minify(code) {
  code = code.replace(/[ \t]+/g, " ");
  code = code.replace(/\n\s*\n/g, "\n");
  code = code.replace(/^\s+|\s+$/gm, "");
  code = code.replace(/\s*([=+\-*/%<>~^&|,;(){}[\]])\s*/g, "$1");
  return code;
}

function encryptStringXOR(str, key, shift) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    const keyByte = key + ((i + shift) % 11);
    bytes.push((charCode ^ keyByte) & 0xff);
  }
  return bytes;
}

function makeDecoderLua(varName, key, shift) {
  return `local function ${varName}(t)local k=${key} local s='' for i=1,#t do s=s..string.char((t[i]~(k+((i-1+${shift})%11)))&0xff) end return s end`;
}

function bytesToLuaTable(bytes) {
  return "{" + bytes.join(",") + "}";
}

function encodeNumber(n, complexity = 1) {
  if (!Number.isInteger(n) || n < 0 || n > 200000) {
    return String(n);
  }
  if (complexity === 0) return String(n);

  const variant = Math.floor(Math.random() * (complexity >= 2 ? 6 : 4));

  switch (variant) {
    case 0: {
      const a = Math.floor(Math.random() * Math.max(1, n));
      const b = n - a;
      return `(${a}+${b})`;
    }
    case 1: {
      if (n < 4) return String(n);
      const a = 2 + Math.floor(Math.random() * 5);
      const b = Math.floor(n / a);
      const c = n - a * b;
      return `(${a}*${b}${c >= 0 ? "+" + c : c})`;
    }
    case 2: {
      const offset = 1 + Math.floor(Math.random() * 200);
      return `(${n + offset}-${offset})`;
    }
    case 3: {
      const mask = Math.floor(Math.random() * 255);
      return `(${n ^ mask}~${mask})`;
    }
    case 4: {
      const shift = randInt(1, 8);
      return `((${n << shift})>>${shift})`;
    }
    case 5: {
      const or1 = n | randInt(0, 15);
      const and1 = n & 0xffff;
      return `(${n}|(${or1}&${and1}~${n}))`;
    }
    default:
      return String(n);
  }
}

function makeOpaqueChars() {
  const parts = [];
  const len = randInt(6, 14);
  const chars = "lI1O0";
  for (let i = 0; i < len; i++) {
    parts.push(chars[Math.floor(Math.random() * chars.length)]);
  }
  return parts.join("");
}

class RenameContext {
  constructor(seed) {
    this.map = new Map();
    this.counter = 0;
    this.seed = seed;
  }

  rename(originalName) {
    if (ROBLOX_GLOBALS.has(originalName)) return originalName;
    if (this.map.has(originalName)) return this.map.get(originalName);
    const newName = "_" + makeOpaqueChars() + this.counter.toString(16);
    this.counter++;
    this.map.set(originalName, newName);
    return newName;
  }

  get(originalName) {
    if (ROBLOX_GLOBALS.has(originalName)) return originalName;
    return this.map.get(originalName) || originalName;
  }
}

function walkAst(node, ctx) {
  if (!node || typeof node !== "object") return;

  if (node.type === "StringLiteral" && typeof node.value === "string") {
    const bytes = encryptStringXOR(node.value, ctx.stringKey, ctx.stringShift);
    node.__obfuscated = {
      type: "encrypted_string",
      bytes: bytes,
    };
    return;
  }

  if (node.type === "NumericLiteral" && typeof node.value === "number") {
    node.__obfuscated = {
      type: "encoded_number",
      expression: encodeNumber(node.value, ctx.numberComplexity),
    };
    return;
  }

  if (ctx.renameEnabled && ctx.renameCtx) {
    if (node.type === "LocalStatement" && Array.isArray(node.variables)) {
      node.variables.forEach((v) => {
        if (v.type === "Identifier" && v.name) {
          v.name = ctx.renameCtx.rename(v.name);
        }
      });
    }

    if (node.type === "FunctionDeclaration") {
      if (node.isLocal && node.identifier && node.identifier.type === "Identifier") {
        node.identifier.name = ctx.renameCtx.rename(node.identifier.name);
      }
      if (Array.isArray(node.parameters)) {
        node.parameters.forEach((p) => {
          if (p.type === "Identifier" && p.name) {
            p.name = ctx.renameCtx.rename(p.name);
          }
        });
      }
    }

    if (node.type === "ForNumericStatement" && node.variable) {
      node.variable.name = ctx.renameCtx.rename(node.variable.name);
    }

    if (node.type === "ForGenericStatement" && Array.isArray(node.variables)) {
      node.variables.forEach((v) => {
        v.name = ctx.renameCtx.rename(v.name);
      });
    }
  }

  for (const key in node) {
    if (key === "loc" || key === "range" || key === "__obfuscated") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      child.forEach((c) => walkAst(c, ctx));
    } else if (child && typeof child === "object") {
      walkAst(child, ctx);
    }
  }

  if (ctx.renameEnabled && ctx.renameCtx && node.type === "Identifier" && node.name) {
    if (ctx.renameCtx.map.has(node.name)) {
      node.name = ctx.renameCtx.map.get(node.name);
    }
  }
}

function serialize(node) {
  if (!node) return "";

  if (node.__obfuscated) {
    if (node.__obfuscated.type === "encrypted_string") {
      return `_D(${bytesToLuaTable(node.__obfuscated.bytes)})`;
    }
    if (node.__obfuscated.type === "encoded_number") {
      return node.__obfuscated.expression;
    }
  }

  switch (node.type) {
    case "Chunk":
      return node.body.map(serialize).join("\n");

    case "LocalStatement": {
      const vars = node.variables.map((v) => v.name).join(",");
      const inits = node.init.map(serialize).join(",");
      return `local ${vars}${inits ? "=" + inits : ""}`;
    }

    case "AssignmentStatement": {
      const lhs = node.variables.map(serialize).join(",");
      const rhs = node.init.map(serialize).join(",");
      return `${lhs}=${rhs}`;
    }

    case "CallStatement":
      return serialize(node.expression);

    case "CallExpression": {
      const base = serialize(node.base);
      const args = node.arguments.map(serialize).join(",");
      return `${base}(${args})`;
    }

    case "StringCallExpression":
      return `${serialize(node.base)}(${serialize(node.argument)})`;

    case "TableCallExpression":
      return `${serialize(node.base)}(${serialize(node.arguments)})`;

    case "Identifier":
      return node.name;

    case "StringLiteral":
      return JSON.stringify(node.value);

    case "NumericLiteral":
      return String(node.value);

    case "BooleanLiteral":
      return node.value ? "true" : "false";

    case "NilLiteral":
      return "nil";

    case "VarargLiteral":
      return "...";

    case "MemberExpression":
      return `${serialize(node.base)}${node.indexer}${node.identifier.name}`;

    case "IndexExpression":
      return `${serialize(node.base)}[${serialize(node.index)}]`;

    case "BinaryExpression":
    case "LogicalExpression":
      return `(${serialize(node.left)}${node.operator}${serialize(node.right)})`;

    case "UnaryExpression":
      return `(${node.operator} ${serialize(node.argument)})`;

    case "FunctionDeclaration": {
      const params = node.parameters
        .map((p) => (p.type === "VarargLiteral" ? "..." : p.name))
        .join(",");
      const body = node.body.map(serialize).join("\n");
      const identifier = node.identifier ? serialize(node.identifier) : "";
      const localPrefix = node.isLocal ? "local " : "";
      if (identifier) {
        return `${localPrefix}function ${identifier}(${params})\n${body}\nend`;
      }
      return `function(${params})\n${body}\nend`;
    }

    case "IfStatement": {
      let out = "";
      node.clauses.forEach((clause) => {
        if (clause.type === "IfClause") {
          out += `if ${serialize(clause.condition)} then\n${clause.body.map(serialize).join("\n")}\n`;
        } else if (clause.type === "ElseifClause") {
          out += `elseif ${serialize(clause.condition)} then\n${clause.body.map(serialize).join("\n")}\n`;
        } else if (clause.type === "ElseClause") {
          out += `else\n${clause.body.map(serialize).join("\n")}\n`;
        }
      });
      out += "end";
      return out;
    }

    case "WhileStatement":
      return `while ${serialize(node.condition)} do\n${node.body.map(serialize).join("\n")}\nend`;

    case "RepeatStatement":
      return `repeat\n${node.body.map(serialize).join("\n")}\nuntil ${serialize(node.condition)}`;

    case "ForNumericStatement": {
      const variable = node.variable.name;
      const start = serialize(node.start);
      const end = serialize(node.end);
      const step = node.step ? "," + serialize(node.step) : "";
      const body = node.body.map(serialize).join("\n");
      return `for ${variable}=${start},${end}${step} do\n${body}\nend`;
    }

    case "ForGenericStatement": {
      const vars = node.variables.map((v) => v.name).join(",");
      const iters = node.iterators.map(serialize).join(",");
      const body = node.body.map(serialize).join("\n");
      return `for ${vars} in ${iters} do\n${body}\nend`;
    }

    case "DoStatement":
      return `do\n${node.body.map(serialize).join("\n")}\nend`;

    case "ReturnStatement":
      return `return ${node.arguments.map(serialize).join(",")}`;

    case "BreakStatement":
      return "break";

    case "TableConstructorExpression": {
      const fields = node.fields.map((f) => {
        if (f.type === "TableKey") {
          return `[${serialize(f.key)}]=${serialize(f.value)}`;
        }
        if (f.type === "TableKeyString") {
          return `${f.key.name}=${serialize(f.value)}`;
        }
        return serialize(f.value);
      });
      return `{${fields.join(",")}}`;
    }

    default:
      return "";
  }
}

function wrapWithOpaquePredicates(code) {
  const trueConditions = [
    "((#'')==0)",
    "((1+1)==2)",
    "((5*5)==25)",
    "(('a'..'b')=='ab')",
    "((type(1))=='number')",
    "((math.floor(1.5))==1)",
    "((string.len('x'))==1)",
  ];
  const cond = randChoice(trueConditions);
  const junkVar = "_" + makeOpaqueChars();
  const junk = `local ${junkVar}=${randInt(1, 999)}*${randInt(1, 999)}`;
  return `if ${cond} then\n${code}\nelse\n${junk}\nend`;
}

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function makePayloadDecoderLua(varName, xorKey) {
  const decoder = [
    `local function ${varName}(s)`,
    `local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'`,
    `local d={}`,
    `for i=1,#b do d[b:sub(i,i)]=i-1 end`,
    `local o={}`,
    `local pad=0`,
    `if s:sub(-2)=='==' then pad=2 elseif s:sub(-1)=='=' then pad=1 end`,
    `s=s:gsub('[^A-Za-z0-9+/=]','')`,
    `for i=1,#s,4 do`,
    `local a=d[s:sub(i,i)] or 0`,
    `local b1=d[s:sub(i+1,i+1)] or 0`,
    `local c=d[s:sub(i+2,i+2)] or 0`,
    `local e=d[s:sub(i+3,i+3)] or 0`,
    `local n=(a<<18)|(b1<<12)|(c<<6)|e`,
    `o[#o+1]=string.char((n>>16)&0xff)`,
    `o[#o+1]=string.char((n>>8)&0xff)`,
    `o[#o+1]=string.char(n&0xff)`,
    `end`,
    `local r=table.concat(o)`,
    `if pad>0 then r=r:sub(1,#r-pad) end`,
    `local out={}`,
    `for i=1,#r do`,
    `out[i]=string.char((r:byte(i)~(${xorKey}+((i-1)%13)))&0xff)`,
    `end`,
    `return table.concat(out)`,
    `end`,
  ].join(" ");
  return decoder;
}

function encryptPayload(code, xorKey) {
  const bytes = [];
  for (let i = 0; i < code.length; i++) {
    const c = code.charCodeAt(i);
    const k = xorKey + (i % 13);
    bytes.push((c ^ k) & 0xff);
  }
  return bytesToBase64(bytes);
}

function obfuscate(luaCode, level = "medium") {
  try {
    let code = preprocess(luaCode);

    if (level === "none") {
      return code;
    }

    if (level === "basic") {
      return minify(code);
    }

    const ast = luaparse.parse(code, {
      luaVersion: "5.3",
      comments: false,
    });

    const isMaximum = level === "maximum";

    const stringKey = randInt(30, 230);
    const stringShift = randInt(0, 10);
    const ctx = {
      stringKey,
      stringShift,
      numberComplexity: isMaximum ? 2 : 1,
      renameEnabled: isMaximum,
      renameCtx: isMaximum ? new RenameContext(stringKey) : null,
    };

    walkAst(ast, ctx);

    let obfuscated = serialize(ast);
    const decoder = makeDecoderLua("_D", stringKey, stringShift);
    let combined = `${decoder}\n${obfuscated}`;

    if (!isMaximum) {
      return combined;
    }

    combined = wrapWithOpaquePredicates(combined);

    const payloadXor = randInt(40, 240);
    const encryptedPayload = encryptPayload(combined, payloadXor);
    const payloadDecoder = makePayloadDecoderLua("_P", payloadXor);
    const wrapperVar = "_" + makeOpaqueChars();
    const strVar = "_" + makeOpaqueChars();

    const antiDebug = [
      `local ${wrapperVar}=function()`,
      `if debug and debug.getinfo then`,
      `local ok=pcall(function() return debug.getinfo(1) end)`,
      `if not ok then return end`,
      `end`,
      `end`,
      `${wrapperVar}()`,
    ].join(" ");

    const finalCode = [
      antiDebug,
      payloadDecoder,
      `local ${strVar}="${encryptedPayload}"`,
      `local _L=loadstring or load`,
      `local _F=_L(_P(${strVar}))`,
      `if _F then _F() end`,
    ].join("\n");

    return finalCode;
  } catch (err) {
    console.error("Obfuscation error:", err.message);
    throw new Error("Failed to obfuscate: " + err.message);
  }
}

module.exports = { obfuscate };
