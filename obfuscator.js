// ==========================================
// Luraph-Inspired Lua Obfuscator - Backend Engine
// Layers 1-3: Preprocessing, String Encryption, Number Encoding
// ==========================================

const luaparse = require("luaparse");

// ==========================================
// LAYER 1: Preprocessing
// ==========================================
function preprocess(code) {
  code = code.replace(/--\[\[[\s\S]*?\]\]/g, "");
  code = code.replace(/--[^\n]*/g, "");
  code = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  code = code
    .split("\n")
    .map((line) => line.replace(/\s+$/, ""))
    .join("\n");
  return code.trim();
}

// ==========================================
// LAYER 2: String Encryption (XOR + rotating key)
// ==========================================
function encryptString(str, key) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    const keyByte = key + (i % 7);
    bytes.push((charCode ^ keyByte) & 0xff);
  }
  return bytes;
}

function makeStringDecoderLua(varName, key) {
  return `local function ${varName}(t)local k=${key} local s='' for i=1,#t do s=s..string.char((t[i]~(k+((i-1)%7)))&0xff) end return s end`;
}

function bytesToLuaTable(bytes) {
  return "{" + bytes.join(",") + "}";
}

// ==========================================
// LAYER 3: Number Encoding
// ==========================================
function encodeNumber(n) {
  if (!Number.isInteger(n) || n < 0 || n > 100000) {
    return String(n);
  }

  const variant = Math.floor(Math.random() * 4);

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
      const offset = 1 + Math.floor(Math.random() * 100);
      return `(${n + offset}-${offset})`;
    }
    case 3: {
      const mask = Math.floor(Math.random() * 255);
      return `(${n ^ mask}~${mask})`;
    }
    default:
      return String(n);
  }
}

// ==========================================
// AST Walker
// ==========================================
function walkAst(node, ctx) {
  if (!node || typeof node !== "object") return;

  if (node.type === "StringLiteral" && typeof node.value === "string") {
    const bytes = encryptString(node.value, ctx.stringKey);
    node.__obfuscated = {
      type: "encrypted_string",
      bytes: bytes,
    };
    return;
  }

  if (node.type === "NumericLiteral" && typeof node.value === "number") {
    if (Number.isInteger(node.value) && node.value >= 0 && node.value <= 100000) {
      node.__obfuscated = {
        type: "encoded_number",
        expression: encodeNumber(node.value),
      };
    }
    return;
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
}

// ==========================================
// Serializer - Convert AST back to Lua
// ==========================================
function serialize(node) {
  if (!node) return "";

  if (node.__obfuscated) {
    if (node.__obfuscated.type === "encrypted_string") {
      const bytesLua = bytesToLuaTable(node.__obfuscated.bytes);
      return `_D(${bytesLua})`;
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
      return `${serialize(node.base)}${serialize(node.argument)}`;

    case "TableCallExpression":
      return `${serialize(node.base)}${serialize(node.arguments)}`;

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
      return `(${node.operator}${serialize(node.argument)})`;

    case "FunctionDeclaration": {
      const params = node.parameters.map((p) => (p.name ? p.name : "...")).join(",");
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

// ==========================================
// MAIN OBFUSCATE FUNCTION
// ==========================================
function obfuscate(luaCode, level = "medium") {
  try {
    let code = preprocess(luaCode);

    if (level === "none") {
      return code;
    }

    const ast = luaparse.parse(code, {
      luaVersion: "5.3",
      comments: false,
    });

    const stringKey = 30 + Math.floor(Math.random() * 200);
    const ctx = { stringKey };
    walkAst(ast, ctx);

    const obfuscated = serialize(ast);
    const decoder = makeStringDecoderLua("_D", stringKey);

    return `${decoder}\n${obfuscated}`;
  } catch (err) {
    console.error("Obfuscation error:", err);
    throw new Error("Failed to obfuscate: " + err.message);
  }
}

module.exports = { obfuscate };
