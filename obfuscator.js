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

function randInt(min,max){return min+Math.floor(Math.random()*(max-min+1));}
function randChoice(a){return a[Math.floor(Math.random()*a.length)];}
function randHexName(len){
  len=len||6;
  const c="0123456789abcdef";
  let o="_0x";
  for(let i=0;i<len;i++)o+=c[Math.floor(Math.random()*c.length)];
  return o;
}

function preprocess(code){
  code=code.replace(/--\[\[[\s\S]*?\]\]/g,"");
  code=code.replace(/--[^\n]*/g,"");
  code=code.replace(/\r\n/g,"\n").replace(/\r/g,"\n");
  code=code.split("\n").map(l=>l.replace(/\s+$/,"")).join("\n");
  return code.trim();
}

// v5.4 FINAL FIX: Continuation-aware minifier
// Checks BOTH prev line's ending AND current line's beginning before inserting ';'
// Prevents breaking multi-line expressions common in Luau/Roblox scripts:
//   - `if x\n  and y then` (word op continuation)
//   - `game\n  :GetService()` (method chain continuation)
//   - `"a"\n  .. "b"` (concat continuation)
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
    // Prev line ends with block-opener or operator â†’ no ;
    if(/\b(do|then|else|repeat)\s*$/.test(prev))addSemi=false;
    else if(/[=,{(\[+\-*/%<>~^&|.:;]$/.test(prev))addSemi=false;
    else if(/\b(and|or|not|in|return|local|elseif)\s*$/.test(prev))addSemi=false;
    else if(/\)\s*$/.test(prev)&&/\bfunction\b/.test(prev)&&!/\bend\s*\)\s*$/.test(prev))addSemi=false;
    // Current line begins with continuation token â†’ no ;
    else if(/^(and|or|not)\b/.test(line))addSemi=false;
    else if(/^[.:,)\]}+\-*/%<>=~^&|]/.test(line))addSemi=false;
    else if(/^(then|do|else|elseif|end|until)\b/.test(line))addSemi=false;
    if(addSemi)result[result.length-1]=prev+";";
    result.push(line);
  }
  let out=result.join(" ");
  out=out.replace(/  +/g," ").replace(/;\s*;/g,";").replace(/;\s*end\b/g," end").replace(/;\s*\)/g,")").replace(/;\s*until\b/g," until").replace(/;\s*elseif\b/g," elseif").replace(/;\s*else\b/g," else").replace(/;\s*then\b/g," then").replace(/;\s*do\b/g," do").replace(/;\s*(and|or)\b/g," $1").replace(/;\s*(\.\.|:|\.)/g," $1");
  return out.trim();
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

function generateJunkOps(count){
  const ops=[];
  for(let i=0;i<count;i++){
    const v=randHexName(4);
    const op=randChoice([
      "local "+v+"="+randInt(1,999)+"*"+randInt(1,999),
      "local "+v+"="+randInt(0,999)+"+"+randInt(0,999),
      "local "+v+"=math.floor("+randInt(100,9999)+"/"+randInt(2,9)+")",
      "local "+v+"=bit32.bxor("+randInt(0,255)+","+randInt(0,255)+")",
      "local "+v+"=string.rep('"+randChoice(["x","a","z","q"])+"',"+randInt(1,5)+")",
      "local "+v+"={"+randInt(1,999)+","+randInt(1,999)+","+randInt(1,999)+"}"
    ]);
    ops.push(op);
  }
  return ops.join("; ");
}

function generateOpaquePredicate(payload){
  const conds=[
    "((2*3)==6)",
    "(math.floor(1.5)==1)",
    "(string.len('x')==1)",
    "(#'ab'==2)",
    "(bit32.band(15,15)==15)",
    "(((1+1)==2) and ((3-1)==2))",
    "(type(1)=='number')"
  ];
  const c1=randChoice(conds);
  const c2=randChoice(conds);
  const junkV=randHexName(4);
  return "if "+c1+" and "+c2+" then "+payload+" else local "+junkV+"="+randInt(1,999)+"*"+randInt(1,999)+" end";
}

function generateAntiTamper(){
  const wrapper=randHexName(6);
  const chk1=randHexName(5);
  const chk2=randHexName(5);
  const flag=randHexName(4);
  return "local "+wrapper+"=function() local "+flag+"=true local "+chk1+"=pcall(function() return bit32.bxor(15,15)==0 end) local "+chk2+"=pcall(function() return (type(game)=='userdata') or (type(game)=='table') or true end) if not "+chk1+" then "+flag+"=false end if not "+chk2+" then "+flag+"=false end return "+flag+" end "+wrapper+"()";
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

function byteLevelTripleObfuscate(code,level){
  const minified=aggressiveMinify(code);
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
  const junk1=generateJunkOps(randInt(10,20));
  const junk2=generateJunkOps(randInt(5,15));

  const execCore="local _L=loadstring or load; local "+execVar+","+errVar+"=_L("+realDec+"("+strVar+")); if "+execVar+" then local _ok,_err=pcall("+execVar+"); if (not _ok) and _err then warn('[AzureVM] Runtime: '..tostring(_err)) end else if "+errVar+" then warn('[AzureVM] Compile: '..tostring("+errVar+")) end end";

  const parts=[];
  if(level==="maximum")parts.push(generateAntiTamper());
  parts.push(junk1);
  parts.push(fakeDecs);
  parts.push(decoder);
  parts.push("local "+strVar+"=\""+encPayload+"\"");
  parts.push(generateOpaquePredicate(execCore));
  parts.push(junk2);
  return parts.join("; ");
}

async function obfuscate(luaCode,level){
  level=level||"medium";
  try{
    let code=preprocess(luaCode);
    if(level==="none")return code;
    if(level==="basic")return aggressiveMinify(code);

    let ast=null;
    try{
      ast=luaparse.parse(code,{luaVersion:"5.1",comments:false});
    }catch(e1){
      try{
        ast=luaparse.parse(code,{luaVersion:"5.3",comments:false});
      }catch(e2){
        console.warn("[obfuscator] Parse failed, using byte-level fallback");
      }
    }

    if(!ast){
      return byteLevelTripleObfuscate(code,level);
    }

    const isMedium=level==="medium";
    const isMaximum=level==="maximum";
    const stringKey=randInt(30,230);
    const stringShift=randInt(0,10);
    const ctx={stringKey,stringShift,rename:isMaximum?new RenameCtx():null};
    walkAst(ast,ctx);
    let ob=serialize(ast);
    const decoder=makeStringDecoder("_D",stringKey,stringShift);
    let combined=decoder+"; "+ob;

    if(isMedium)return combined;

    return byteLevelTripleObfuscate(combined,level);
  }catch(err){
    console.error("[obfuscator] Error:",err.message);
    try{
      return byteLevelTripleObfuscate(preprocess(luaCode),level);
    }catch(e){
      throw new Error("Failed to obfuscate: "+err.message);
    }
  }
}

process.on("uncaughtException",(e)=>{console.error("[obfuscator] Uncaught:",e.message);});
process.on("unhandledRejection",(r)=>{console.error("[obfuscator] Unhandled:",r);});

module.exports={obfuscate};
