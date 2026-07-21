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

// v6.0 VM OPCODES (randomized each obfuscation)
const OP_NAMES = ["PUSH_CONST","PUSH_NIL","PUSH_TRUE","PUSH_FALSE","PUSH_GLOBAL","SET_GLOBAL","DUP","POP","CALL","RETURN","ADD","SUB","MUL","DIV","MOD","POW","CONCAT","EQ","NEQ","LT","LE","GT","GE","NOT","NEG","LEN","JMP","JMP_IF_FALSE","JMP_IF_TRUE","NEW_TABLE","SET_INDEX","GET_INDEX","GET_MEMBER","SET_MEMBER","METHOD_CALL","HALT"];

function randInt(min,max){return min+Math.floor(Math.random()*(max-min+1));}
function randChoice(a){return a[Math.floor(Math.random()*a.length)];}
function randHexName(len){
  len=len||6;
  const c="0123456789abcdef";
  let o="_0x";
  for(let i=0;i<len;i++)o+=c[Math.floor(Math.random()*c.length)];
  return o;
}

// Randomize opcodes each run â€” same handler logic, different numeric codes
// Deobfuscator can't hardcode opcode meanings
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

// v5.5 string-aware preprocessor (unchanged)
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

// ============================================================
// v6.0 VM COMPILER â€” compiles simple AST nodes to bytecode
// Only handles VM-safe patterns; complex nodes fall through to text mode
// ============================================================
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
    if(node.indexer===":"){
      // method access â€” treat like member for later METHOD_CALL
      bc.push(OP.GET_MEMBER,idx);
    } else {
      bc.push(OP.GET_MEMBER,idx);
    }
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

// Generate the VM interpreter as Lua code (randomized opcodes injected)
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
    +"end end end";
}

// Encode bytecode as base64 string of packed bytes
function packBytecode(bc){
  // Simple pack: each int as 2 bytes big-endian (max 65535 per int)
  const bytes=[];
  for(const n of bc){
    const v = (typeof n === "number") ? Math.max(0, Math.min(65535, n|0)) : 0;
    bytes.push((v>>8)&0xff, v&0xff);
  }
  return Buffer.from(bytes).toString("base64");
}

// Generate the unpacker: takes base64 -> array of ints
function makeBytecodeUnpacker(fnName){
  return "local function "+fnName+"(s) local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' local d={} for i=1,#b do d[string.sub(b,i,i)]=i-1 end local o={} local pad=0 if string.sub(s,-2)=='==' then pad=2 elseif string.sub(s,-1)=='=' then pad=1 end s=string.gsub(s,'[^A-Za-z0-9+/=]','') local raw={} for i=1,#s,4 do local a=d[string.sub(s,i,i)] or 0 local b1=d[string.sub(s,i+1,i+1)] or 0 local c=d[string.sub(s,i+2,i+2)] or 0 local e=d[string.sub(s,i+3,i+3)] or 0 local n=bit32.bor(bit32.lshift(a,18),bit32.lshift(b1,12),bit32.lshift(c,6),e) table.insert(raw,bit32.band(bit32.rshift(n,16),0xff)) table.insert(raw,bit32.band(bit32.rshift(n,8),0xff)) table.insert(raw,bit32.band(n,0xff)) end for i=1,pad do table.remove(raw) end local out={} for i=1,#raw,2 do table.insert(out,bit32.bor(bit32.lshift(raw[i],8),raw[i+1] or 0)) end return out end";
}

// Encode constants as Lua table literal
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

// ============================================================
// v5.5 encryption primitives (unchanged)
// ============================================================
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
    "((2*3)==6)","(math.floor(1.5)==1)","(string.len('x')==1)","(#'ab'==2)",
    "(bit32.band(15,15)==15)","(((1+1)==2) and ((3-1)==2))","(type(1)=='number')"
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

// ============================================================
// v6.0 HYBRID VM WRAPPER
// Wraps a subset of top-level statements in VM bytecode
// Rest of the script stays in AST-serialized form
// ============================================================
function tryVmWrap(ast, level){
  if(!ast || !ast.body || ast.body.length === 0) return null;
  
  const OP = makeOpTable();
  const bc = [];
  const consts = [];
  const globals = [];
  const vmStatements = [];
  const passthrough = [];
  
  // Compile only VM-safe top-level call statements to bytecode
  // Everything else goes through normal AST path
  let compiledCount = 0;
  const MAX_VM_STATEMENTS = 30; // limit to keep bytecode manageable
  
  for(const stmt of ast.body){
    if(compiledCount < MAX_VM_STATEMENTS && vmCanCompile(stmt)){
      vmCompileStmt(stmt, bc, consts, globals, OP);
      compiledCount++;
      vmStatements.push(stmt);
    } else {
      passthrough.push(stmt);
    }
  }
  
  if(compiledCount === 0) return null; // nothing to VM-compile
  
  bc.push(OP.HALT);
  
  // Build the VM harness
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
    
    // v6.0: Try VM wrapping for maximum level BEFORE encryption
    // If VM can compile some top-level calls, extract them; rest goes through AST path
    let vmPrefix = "";
    if(isMaximum){
      const vmResult = tryVmWrap(ast, level);
      if(vmResult && vmResult.compiledCount > 0){
        vmPrefix = vmResult.vmHarness + "; ";
        // Replace ast body with just the passthrough stmts
        ast.body = vmResult.passthrough;
        console.log("[obfuscator] VM-compiled",vmResult.compiledCount,"statements");
      }
    }
    
    const stringKey=randInt(30,230);
    const stringShift=randInt(0,10);
    const ctx={stringKey,stringShift,rename:isMaximum?new RenameCtx():null};
    walkAst(ast,ctx);
    let ob=serialize(ast);
    const decoder=makeStringDecoder("_D",stringKey,stringShift);
    let combined=decoder+"; "+vmPrefix+ob;

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
