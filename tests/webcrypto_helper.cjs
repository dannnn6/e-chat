// Test-only helper. Generated private keys exist only in the test subprocess payload.
const {webcrypto:crypto}=require('node:crypto');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const b64=b=>Buffer.from(b).toString('base64url');
const unb64=s=>new Uint8Array(Buffer.from(s,'base64url'));
const sha=async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex');
(async()=>{
 const packet=JSON.parse(fs.readFileSync(0,'utf8'));
 let result;
 if(packet.op==='keys'){
  const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const device=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  result={rootPrivateKey:b64(await crypto.subtle.exportKey('pkcs8',root.privateKey)),rootPublicKey:b64(await crypto.subtle.exportKey('spki',root.publicKey)),devicePublicKey:b64(await crypto.subtle.exportKey('spki',device.publicKey))};
 }else if(packet.op==='sign'){
  const key=await crypto.subtle.importKey('pkcs8',unb64(packet.privateKey),{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  result={signature:b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,new TextEncoder().encode(packet.transcript)))};
 }else if(packet.op==='validate'){
  const source=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
  const start=source.indexOf('async function validateChallenge('),end=source.indexOf('\nasync function updateQueued',start);
  if(start<0||end<0)throw new Error('Client validator not found');
  const context=vm.createContext({crypto,unb64,sha,encoder:new TextEncoder(),location:{origin:packet.origin},packet});
  vm.runInContext(source.slice(start,end),context);
  try{await vm.runInContext('validateChallenge(packet.challenge,packet.expected)',context);result={valid:true};}
  catch(error){result={valid:false,error:error.message};}
 }else throw new Error('Unknown operation');
 console.log(JSON.stringify(result));
})().catch(error=>{console.error(error.message);process.exitCode=1;});