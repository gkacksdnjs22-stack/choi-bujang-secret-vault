import {createHash,createHmac,createPublicKey,randomUUID,timingSafeEqual,verify} from 'node:crypto';
import {serverDeviceContext} from './server-device.mjs';
const hash=value=>createHash('sha256').update(value).digest('hex');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function canonicalBody(value){
  if(typeof value==='string')value=JSON.parse(value);
  const normalize=x=>Array.isArray(x)?x.map(normalize):x&&typeof x==='object'
    ?Object.fromEntries(Object.keys(x).sort().map(key=>[key,normalize(x[key])])):x;
  const text=JSON.stringify(normalize(value??null));
  if(text.length>30000)throw Error('app_proof_invalid');return text;
}
export function proofTarget(url){
  const target=new URL(url,'https://local.invalid');
  const id=target.pathname.split('/').at(-1);
  // 플랫폼이 동적 경로에서 삽입하는 동일 ID만 제거합니다. 다른 쿼리는 서명에 포함합니다.
  for(const key of ['id','noteId'])if(target.searchParams.getAll(key).length===1&&target.searchParams.get(key)===id
    &&/^[a-f0-9-]{36}$/i.test(id))target.searchParams.delete(key);
  return target.pathname+target.search;
}
export function proofMessage({method,url,body,certificate,time,nonce}){
  return JSON.stringify(['vault-app-proof-v1',method,proofTarget(url),hash(canonicalBody(body)),hash(certificate),time,nonce]);
}
function safePublicKey(publicKey){
  if(!publicKey||publicKey.kty!=='EC'||publicKey.crv!=='P-256'||publicKey.d!==undefined
    ||!['x','y'].every(key=>typeof publicKey[key]==='string'&&/^[A-Za-z0-9_-]{43}$/.test(publicKey[key])))throw Error('app_proof_invalid');
  const key={kty:'EC',crv:'P-256',x:publicKey.x,y:publicKey.y};createPublicKey({key,format:'jwk'});return key;
}
const seal=(payload,secret)=>createHmac('sha256',secret).update('vault-app-certificate-v1\n'+payload).digest('hex');
export function issueAppCertificate({publicKey,identity,context,secret,expiresAt,now=Date.now()}){
  const exp=Math.min(expiresAt,now+600000);
  if(!identity?.userId||!Number.isSafeInteger(exp)||exp<=now||!secret)throw Error('app_proof_invalid');
  const payload=Buffer.from(JSON.stringify({schema:'vault-app-certificate-v1',id:randomUUID(),user:identity.userId,
    class:context.classId,project:context.projectId,subject:context.subjectId,device:context.deviceId,
    publicKey:safePublicKey(publicKey),exp})).toString('base64url');
  return {certificate:payload+'.'+seal(payload,secret),expiresAt:exp};
}
export async function verifyAppProof({req,db,identity,context,secret,now=Date.now(),observe=()=>{}}){
  let stage="headers";
  try{
    const certificate=req.headers?.['x-vault-app-certificate'];
    const signature=req.headers?.['x-vault-app-signature'];
    const time=req.headers?.['x-vault-app-time'],nonce=req.headers?.['x-vault-app-nonce'];
    if(typeof certificate!=='string'||certificate.length>4096||typeof signature!=='string'
      ||!/^[A-Za-z0-9_-]{86}$/.test(signature)||typeof time!=='string'||!/^\d{13}$/.test(time)
      ||Math.abs(now-Number(time))>30000||!uuid.test(nonce??''))return (observe(stage),false);
    stage='certificate';
    const [payload,mac,...extra]=certificate.split('.');
    if(extra.length||!/^[a-f0-9]{64}$/.test(mac??'')||!timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(seal(payload,secret),'hex')))return (observe(stage),false);
    const cert=JSON.parse(Buffer.from(payload,'base64url').toString());
    if(cert.schema!=='vault-app-certificate-v1'||!uuid.test(cert.id)||cert.user!==identity.userId
      ||cert.class!==context.classId||cert.project!==context.projectId||cert.subject!==context.subjectId||cert.device!==context.deviceId
      ||!Number.isSafeInteger(cert.exp)||cert.exp<=now||cert.exp>now+600000)return (observe(stage),false);
    stage='signature';
    const key=createPublicKey({key:safePublicKey(cert.publicKey),format:'jwk'});
    if(!verify('sha256',Buffer.from(proofMessage({method:req.method,url:req.url,body:req.body,certificate,time,nonce})),
      {key,dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url')))return (observe(stage),false);
    stage='nonce';
    const {data,error}=await db.rpc('consume_app_request_nonce',{p_certificate_id:cert.id,p_nonce:nonce,p_expires_at:new Date(cert.exp).toISOString()});
    if(error||data!==true)return (observe(stage),false);return true;
  }catch{return (observe(stage),false);}
}
export async function enforceAppProof({req,res,db,identity,config,context}){
  if(config.step<11)return true;
  const secret=process.env.SUPABASE_SECRET_KEY;
  context??=serverDeviceContext(req,res,identity,config,secret);
  let proofStage;
  if(await verifyAppProof({req,db,identity,context,secret,observe:value=>{proofStage=value;}}))return true;
  res.status(403).json({error:'요청 서명을 다시 확인하세요.',reasonCode:'app_proof_invalid',proofStage});return false;
}
