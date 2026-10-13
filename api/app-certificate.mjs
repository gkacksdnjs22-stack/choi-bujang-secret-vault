import {readFileSync} from 'node:fs';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../src/verify-login.mjs';
import {requestAuthorization} from '../src/session-cookie.mjs';
import {serverDeviceContext} from '../src/server-device.mjs';
import {issueAppCertificate} from '../src/app-proof.mjs';
const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
let verify;
export default async function handler(req,res){
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST')return res.status(405).json({error:'POST만 가능합니다.'});
  const secret=process.env.SUPABASE_SECRET_KEY,url=process.env.SUPABASE_URL;
  if(!secret||!url||(process.env.RESOURCE_POLICY_MODE??'enforce')!=='enforce')return res.status(503).json({error:'서버 설정을 확인하세요.'});
  try{
    verify??=createLoginVerifier({config,supabaseSecretKey:secret});
    const identity=await verify(requestAuthorization(req,config));
    if(!identity)return res.status(401).json({error:'로그인이 필요합니다.'});
    const context=serverDeviceContext(req,res,identity,config,secret);
    const db=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data,error}=await db.from('principal_bindings').select('expires_at')
      .eq('class_id',context.classId).eq('project_id',context.projectId).eq('subject_id',context.subjectId)
      .eq('device_id',context.deviceId).eq('user_id',identity.userId).eq('enabled',true).maybeSingle();
    if(error||!data||!Number.isFinite(Date.parse(data.expires_at))||Date.parse(data.expires_at)<=Date.now())return res.status(403).json({error:'현재 승인된 기기만 요청 서명을 연결할 수 있습니다.'});
    const body=typeof req.body==='string'?JSON.parse(req.body):req.body;
    if(!body||Object.keys(body).some(key=>key!=='publicKey'))return res.status(400).json({error:'공개키만 전달하세요.'});
    return res.status(200).json(issueAppCertificate({publicKey:body.publicKey,identity,context,secret,expiresAt:Date.parse(data.expires_at)}));
  }catch{return res.status(400).json({error:'요청 서명 연결을 확인하세요.'});}
}
