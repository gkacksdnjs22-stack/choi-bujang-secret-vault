import {readFileSync} from 'node:fs';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../../src/verify-login.mjs';
import {serverDeviceContext} from '../../src/server-device.mjs';
import {restorePrivateNote} from '../../src/recovery.mjs';
const config=JSON.parse(readFileSync(new URL('../../aleph.config.json',import.meta.url),'utf8'));
let verify;
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'POST가 필요합니다.'});}
  if((process.env.RESOURCE_POLICY_MODE??'enforce')!=='enforce')return res.status(503).json({error:'권한 설정을 확인하세요.'});
  const key=process.env.SUPABASE_SECRET_KEY,url=process.env.SUPABASE_URL;
  if(!key||!url)return res.status(503).json({error:'복구 서버 설정이 필요합니다.'});
  try {
    verify??=createLoginVerifier({config,supabaseSecretKey:key});
    const identity=await verify(req.headers?.authorization);
    if(!identity)return res.status(401).json({error:'로그인이 필요합니다.'});
    const path=new URL(req.url,'https://local.invalid');
    const match=/^\/api\/restore\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(path.pathname);
    const body=typeof req.body==='string'?JSON.parse(req.body):req.body;
    if(!match||path.search||(body!=null&&(typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)))
      return res.status(400).json({error:'자료 ID 한 개만 지정하세요.'});
    const context=serverDeviceContext(req,res,identity,config,key);
    const db=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
    return res.status(200).json(await restorePrivateNote({db,noteId:match[1],identity,context}));
  }catch(error){
    if(error.message==='restore_unavailable')return res.status(503).json({error:'복구 DB 설정이 필요합니다.'});
    return res.status(403).json({error:'사본·소유권·등록 상태를 확인하세요.',reasonCode:'restore_rejected'});
  }
}
