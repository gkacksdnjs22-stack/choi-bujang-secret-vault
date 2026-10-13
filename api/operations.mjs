import {readFileSync} from 'node:fs';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../src/verify-login.mjs';
import {requestAuthorization} from '../src/session-cookie.mjs';
import {serverDeviceContext} from '../src/server-device.mjs';
import {enforceAppProof} from '../src/app-proof.mjs';
import {RULE_IDS} from '../src/decider.mjs';
import {traceRequest} from '../src/request-trace.mjs';
const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
let verify;
export default async function handler(req,res){
  const trace=traceRequest(res);res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET')return res.status(405).json({error:'읽기 전용 작전실입니다.'});
  if(new URL(req.url,'https://local.invalid').search)return res.status(400).json({error:'조회 범위를 바꿀 수 없습니다.'});
  const secret=process.env.SUPABASE_SECRET_KEY,url=process.env.SUPABASE_URL;
  if(!secret||!url||(process.env.RESOURCE_POLICY_MODE??'enforce')!=='enforce')return res.status(503).json({error:'서버 설정을 확인하세요.'});
  try{
    verify??=createLoginVerifier({config,supabaseSecretKey:secret});
    const identity=await verify(requestAuthorization(req,config));
    if(identity?.kind!=='student')return res.status(401).json({error:'본인 계정으로 로그인하세요.'});
    const context=serverDeviceContext(req,res,identity,config,secret);
    const db=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
    if(!await enforceAppProof({req,res,db,identity,config,context}))return res;
    const binding=await db.from('principal_bindings').select('enabled,expires_at')
      .eq('class_id',context.classId).eq('project_id',context.projectId).eq('subject_id',context.subjectId)
      .eq('device_id',context.deviceId).eq('user_id',identity.userId).maybeSingle();
    if(binding.error)return res.status(503).json({error:'접속 기록 조회 실패'});
    if(binding.data?.enabled!==true||!(Date.parse(binding.data.expires_at)>Date.now()))return res.status(403).json({error:'현재 등록된 접속만 허용합니다.'});
    const notes=await db.from('notes').select('public_id').eq('owner_id',identity.userId);
    if(notes.error)return res.status(503).json({error:'본인 자료 집계 실패'});
    const versions=[];
    for(const note of notes.data.slice(0,8)){
      const preview=await db.rpc('preview_private_note_recovery',{p_note_id:note.public_id,p_actor_id:identity.userId,
        p_class_id:context.classId,p_project_id:context.projectId,p_subject_id:context.subjectId,p_device_id:context.deviceId});
      if(preview.error||preview.data?.verified!==true){versions.push({state:'unavailable'});continue;}
      versions.push({state:'verified',version:preview.data.version,capturedAt:preview.data.capturedAt,
        changedFields:preview.data.changedFields});
    }
    return res.status(200).json({schema:'vault.operations.v1',...trace,source:'own_server_live',
      rules:[...RULE_IDS],registration:{state:'active',expiresAt:binding.data.expires_at},ownNoteCount:notes.data.length,
      recovery:{source:'stored_backup_read_verified',versions,inspected:versions.length,total:notes.data.length},
      detection:{state:'not_connected',eventCount:null,source:'operator_events_not_received'},
      revocation:{state:'not_executed',source:'current_binding_read_only'},
      officialTests:{total:41,executed:0,source:'official_individual_results_not_received'}});
  }catch{return res.status(503).json({error:'작전실 결과 조회 실패'});}
}
