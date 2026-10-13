import {traceRequest} from '../src/request-trace.mjs';
import {requestAuthorization} from '../src/session-cookie.mjs';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { serverDeviceContext } from '../src/server-device.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
let verify;
export default async function handler(req, res) {
  traceRequest(res);
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET','POST'].includes(req.method)) return res.status(405).json({ error: '조회 또는 승인 요청만 가능합니다.' });
  const secret = process.env.SUPABASE_SECRET_KEY, url = process.env.SUPABASE_URL;
  if (!secret || !url) return res.status(503).json({ error: '서버 연결 설정이 필요합니다.' });
  try {
    verify ??= createLoginVerifier({ config, supabaseSecretKey: secret });
    const identity = await verify(requestAuthorization(req,config));
    if (identity?.kind !== 'student') return res.status(401).json({ error: '본인 계정으로 로그인하세요.' });
    const context = serverDeviceContext(req, res, identity, config, secret);
    const db = createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
    if(req.method==='POST'){
      const body=typeof req.body==='string'?JSON.parse(req.body):req.body;
      if(body!=null&&(typeof body!=='object'||Array.isArray(body)||Object.keys(body).length))return res.status(400).json({error:'승인 정보는 서버가 확인합니다.'});
      const {requestId,...scope}=context;
      const {error}=await db.from('device_approval_requests').upsert({class_id:scope.classId,project_id:scope.projectId,
        subject_id:scope.subjectId,device_id:scope.deviceId,user_id:identity.userId,requested_at:new Date().toISOString()},
        {onConflict:'class_id,project_id,subject_id,device_id,user_id'});
      if(error)return res.status(503).json({error:'승인 요청을 저장할 수 없습니다.'});
      return res.status(202).json({requested:true,registered:false});
    }
    const { data, error } = await db.from('principal_bindings').select('enabled,expires_at')
      .eq('class_id', context.classId).eq('project_id', context.projectId).eq('subject_id', context.subjectId)
      .eq('device_id', context.deviceId).eq('user_id', identity.userId).maybeSingle();
    if (error) return res.status(503).json({ error: '연결 상태를 조회할 수 없습니다.' });
    const { requestId, ...registration } = context;
    return res.status(200).json({ ...registration, userId: identity.userId,
      registered: data?.enabled === true && Date.parse(data.expires_at) > Date.now(),
      deviceType: 'signed_browser_cookie' });
  } catch { return res.status(503).json({ error: '연결 상태를 확인할 수 없습니다.' }); }
}
