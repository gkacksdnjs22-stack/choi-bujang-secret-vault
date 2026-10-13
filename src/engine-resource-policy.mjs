import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { decideOwnedResource } from './ownership-decider.mjs';

const keys = ['schema','requestId','classId','projectId','subjectId','deviceId','service','method','path','route',
  'queryLength','querySha256','at','policyRevision','deviceRegistered','stepUp','recentEvents','signals'];
const emptyQuery = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const deny = request => ({schema:'aleph.decision.v1',requestId:request?.requestId,decision:'deny',
  reasonCode:request?.deviceRegistered === true ? 'policy_denied' : 'device_not_registered',
  ruleIds:[request?.deviceRegistered === true ? 'resource_zone' : 'device_registered']});

// trustedUserId는 서명 검증한 API 로그인에서만 전달하는 내부 인자입니다.
// 엔진 진입점에서는 관리자 등록부가 가명 주체를 현재 사용자에 연결합니다.
export function createEngineDecision({db, config}) {
  return async function decision(request, trustedUserId) {
    if (!request || Object.keys(request).sort().join() !== [...keys].sort().join()
      || request.schema !== 'aleph.decision.v1' || request.deviceRegistered !== true
      || !/^[a-f0-9]{16}$/.test(request.deviceId ?? '')
      || ['requestId','classId','projectId','subjectId'].some(key => typeof request[key] !== 'string' || !request[key])
      || request.queryLength !== 0 || request.querySha256 !== emptyQuery
      || !Number.isInteger(request.policyRevision) || request.policyRevision < 1
      || !Number.isFinite(Date.parse(request.at)) || Math.abs(Date.now()-Date.parse(request.at)) > 5000) return deny(request);
    const match = /^\/(api\/)?(notes|announcements)(?:\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?$/i.exec(request.path ?? '');
    if (!match || request.service !== match[2]
      || request.route !== `${request.method} /${match[1] ?? ''}${match[2]}${match[3] ? '/:id' : ''}`
      || !(match[3] ? ['GET','PUT','DELETE'] : ['GET','POST']).includes(request.method)) return deny(request);
    // 엔진의 /notes 경로와 API의 /api/notes는 같은 자원 ID로 정규화합니다.
    const normalized = {...request, path:`/api/${match[2]}${match[3] ? '/'+match[3] : ''}`,
      route:`${request.method} /api/${match[2]}${match[3] ? '/:id' : ''}`};
    try {
      const {data, error} = await db.from('principal_bindings').select('user_id,expires_at')
        .eq('class_id', request.classId).eq('project_id', request.projectId)
        .eq('subject_id', request.subjectId).eq('device_id', request.deviceId).eq('enabled',true).maybeSingle();
      if (error || !data?.user_id || Date.parse(data.expires_at) <= Date.now()
        || !Number.isFinite(Date.parse(data.expires_at))
        || (trustedUserId !== undefined && trustedUserId !== data.user_id)) return deny(request);
      return await decideOwnedResource({db,config,identity:{userId:data.user_id},request:normalized});
    } catch { return deny(request); }
  };
}

export async function runtimeDecision(request) {
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return deny(request);
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
  const db = createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
  return createEngineDecision({db,config})(request);
}
