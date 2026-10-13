import { serverDeviceContext } from './server-device.mjs';
import { decideOwnedResource } from './ownership-decider.mjs';

export async function enforceServerResourcePolicy({ req, res, db, config, identity, resource, id }) {
  // 기존 사이트는 명시적으로 활성화하기 전까지 유지합니다. 알 수 없는 모드는 거부합니다.
  const mode = process.env.RESOURCE_POLICY_MODE ?? 'off';
  if (mode === 'off') return true;
  if (mode !== 'enforce') { res.status(503).json({ error: '권한 설정을 확인하세요.' }); return false; }
  const context = serverDeviceContext(req, res, identity, config, process.env.SUPABASE_SECRET_KEY);
  const { data: registration, error } = await db.from('principal_bindings').select('user_id,expires_at')
    .eq('class_id', context.classId).eq('project_id', context.projectId).eq('subject_id', context.subjectId)
    .eq('device_id', context.deviceId).eq('user_id', identity.userId).eq('enabled', true).maybeSingle();
  const registered = !error && registration?.user_id === identity.userId && Date.parse(registration.expires_at) > Date.now();
  // 자체 서버에서 검증한 로그인·서명 쿠키로 만든 요청입니다. 브라우저 role/신호를 복사하지 않습니다.
  const request = { schema: 'aleph.decision.v1', ...context, service: resource, method: req.method,
    path: `/api/${resource}${id ? `/${id}` : ''}`, route: `${req.method} /api/${resource}${id ? '/:id' : ''}`,
    queryLength: 0, querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at: new Date().toISOString(), policyRevision: 1, deviceRegistered: registered,
    stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [], signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 0 } };
  // 연결 등록 상태는 관리자 등록부의 현재 값으로 결정합니다.
  const decision = await decideOwnedResource({ db, config, identity, request });
  if (decision.decision === 'allow') return true;
  res.status(403).json({ error: '등록된 접속과 자료 접근 권한을 확인하세요.', reasonCode: decision.reasonCode });
  return false;
}
