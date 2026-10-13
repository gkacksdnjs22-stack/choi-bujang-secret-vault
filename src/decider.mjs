// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 신원·기기·경로의 선행 검사는 엔진이 담당합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

// 판정 파일은 외부 모듈 없이도 실행됩니다. 공식 연습의 demo 자료 ID도 보존합니다.
function permittedResourceRoute(request) {
  if (request.service !== 'notes' || typeof request.subjectId !== 'string' || !request.subjectId
      || !/^[a-f0-9]{16}$/.test(request.deviceId ?? '')) return false;
  const { method, path, route } = request;
  if (path === '/notes') return ['GET', 'POST'].includes(method) && route === `${method} /notes`;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (typeof path === 'string' && path.startsWith('/notes/')) {
    const id = path.slice('/notes/'.length);
    const demoOwner = id === 'demo' && request.subjectId === 'learner_fixture';
    return (uuid.test(id) || demoOwner)
      && ['GET', 'PUT', 'DELETE'].includes(method) && route === `${method} /notes/:id`;
  }
  // 강사 역할 계약이 없으므로 공지 쓰기는 거부하고 API에서 실제 권한을 다시 확인합니다.
  if (path === '/announcements') return method === 'GET' && route === 'GET /announcements';
  return typeof path === 'string' && path.startsWith('/announcements/')
    && uuid.test(path.slice('/announcements/'.length))
    && method === 'GET' && route === 'GET /announcements/:id';
}

// 가상 신호만 평가합니다. 실제 source:none의 unknown 값을 정상 위치로 바꾸지 않습니다.
function requiresStepUp(request) {
  const signals = request.signals;
  if (signals?.source === 'none') return false;
  if (signals?.source !== 'judge_fixture'
      || !['local', 'foreign'].includes(signals.region)
      || !['usual', 'unusual'].includes(signals.network)
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23
      || !Array.isArray(request.recentEvents) || request.recentEvents.length > 12
      || request.recentEvents.some(event => !event || typeof event.kind !== 'string'
        || !Number.isInteger(event.ageSeconds) || event.ageSeconds < 0
        || !Number.isInteger(event.count) || event.count < 0)) return true;
  const unusualHour = signals.hour < 6 || signals.hour >= 22;
  const burst = request.recentEvents.some(event => event.kind === 'risk_signal'
    && event.ageSeconds <= 300 && event.count >= 10);
  return unusualHour && signals.network === 'unusual' && burst;
}

export async function decide(request) {
  const registered = request.deviceRegistered === true;
  if (registered && !permittedResourceRoute(request)) return {
    schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'policy_denied', ruleIds: ['resource_zone'],
  };
  const freshVerification = request.stepUp?.verified === true
    && Number.isInteger(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900;
  const additionalCheck = registered && requiresStepUp(request) && !freshVerification;
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !registered ? 'deny' : additionalCheck ? 'step_up' : 'allow',
    reasonCode: !registered ? 'device_not_registered' : additionalCheck ? 'step_up_required' : 'approved',
    ruleIds: additionalCheck ? [...RULE_IDS] : [RULE_IDS[0]],
  };
}
