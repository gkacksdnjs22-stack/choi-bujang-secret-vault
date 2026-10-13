// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 신원·기기·경로의 선행 검사는 엔진이 담당합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

// 모든 진입점이 같은 권한 대조를 사용합니다. 연습용 자료도 예외로 허용하지 않습니다.
function permittedResourceRoute(request, grants = []) {
  if (!['notes', 'announcements'].includes(request.service) || typeof request.subjectId !== 'string' || !request.subjectId
      || !/^[a-f0-9]{16}$/.test(request.deviceId ?? '')) return false;
  // 계약은 쿼리 원문을 주지 않습니다. 기능 선택인지 확인할 수 없는 쿼리는 허용하지 않습니다.
  if (request.queryLength !== 0) return false;
  return grants.some(grant => ['classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route']
    .every(key => grant[key] === request[key])
    && Date.parse(request.at) < Date.parse(grant.expiresAt));
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

// 서버가 구성하는 정책 입력입니다. 브라우저 요청에서 grants를 가져오지 않습니다.
export function createDecider(grants) {
  if (!Array.isArray(grants)) throw new TypeError('권한 목록이 필요합니다.');
  const keys = ['classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route', 'expiresAt'];
  const snapshot = grants.map(grant => {
    if (!grant || Object.keys(grant).sort().join() !== [...keys].sort().join()
      || keys.some(key => typeof grant[key] !== 'string' || !grant[key])
      || !/^[a-f0-9]{16}$/.test(grant.deviceId)
      || !Number.isFinite(Date.parse(grant.expiresAt))) throw new TypeError('유효하지 않은 권한입니다.');
    const match = /^\/(api\/)?(notes|announcements)(?:\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?$/i.exec(grant.path);
    if (!match || grant.service !== match[2]
      || !(match[3] ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST']).includes(grant.method)
      || grant.route !== `${grant.method} /${match[1] ?? ''}${match[2]}${match[3] ? '/:id' : ''}`) throw new TypeError('정확한 자료 경로가 필요합니다.');
    return Object.freeze({ ...grant });
  });
  return request => decideWithGrants(request, snapshot);
}

export async function decide(request) {
  // 엔진이 확인한 18개 항목만 받습니다. HTTP 본문을 이 함수에 직접 연결하지 않습니다.
  // 실제 서버 등록부를 매번 조회합니다. 연결/등록 실패를 연습용 허용으로 대신하지 않습니다.
  if (request?.deviceRegistered === true) {
    try {
      const { runtimeDecision } = await import('./engine-resource-policy.mjs');
      return await runtimeDecision(request);
    } catch { /* 독립 격리 실행 또는 서버 연결 실패는 거부 */ }
  }
  return decideWithGrants(request ?? {}, []);
}

async function decideWithGrants(request, grants) {
  const registered = request.deviceRegistered === true;
  if (registered && !permittedResourceRoute(request, grants)) return {
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
