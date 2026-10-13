// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 신원·기기·경로의 선행 검사는 엔진이 담당합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { permittedResourceRoute } from './resource-routes.mjs';
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

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
