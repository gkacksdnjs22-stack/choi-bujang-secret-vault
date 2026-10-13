import assert from 'node:assert/strict';
import { createDecider, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests, fixtureGrant } from './fixture-7.mjs';

const { normal, suspicious } = fixtureRequests();
const decide = createDecider([fixtureGrant(normal)]);
let count = 0;
async function check(request, decision, reasonCode) {
  const result = await decide(request);
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(result.requestId, request.requestId);
  assert.equal(result.decision, decision);
  if (reasonCode) assert.equal(result.reasonCode, reasonCode);
  assert.ok(result.ruleIds.every(id => RULE_IDS.includes(id)));
  count++;
}

// 어느 한 위험 신호만으로는 정상 사용자를 추가 확인으로 보내지 않습니다.
await check({ ...normal, signals: { ...normal.signals, region: 'foreign' } }, 'allow');
await check({ ...suspicious, signals: { ...suspicious.signals, hour: 14 } }, 'allow');
await check({ ...suspicious, signals: { ...suspicious.signals, network: 'usual' } }, 'allow');
await check({ ...suspicious, recentEvents: [] }, 'allow');
await check({ ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 301, count: 20 }] }, 'allow');
await check({ ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 9 }] }, 'allow');
await check({ ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 300, count: 10 }] }, 'step_up');

// 미등록 기기는 추가 인증 여부와 무관하게 거부합니다.
await check({ ...suspicious, deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 60 } }, 'deny', 'device_not_registered');
for (const age of [0, 900]) {
  await check({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } }, 'allow');
}
for (const age of [-1, 901, null, '60', 0.5]) {
  await check({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } }, 'step_up', 'step_up_required');
}
await check({ ...suspicious, stepUp: { verified: false, authAgeSeconds: 60 } }, 'step_up');

// 누락·출처 불명 신호를 정상값으로 만들지 않으며 클라이언트 헤더도 읽지 않습니다.
await check({ ...normal, signals: undefined }, 'step_up');
await check({ ...normal, signals: { ...normal.signals, source: 'client' } }, 'step_up');
await check({ ...normal, signals: { ...normal.signals, hour: null } }, 'step_up');
await check({ ...normal, recentEvents: undefined }, 'step_up');
await check({ ...normal, headers: { 'x-region': 'foreign', 'x-risk': 'high' } }, 'allow');
await check({ ...suspicious, headers: { 'x-step-up-verified': 'true' } }, 'step_up');
await check({ ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null } }, 'allow');
console.log(`7단계 가상 요청 경계·출처·기기 우선순위 ${count}건 통과 (운영 연결 시험 아님)`);
