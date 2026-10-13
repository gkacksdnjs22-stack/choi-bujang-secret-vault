import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decideOwnedResource } from '../src/ownership-decider.mjs';
import { fixtureRequests } from './fixture-7.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
const id = '00000000-0000-4000-8000-000000000001';
const { normal, suspicious } = fixtureRequests();
const request = { ...normal, at: new Date().toISOString(), subjectId: 'subject_A', path: `/api/notes/${id}`, route: 'GET /api/notes/:id' };
const rows = {
  principal_bindings: ['A','B'].map(user => ({ class_id: request.classId, project_id: request.projectId,
    subject_id: `subject_${user}`, device_id: request.deviceId, user_id: user, enabled: true,
    expires_at: new Date(Date.now() + 60000).toISOString() })),
  notes: [{ public_id: id, owner_id: 'A' }], instructor_memberships: [],
};
const db = { from(table) { const filters = []; return {
  select() { return this; }, eq(key,value) { filters.push(row => row[key] === value); return this; },
  async maybeSingle() { return { data: rows[table].find(row => filters.every(f => f(row))) ?? null, error: null }; },
}; } };
const check = (user, input = request) => decideOwnedResource({ db, config, identity: { userId: user }, request: input });
assert.equal((await check('A')).decision, 'allow');
assert.equal((await check('B', { ...request, subjectId: 'subject_B' })).decision, 'deny');
assert.equal((await check('B')).decision, 'deny');
for (const method of ['PUT','DELETE']) {
  assert.equal((await check('A', { ...request, method, route: `${method} /api/notes/:id` })).decision, 'allow');
  assert.equal((await check('B', { ...request, subjectId: 'subject_B', method, route: `${method} /api/notes/:id` })).decision, 'deny');
}
rows.notes[0].owner_id = 'B';
assert.equal((await check('A')).decision, 'deny');
rows.notes[0].owner_id = 'A';
rows.principal_bindings[0].enabled = false;
assert.equal((await check('A')).decision, 'deny');
rows.principal_bindings[0].enabled = true;
assert.equal((await check('A', { ...request, signals: suspicious.signals, recentEvents: suspicious.recentEvents })).decision, 'step_up');
assert.equal((await check('A', { ...request, service: 'announcements', path: `/api/announcements/${id}`, method: 'PUT', route: 'PUT /api/announcements/:id' })).decision, 'deny');
rows.principal_bindings[0].expires_at = '2020-01-01T00:00:00Z';
assert.equal((await check('A')).decision, 'deny');
console.log('관리자 연결 등록부 → 현재 소유권 조회 → 판정기 가상 통합 검증 통과. 이 시험은 운영 DB나 엔진을 호출하지 않습니다.');
