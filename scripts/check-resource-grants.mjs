import assert from 'node:assert/strict';
import { createDecider } from '../src/decider.mjs';
import { fixtureRequests } from './fixture-7.mjs';
import { issueResourceGrant } from '../src/resource-grants.mjs';

const { normal, suspicious } = fixtureRequests();
const request = { ...normal, subjectId: 'subject_A', path: '/api/notes/00000000-0000-4000-8000-000000000001', route: 'GET /api/notes/:id' };
const grant = Object.fromEntries(['classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route'].map(key => [key, request[key]]));
grant.expiresAt = new Date(Date.parse(request.at) + 60000).toISOString();
const granted = createDecider([grant]);
assert.equal((await granted(request)).decision, 'allow');
for (const [key, value] of [['subjectId', 'subject_B'], ['classId', 'other_class'], ['projectId', 'other_project'], ['deviceId', 'b'.repeat(16)], ['method', 'PUT'], ['path', request.path.replace(/1$/, '2')], ['route', 'GET /api/notes']]) {
  assert.equal((await granted({ ...request, [key]: value })).decision, 'deny', key);
}
assert.equal((await granted({ ...request, at: grant.expiresAt })).decision, 'deny');
assert.equal((await granted({ ...request, deviceRegistered: false })).decision, 'deny');
assert.equal((await granted({ ...request, signals: suspicious.signals, recentEvents: suspicious.recentEvents })).decision, 'step_up');
assert.equal((await createDecider([])(request)).decision, 'deny');
grant.subjectId = 'subject_B';
assert.equal((await granted({ ...request, subjectId: 'subject_B' })).decision, 'deny');
assert.throws(() => createDecider([{ ...grant, path: '/api/notes/export' }]));
assert.throws(() => createDecider([{ ...grant, role: 'instructor' }]));
const binding = { userId: 'A', ...Object.fromEntries(['classId', 'projectId', 'subjectId', 'deviceId'].map(key => [key, request[key]])) };
const db = { from(table) {
  const filters = {};
  return { select() { return this; }, eq(key, value) { filters[key] = value; return this; },
    async maybeSingle() { return { error: null, data: table === 'notes' && filters.owner_id === 'A'
      && filters.public_id === request.path.split('/').at(-1) ? { public_id: filters.public_id } : null }; } };
} };
const fresh = { ...request, at: new Date().toISOString() };
const issued = await issueResourceGrant(db, { userId: 'A' }, binding, fresh);
assert.ok(issued);
assert.equal((await createDecider([issued])(fresh)).decision, 'allow');
assert.equal(await issueResourceGrant(db, { userId: 'B' }, { ...binding, userId: 'B' }, fresh), null);
assert.equal(await issueResourceGrant(db, { userId: 'B' }, binding, fresh), null);
assert.equal(await issueResourceGrant(db, { userId: 'A' }, binding, { ...fresh, at: '2020-01-01T00:00:00Z' }), null);
console.log('서버 권한 등록부 가상 검증: A 허용, B·다른 기기·자료·동작 차단, 만료·회수·위험 재인증 통과. 실제 계정 연결은 별도입니다.');
