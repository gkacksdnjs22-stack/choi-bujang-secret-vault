import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from './fixture-7.mjs';
import { apiResourceTarget, resourceRouteAllowed } from '../src/resource-routes.mjs';
const routeConfig = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
assert.equal(resourceRouteAllowed(routeConfig, 'notes', 'GET', 'example'), true);
assert.equal(resourceRouteAllowed(routeConfig, 'notes', 'PUT', 'example'), true);
assert.equal(resourceRouteAllowed(routeConfig, 'notes', 'PATCH', 'example'), false);
assert.equal(resourceRouteAllowed({ allowedRoutes: [] }, 'notes', 'GET', 'example'), false);
const wrongZone = structuredClone(routeConfig);
wrongZone.allowedRoutes.find(r => r.pathPattern === '/api/notes/:id' && r.method === 'GET').zone = 'class-notices';
assert.equal(resourceRouteAllowed(wrongZone, 'notes', 'GET', 'example'), false);
const duplicateRoute = structuredClone(routeConfig);
duplicateRoute.allowedRoutes.push(duplicateRoute.allowedRoutes.find(r => r.pathPattern === '/api/notes/:id' && r.method === 'GET'));
assert.equal(resourceRouteAllowed(duplicateRoute, 'notes', 'GET', 'example'), false);
const id = '00000000-0000-4000-8000-000000000001';
const { normal } = fixtureRequests();
const isolated = await import(`data:text/javascript;base64,${readFileSync(new URL('../src/decider.mjs', import.meta.url)).toString('base64')}`);
assert.equal((await isolated.decide(normal)).decision, 'allow');
assert.equal((await isolated.decide({ ...normal, subjectId: 'other_learner_fixture' })).decision, 'deny');
assert.equal((await isolated.decide({ ...normal, path: '/notes/export' })).decision, 'deny');
for (const [path, route, method, expected] of [
  ['/notes/demo', 'GET /notes/:id', 'GET', 'allow'],
  ['/notes/demo', 'PUT /notes/:id', 'PUT', 'allow'],
  [`/notes/${id}`, 'GET /notes/:id', 'GET', 'deny'],
  [`/notes/${id}`, 'PUT /notes/:id', 'PUT', 'deny'],
  ['/notes/export', 'GET /notes/:id', 'GET', 'deny'],
  [`/notes/${id}/export`, 'GET /notes/:id', 'GET', 'deny'],
  [`/notes/${id}`, 'GET /notes/:id', 'DELETE', 'deny'],
  ['/other-zone', 'GET /notes', 'GET', 'deny'],
  [`/announcements/${id}`, 'PUT /announcements/:id', 'PUT', 'deny'],
  [`/announcements/${id}`, 'GET /announcements/:id', 'GET', 'deny'],
]) assert.equal((await decide({ ...normal, path, route, method })).decision, expected);
assert.equal((await decide({ ...normal, queryLength: 12 })).decision, 'deny');
for (const url of ['/api/notes/export', `/api/notes/${id}/export`, '/api/notes?action=export', '/api/notes?owner_id=B']) {
  assert.equal(apiResourceTarget({ url }, 'notes').invalid, true);
}

const stores = {
  notes: [{ public_id: id, owner_id: 'A', title: 'fixture', content: 'fixture' }],
  announcements: [{ public_id: id, title: 'fixture', content: 'fixture' }],
  instructor_memberships: [{ user_id: 'I', enabled: true }],
};
class Query {
  constructor(table) { this.table = table; this.filters = []; this.action = 'select'; }
  select() { return this; } order() { return this; }
  eq(key, value) { this.filters.push(row => row[key] === value); return this; }
  maybeSingle() { this.single = true; return this; }
  update(value) { this.action = 'update'; this.value = value; return this; }
  insert(value) { this.action = 'insert'; this.value = value; return this; }
  delete() { this.action = 'delete'; return this; }
  then(resolve) {
    let found = stores[this.table].filter(row => this.filters.every(fn => fn(row)));
    if (this.action === 'update') found.forEach(row => Object.assign(row, this.value));
    if (this.action === 'insert') { stores[this.table].push(this.value); found = [this.value]; }
    if (this.action === 'delete') stores[this.table] = stores[this.table].filter(row => !found.includes(row));
    return Promise.resolve({ data: this.single ? found[0] ?? null : found, error: null }).then(resolve);
  }
}
globalThis.__resourceTest = {
  createClient: () => ({ from: table => new Query(table) }),
  createLoginVerifier: () => async header => ['A', 'B', 'I'].includes(header) ? { userId: header } : null,
};
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@supabase/supabase-js') return { url: 'data:text/javascript,export const createClient=globalThis.__resourceTest.createClient', shortCircuit: true };
  if (specifier.endsWith('/verify-login.mjs')) return { url: 'data:text/javascript,export const createLoginVerifier=globalThis.__resourceTest.createLoginVerifier', shortCircuit: true };
  return next(specifier, context);
} });
process.env.SUPABASE_URL = 'https://local-test.invalid';
process.env.SUPABASE_SECRET_KEY = 'local-test-placeholder';
const { default: notes } = await import('../api/notes.mjs');
const { default: announcements } = await import('../api/announcements.mjs');
async function request(handler, user, method, url, body) {
  const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(value) { this.value = value; return this; } };
  await handler({ method, url, query: {}, headers: { authorization: user }, body }, res);
  return res;
}
assert.equal((await request(notes, 'A', 'GET', `/api/notes/${id}`)).value.resourceId, `notes:${id}`);
assert.equal((await request(notes, 'A', 'PUT', `/api/notes/${id}`, { title: 'own edit', body: 'fixture' })).code, 200);
assert.equal((await request(notes, 'A', 'GET', `/api/notes?id=${id}`)).code, 200);
assert.equal((await request(notes, 'B', 'GET', `/api/notes?id=${id}`)).code, 404);
assert.equal((await request(notes, 'A', 'PATCH', `/api/notes/${id}`, {})).code, 403);
assert.equal((await request(notes, 'A', 'GET', '/api/notes?action=export')).code, 400);
for (const method of ['GET', 'PUT', 'DELETE']) assert.equal((await request(notes, 'B', method, `/api/notes/${id}`, { title: 'x', body: 'fixture' })).code, 404);
assert.deepEqual((await request(notes, 'B', 'GET', '/api/notes')).value, []);
assert.equal((await request(announcements, 'A', 'GET', `/api/announcements/${id}`)).value.resourceId, `announcements:${id}`);
for (const method of ['POST', 'PUT', 'DELETE']) assert.equal((await request(announcements, 'A', method, `/api/announcements/${id}`, { role: 'instructor', title: 'x', body: 'fixture' })).code, 403);
assert.equal((await request(announcements, 'I', 'PUT', `/api/announcements/${id}`, { title: 'x', body: 'fixture' })).code, 200);
assert.equal((await request(announcements, 'I', 'PUT', `/api/announcements/${id}`, { role: 'instructor', title: 'x', body: 'fixture' })).code, 400);
assert.equal((await request(announcements, '', 'GET', '/api/announcements')).code, 401);
console.log('8단계: 정확한 자원 경로·타인 메모 차단·학생 공지 쓰기 거부·저장된 강사 권한 검증 통과 (로컬 가상 DB)');
