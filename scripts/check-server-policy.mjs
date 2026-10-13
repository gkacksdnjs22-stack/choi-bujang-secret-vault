import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { serverDeviceContext } from '../src/server-device.mjs';
import { enforceServerResourcePolicy } from '../src/server-resource-policy.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
process.env.SUPABASE_SECRET_KEY = 'local-fixture-key';
process.env.RESOURCE_POLICY_MODE = 'enforce';
const secret = process.env.SUPABASE_SECRET_KEY;
const id = '00000000-0000-4000-8000-000000000001';
const response = () => ({ headers: {}, setHeader(k,v) { this.headers[k] = v; }, status(code) { this.code = code; return this; }, json(value) { this.value = value; return this; } });
const first = response();
const context = serverDeviceContext({ headers: {} }, first, { userId:'A' }, config, secret);
const cookie = first.headers['Set-Cookie'].split(';')[0];
assert.match(first.headers['Set-Cookie'], /HttpOnly; Secure; SameSite=Strict/);
assert.equal(serverDeviceContext({ headers: { cookie } }, response(), { userId:'A' }, config, secret).deviceId, context.deviceId);
const otherContext = serverDeviceContext({ headers: { cookie } }, response(), { userId:'B' }, config, secret);
assert.equal(otherContext.deviceId, context.deviceId);
assert.notEqual(otherContext.subjectId, context.subjectId);
const registrations = [{ class_id: context.classId, project_id: context.projectId, subject_id: context.subjectId,
  device_id: context.deviceId, user_id:'A', enabled:true, expires_at:new Date(Date.now()+60000).toISOString() }];
const tables = { principal_bindings:registrations, notes:[{public_id:id,owner_id:'A'}], instructor_memberships:[] };
const db = { from(table) { const filters=[]; return { select() { return this; }, eq(k,v) {filters.push(r=>r[k]===v);return this;},
  async maybeSingle() {return {data:tables[table].find(r=>filters.every(f=>f(r)))??null,error:null};} }; } };
const run = async (user='A', headers={cookie}, method='GET', target=id) => {
  const res=response(); const allowed=await enforceServerResourcePolicy({req:{headers,method},res,db,config,identity:{userId:user},resource:'notes',id:target});
  return {allowed,res};
};
assert.equal((await run()).allowed,true);
assert.equal((await run('B')).allowed,false);
assert.equal((await run('A',{cookie:cookie.slice(0,-1)+'x'})).allowed,false);
tables.notes[0].owner_id='B'; assert.equal((await run()).allowed,false); tables.notes[0].owner_id='A';
assert.equal((await run('A',{cookie},'GET',null)).allowed,true);
assert.equal((await run('A',{cookie},'POST',null)).allowed,true);
registrations[0].enabled=false; assert.equal((await run()).allowed,false);
process.env.RESOURCE_POLICY_MODE='unexpected'; assert.equal((await run()).res.code,503);
globalThis.__deviceFixture = { createClient: () => db, createLoginVerifier: () => async header =>
  header === 'fixture_A' ? {kind:'student',userId:'A'} : null };
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@supabase/supabase-js') return {url:'data:text/javascript,export const createClient=globalThis.__deviceFixture.createClient',shortCircuit:true};
  if (specifier.endsWith('/verify-login.mjs')) return {url:'data:text/javascript,export const createLoginVerifier=globalThis.__deviceFixture.createLoginVerifier',shortCircuit:true};
  return next(specifier,context);
} });
process.env.SUPABASE_URL='https://local-fixture.invalid';
const {default:deviceHandler}=await import('../api/device.mjs');
const anonymous=response(); await deviceHandler({method:'GET',headers:{}},anonymous); assert.equal(anonymous.code,401);
const own=response(); await deviceHandler({method:'GET',headers:{authorization:'fixture_A',cookie}},own);
assert.equal(own.code,200); assert.equal(own.value.userId,'A'); assert.equal(own.value.deviceId,context.deviceId);
const write=response(); await deviceHandler({method:'POST',headers:{authorization:'fixture_A'},body:{enabled:true}},write); assert.equal(write.code,405);
console.log('자체 서버 판정: 서명 쿠키·사용자 연결·소유자·회수·추가/목록 경로 가상 통합 검증 통과.');
