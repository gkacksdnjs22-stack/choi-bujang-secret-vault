import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';

// 서버 소유권 판정 진입점입니다. 구역 기본 함수와 별도 집행 단계입니다.
globalThis.__engineFixtureDB = null;
registerHooks({resolve(specifier,context,next) {
  if (specifier === '@supabase/supabase-js') return {url:'data:text/javascript,export const createClient=()=>globalThis.__engineFixtureDB',shortCircuit:true};
  return next(specifier,context);
}});
process.env.SUPABASE_URL='https://local-fixture.invalid';
process.env.SUPABASE_SECRET_KEY='local-engine-fixture';
const {ruleFixture,runRuleCheck} = await import('../src/rule-check.mjs');
const {createEngineDecision,runtimeDecision:decide} = await import('../src/engine-resource-policy.mjs');
const fixture = ruleFixture();
globalThis.__engineFixtureDB=fixture.db;
const request=fixture.request, rows=fixture.rows;
let count=0;
const check=async(input,expected) => {
  const result=await decide(input);
  assert.equal(result.decision,expected);
  assert.equal(result.requestId,input.requestId);
  assert.equal(Object.keys(result).sort().join(),'decision,reasonCode,requestId,ruleIds,schema');
  count++;
};
await check(request,'allow');
await check({...request,path:request.path.replace('/api',''),route:'GET /notes/:id'},'allow');
for (const method of ['GET','PUT','DELETE']) {
  await check({...request,method,route:method+' /api/notes/:id'},'allow');
  await check({...request,subjectId:'check_B',method,route:method+' /api/notes/:id'},'deny');
}
// 서버 소유권 판정의 반대 방향도 검증합니다.
const bNoteId='00000000-0000-4000-8000-000000000004';
rows.notes.push({public_id:bNoteId,owner_id:'B'});
for (const method of ['GET','PUT','DELETE']) {
  const bRequest={...request,subjectId:'check_B',path:'/api/notes/'+bNoteId,
    method,route:method+' /api/notes/:id'};
  await check(bRequest,'allow');
  await check({...bRequest,subjectId:'check_A'},'deny');
}
for (const patch of [{deviceRegistered:false},{deviceId:'b'.repeat(16)},{projectId:'other'},
  {classId:'other'},{subjectId:'unregistered'},{queryLength:10},{querySha256:'0'.repeat(64)},
  {at:'2020-01-01T00:00:00Z'},{at:new Date(Date.now()+60000).toISOString()},
  {path:'/api/notes/export'},{path:request.path+'/export'},{route:'GET /notes/:id'},
  {role:'instructor'},{grants:[]},{policyRevision:0},{schema:'unknown'}]) await check({...request,...patch},'deny');
const notice={...request,service:'announcements',path:'/api/announcements/00000000-0000-4000-8000-000000000002',method:'PUT',route:'PUT /api/announcements/:id'};
await check(notice,'deny');
await check({...notice,subjectId:'check_I'},'allow');
rows.instructor_memberships[0].enabled=false;
await check({...notice,subjectId:'check_I'},'deny');
rows.notes[0].owner_id='B';
await check(request,'deny');
await check({...request,subjectId:'check_B'},'allow');
rows.notes[0].owner_id='A';
rows.principal_bindings[0].enabled=false;
await check(request,'deny');
rows.principal_bindings[0].enabled=true;
rows.principal_bindings[0].expires_at='2020-01-01T00:00:00Z';
await check(request,'deny');
rows.principal_bindings[0].expires_at=new Date(Date.now()+60000).toISOString();
const risk={...request,signals:{source:'judge_fixture',region:'foreign',network:'unusual',hour:3},recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]};
await check(risk,'step_up');
await check({...risk,stepUp:{verified:true,authAgeSeconds:60}},'allow');
const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url)));
assert.equal((await createEngineDecision({db:fixture.db,config})(request,'B')).decision,'deny');
globalThis.__engineFixtureDB={from(){throw new Error('fixture outage');}};
await check(request,'deny');
globalThis.__engineFixtureDB=fixture.db;
for (const caseId of ['s06-unregistered','s07-compound','s08-own','s08-ownership','s08-unknown-route','s08-all-notes','s08-write-notice']) {
  const result=await runRuleCheck(caseId); assert.equal(result.ready,true);assert.equal(result.source,'fixed_virtual_fixture');
}
assert.equal(await runRuleCheck('arbitrary'),null);
const {default:checks} = await import('../api/checks.mjs');
const response=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(value){this.value=value;return this;}});
for (const [method,query,status] of [['GET',{case:'s08-ownership'},200],['POST',{case:'s08-own'},405],
  ['GET',{case:['s08-own']},400],['GET',{case:'s08-own',role:'instructor'},400],['GET',{case:'unknown'},400]]) {
  const res=response();await checks({method,query},res);assert.equal(res.code,status);assert.equal(res.headers['Cache-Control'],'no-store');
}
console.log(`서버 소유권 판정 ${count}건 + 공개 고정 가상 점검 7종 + 점검 API 경계 통과. 실제 계정/운영 엔진 시험은 별도입니다.`);
