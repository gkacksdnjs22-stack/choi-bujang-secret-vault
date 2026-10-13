import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { serverDeviceContext } from '../src/server-device.mjs';

// 실제 API 함수 + 활성화된 서버 판정 흐름. 로그인 발급자와 DB만 가상화합니다.
process.env.SUPABASE_SECRET_KEY = 'local-integration-fixture';
process.env.SUPABASE_URL = 'https://local-fixture.invalid';
process.env.RESOURCE_POLICY_MODE = 'enforce';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
const noteId = '00000000-0000-4000-8000-000000000001';
const noticeId = '00000000-0000-4000-8000-000000000002';
const newId = '00000000-0000-4000-8000-000000000003';
const tables = { notes: [{ public_id: noteId, owner_id: 'A', title: 'fixture', content: 'fixture' }],
  announcements: [{ public_id: noticeId, title: 'fixture', content: 'fixture' }],
  principal_bindings: [], instructor_memberships: [] };
let dbFailure = false;
const response = () => ({ headers: {}, setHeader(k,v) {this.headers[k]=v;},
  status(code) {this.code=code;return this;}, json(value) {this.value=value;return this;} });
const cookies = {};
for (const user of ['A','B','I']) {
  const res = response();
  const context = serverDeviceContext({ headers: {} },res,{userId:user},config,process.env.SUPABASE_SECRET_KEY);
  cookies[user] = res.headers['Set-Cookie'].split(';')[0];
  tables.principal_bindings.push({ class_id:context.classId,project_id:context.projectId,
    subject_id:context.subjectId,device_id:context.deviceId,user_id:user,enabled:true,
    expires_at:new Date(Date.now()+60000).toISOString() });
}
class Query {
  constructor(table) {this.table=table;this.filters=[];this.action='select';}
  select() {return this;}
  eq(k,v) {this.filters.push(row=>row[k]===v);return this;}
  order() {return this;}
  maybeSingle() {this.single=true;return this;}
  insert(value) {this.action='insert';this.value=value;return this;}
  update(value) {this.action='update';this.value=value;return this;}
  delete() {this.action='delete';return this;}
  then(resolve,reject) {
    if(dbFailure)return Promise.resolve({data:null,error:{message:'fixture outage'}}).then(resolve,reject);
    let found=tables[this.table].filter(row=>this.filters.every(filter=>filter(row)));
    if(this.action==='insert'){tables[this.table].push(this.value);found=[this.value];}
    if(this.action==='update')found.forEach(row=>Object.assign(row,this.value));
    if(this.action==='delete')tables[this.table]=tables[this.table].filter(row=>!found.includes(row));
    return Promise.resolve({data:this.single?(found[0]??null):found,error:null}).then(resolve,reject);
  }
}
globalThis.__serverApiFixture = {createClient:()=>({from:table=>new Query(table)}),
  createLoginVerifier:()=>async header=>['fixture_A','fixture_B','fixture_I'].includes(header)
    ?{kind:'student',userId:header.slice(-1)}:null};
registerHooks({resolve(specifier,context,next){
  if(specifier==='@supabase/supabase-js')return {url:'data:text/javascript,export const createClient=globalThis.__serverApiFixture.createClient',shortCircuit:true};
  if(specifier.endsWith('/verify-login.mjs'))return {url:'data:text/javascript,export const createLoginVerifier=globalThis.__serverApiFixture.createLoginVerifier',shortCircuit:true};
  return next(specifier,context);
}});
const {default:notes}=await import('../api/notes.mjs');
const {default:notices}=await import('../api/announcements.mjs');
async function call(handler,user,method,url,body,cookie=cookies[user]) {
  const res=response();await handler({method,url,headers:{authorization:'fixture_'+user,cookie},body},res);
  assert.equal(res.headers['Cache-Control'],'no-store');return res;
}
assert.equal((await call(notes,'A','GET','/api/notes')).value.length,1);
assert.equal((await call(notes,'B','GET','/api/notes')).value.length,0);
assert.equal((await call(notes,'A','GET',`/api/notes/${noteId}?id=${noteId}`)).code,200);
for(const method of ['GET','PUT','DELETE']) {
  const before=structuredClone(tables.notes);
  const denied=await call(notes,'B',method,`/api/notes/${noteId}`,{title:'spoof',body:'fixture',role:'admin'});
  assert.equal(denied.code,403);assert.equal(denied.value.reasonCode,'policy_denied');
  assert.deepEqual(tables.notes,before);
}
assert.equal((await call(notes,'A','PUT',`/api/notes/${noteId}`,{title:'updated',body:'fixture'})).code,200);
assert.equal(tables.notes[0].title,'updated');assert.equal(tables.notes[0].owner_id,'A');
assert.equal((await call(notes,'A','POST','/api/notes',{id:newId,title:'new',body:'fixture',owner_id:'B'})).code,400);
assert.equal((await call(notes,'A','POST','/api/notes',{id:newId,title:'new',body:'fixture'})).code,201);
assert.equal(tables.notes.find(row=>row.public_id===newId).owner_id,'A');
assert.equal((await call(notes,'B','DELETE',`/api/notes/${newId}`)).code,403);
assert.equal((await call(notes,'A','DELETE',`/api/notes/${newId}`)).code,200);
assert.equal(tables.notes.some(row=>row.public_id===newId),false);
assert.equal((await call(notes,'A','GET',`/api/notes/${noteId}`,undefined,cookies.B)).code,403);
tables.principal_bindings.find(row=>row.user_id==='A').enabled=false;
assert.equal((await call(notes,'A','GET','/api/notes')).code,403);
tables.principal_bindings.find(row=>row.user_id==='A').enabled=true;
assert.equal((await call(notices,'A','GET','/api/announcements')).code,200);
for(const method of ['POST','PUT','DELETE']) {
  const before=structuredClone(tables.announcements);
  assert.equal((await call(notices,'A',method,method==='POST'?'/api/announcements':`/api/announcements/${noticeId}`,{role:'instructor',title:'spoof',body:'fixture'})).code,403);
  assert.deepEqual(tables.announcements,before);
}
tables.instructor_memberships.push({user_id:'I',enabled:true});
assert.equal((await call(notices,'I','PUT',`/api/announcements/${noticeId}`,{title:'approved',body:'fixture'})).code,200);
tables.instructor_memberships[0].enabled=false;
const before=structuredClone(tables.announcements);
assert.equal((await call(notices,'I','DELETE',`/api/announcements/${noticeId}`)).code,403);
assert.deepEqual(tables.announcements,before);
dbFailure=true;
assert.equal((await call(notes,'A','GET','/api/notes')).code,403);
console.log('자체 서버 API 통합 검증 통과: 활성 판정 + 본인 CRUD + 타인 차단 + 역할 위조 + 접속/강사 권한 회수 + DB 장애 차단. 가상 DB 시험이며 실제 자료는 변경하지 않았습니다.');
