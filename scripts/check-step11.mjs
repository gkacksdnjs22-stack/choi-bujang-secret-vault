import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {registerHooks} from 'node:module';
import {requestAuthorization,sessionCookie} from '../src/session-cookie.mjs';
const config=JSON.parse(await readFile(new URL('../aleph.config.json',import.meta.url),'utf8'));
const cookie='__Host-vault-session=aaa.bbb.ccc';
assert.equal(requestAuthorization({method:'GET',headers:{cookie}},config),'Bearer aaa.bbb.ccc');
assert.equal(requestAuthorization({method:'POST',headers:{cookie}},config),undefined);
assert.equal(requestAuthorization({method:'POST',headers:{cookie,origin:config.publicAppUrl}},config),'Bearer aaa.bbb.ccc');
assert.equal(requestAuthorization({method:'PUT',headers:{cookie,origin:'https://other.invalid'}},config),undefined);
assert.equal(requestAuthorization({method:'GET',headers:{cookie:cookie+'; '+cookie}},config),undefined);
assert.equal(requestAuthorization({method:'GET',headers:{cookie,authorization:'Bearer invalid'}},config),'Bearer invalid');
assert.match(sessionCookie('aaa.bbb.ccc'),/HttpOnly; Secure; SameSite=Strict/);
const manifest=JSON.parse(await readFile(new URL('../public/manifest.webmanifest',import.meta.url),'utf8'));
assert.equal(manifest.display,'standalone');assert.equal(manifest.start_url,'/');assert.ok(manifest.name&&manifest.icons.length);
const app=await readFile(new URL('../public/app.mjs',import.meta.url),'utf8');
assert.doesNotMatch(app,/(?:sessionStorage|localStorage)\.setItem/);
const sw=await readFile(new URL('../public/sw.js',import.meta.url),'utf8');
assert.match(sw,/cache\.add\('\/offline\.html'\)/);assert.doesNotMatch(sw,/cache\.put|cache\.addAll/);
let approved=false,dbError=false;const writes=[];
const db={from(table){
  return {select(){return this;},eq(){return this;},async maybeSingle(){return {data:approved?{enabled:true,expires_at:new Date(Date.now()+60000).toISOString()}:null,error:dbError?{}:null};},
    async upsert(data){writes.push({table,data});return {error:null};}};
}};
globalThis.__step11Db=db;
registerHooks({resolve(specifier,context,next){
  if(specifier==='@supabase/supabase-js')return {url:'data:text/javascript,export const createClient=()=>globalThis.__step11Db',shortCircuit:true};
  if(specifier.endsWith('/verify-login.mjs'))return {url:'data:text/javascript,export const createLoginVerifier=()=>async h=>h===%22virtual_student%22?{kind:%22student%22,userId:%2200000000-0000-4000-8000-000000000001%22}:null',shortCircuit:true};
  return next(specifier,context);
}});
process.env.SUPABASE_URL='https://local.invalid';process.env.SUPABASE_SECRET_KEY='local-fixture';
const {default:device}=await import('../api/device.mjs');
async function call(method,body,authorization='virtual_student'){
  const res={setHeader(){},status(code){this.code=code;return this;},json(data){this.data=data;return this;}};
  await device({method,body,headers:{authorization}},res);return res;
}
assert.equal((await call('GET',undefined,'invalid')).code,401);
assert.equal((await call('GET')).data.registered,false);
assert.equal((await call('POST',{})).code,202);assert.equal(approved,false);
assert.equal(writes[0].table,'device_approval_requests');assert.equal(writes.length,1);
assert.equal((await call('POST',{registered:true})).code,400);assert.equal(writes.length,1);
approved=true;assert.equal((await call('GET')).data.registered,true);
dbError=true;assert.equal((await call('GET')).code,503);
assert.equal((await call('DELETE')).code,405);
// 실제 화면 코드를 가상 DOM/서버 응답으로 실행해 승인 전 자료 요청 자체가 없는지 확인합니다.
async function screen(registered,deviceStatus=200){
  const elements=new Map();const calls=[];
  const element=id=>{if(!elements.has(id))elements.set(id,{hidden:true,value:'',textContent:'',reset(){},replaceChildren(){},checked:false});return elements.get(id);};
  const fetch=async(path,options={})=>{
    calls.push({path,method:options.method||'GET'});
    const status=path==='/api/device'?(options.method==='POST'?202:deviceStatus):200;
    const value=path==='/api/notes'?[]:options.method==='POST'?{requested:true}:{registered};
    return {status,ok:status>=200&&status<300,async json(){return value;}};
  };
  const execute=new Function('document','fetch','sessionStorage','navigator','window','return (async()=>{'+app+'})()');
  await execute({getElementById:element},fetch,{getItem(){return null;},removeItem(){}},{onLine:true},{addEventListener(){}});
  return {element,calls};
}
const pending=await screen(false);assert.equal(pending.element('workspace').hidden,true);
assert.equal(pending.calls.filter(call=>call.path==='/api/notes').length,0);
await pending.element('requestApproval').onclick();assert.equal(pending.element('workspace').hidden,true);
const approvedScreen=await screen(true);assert.equal(approvedScreen.element('workspace').hidden,false);
assert.equal(approvedScreen.calls.filter(call=>call.path==='/api/notes').length,1);
const failedScreen=await screen(false,503);assert.equal(failedScreen.element('workspace').hidden,true);
assert.equal(failedScreen.calls.filter(call=>call.path==='/api/notes').length,0);
console.log('11단계 쿠키 출처·중복·Bearer 우선순위·승인 신청 비승격·등록 상태·DB 장애 경계 및 설치/오프라인 설정 검증 통과. 가상 API 시험이며 운영 앱 서명 검사는 별도입니다.');
