import assert from 'node:assert/strict';
import {verifyAppProof} from '../src/app-proof.mjs';
import {serverDeviceContext} from '../src/server-device.mjs';
import {signedFixture} from './app-proof-fixture.mjs';
import {issueAppCertificate} from '../src/app-proof.mjs';
import {createProtectedFetch} from '../public/request-proof.mjs';
process.env.SUPABASE_SECRET_KEY='local-proof-fixture';
const config={repoUrl:'https://github.com/virtual/fixture'};
const identity={userId:'B'},seen=new Set();let outage=false;
const db={async rpc(name,args){assert.equal(name,'consume_app_request_nonce');
  if(outage)return {error:{code:'fixture'}};
  const key=args.p_certificate_id+args.p_nonce;if(seen.has(key))return {data:false};seen.add(key);return {data:true};}};
const request=()=>signedFixture({method:'PUT',url:'/api/notes/00000000-0000-4000-8000-000000000002',
  body:{title:'virtual',body:'virtual'},headers:{}},'B',config);
const check=(req,who=identity)=>verifyAppProof({req,identity:who,db,secret:process.env.SUPABASE_SECRET_KEY,
  context:serverDeviceContext(req,{setHeader(){}},who,config,process.env.SUPABASE_SECRET_KEY)});
let req=request();assert.equal(await check(req),true);assert.equal(await check(req),false);
req=request();req.url='/api/notes/00000000-0000-4000-8000-000000000001';assert.equal(await check(req),false);
req=request();req.body.body='changed';assert.equal(await check(req),false);
req=request();req.method='POST';assert.equal(await check(req),false);
req=request();req.url+='?owner=A';assert.equal(await check(req),false);
req=request();delete req.headers['x-vault-app-signature'];assert.equal(await check(req),false);
req=request();assert.equal(await check(req,{userId:'A'}),false);
req=request();req.headers['x-vault-app-time']=String(Date.now()-60000);assert.equal(await check(req),false);
req=request();outage=true;assert.equal(await check(req),false);outage=false;
req=request();req.url+='?id=00000000-0000-4000-8000-000000000002';assert.equal(await check(req),true);
const originalFetch=globalThis.fetch,originalLocation=globalThis.location;
const browserContext=serverDeviceContext(req,{setHeader(){}},identity,config,process.env.SUPABASE_SECRET_KEY);
try{
  globalThis.location={origin:'https://virtual.invalid'};
  globalThis.fetch=async(url,options={})=>{
    if(url==='/api/app-certificate'){
      const {publicKey}=JSON.parse(options.body);assert.equal(publicKey.d,undefined);
      const result=issueAppCertificate({publicKey,identity,context:browserContext,secret:process.env.SUPABASE_SECRET_KEY,expiresAt:Date.now()+60000});
      return {ok:true,async json(){return result;}};
    }
    const signed={method:options.method||'GET',url,body:options.body,
      headers:Object.fromEntries(Object.entries(options.headers).map(([key,value])=>[key.toLowerCase(),value]))};
    assert.equal(await verifyAppProof({req:signed,db,identity,context:browserContext,secret:process.env.SUPABASE_SECRET_KEY}),true);
    return {ok:true,status:200};
  };
  const browserFetch=createProtectedFetch(()=>({}));
  assert.equal((await browserFetch('/api/notes')).status,200);
  assert.equal((await browserFetch('/api/notes/'+req.url.split('/').at(-1).split('?')[0],{method:'PUT',body:JSON.stringify({body:'virtual',title:'virtual'})})).status,200);
}finally{globalThis.fetch=originalFetch;if(originalLocation===undefined)delete globalThis.location;else globalThis.location=originalLocation;}
console.log('요청 서명 정상·재사용·경로/본문/동작/쿼리 변조·누락·타인·시간·DB장애·플랫폼 경로 정규화 경계 통과 (가상 nonce DB).');
