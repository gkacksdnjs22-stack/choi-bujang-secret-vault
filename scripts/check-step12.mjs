import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,rm} from 'node:fs/promises';
import vm from 'node:vm';
import {runAttackChecks} from '../src/attack-check.mjs';
import {summarizeChecks} from '../src/check-summary.mjs';
const original=globalThis.fetch,calls=[];
let mode='success';
globalThis.fetch=async(url,options)=>{
  assert.equal(options.method,'GET');assert.equal(options.alephEvidence?.requestKey,'read');
  assert.ok(options.alephEvidence.caseId);calls.push(options.alephEvidence.caseId);
  if(mode==='network')throw Error('unavailable');
  const path=new URL(url).pathname;
  return new Response(JSON.stringify(path==='/api/checks'?{source:'fixed_virtual_fixture',ready:mode!=='failed'}:
    path==='/data.json'?{notes:[]}:{error:'denied'}),
    {status:path==='/api/checks'||path==='/data.json'?200:path.startsWith('/api/restore/')?405:401});
};
let attempts;
try{
  attempts=await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'});
  assert.equal(attempts.length,13);assert.equal(calls.length,13);assert.equal(new Set(calls).size,13);
  for(const a of attempts){assert.match(a.observed,/^(not_run|HTTP \d{3}(; jsonReady=(true|false))?)$/);
    assert.equal(calls.includes(a.attackId),a.result!=='not_run');}
  assert.ok(!attempts.some(a=>['s08-own','s11-manifest'].includes(a.attackId)));
  assert.equal(attempts.filter(a=>a.result==='blocked').length,13);
  mode='failed';assert.equal((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).filter(a=>a.result==='breached').length,6);
  mode='network';assert.ok((await runAttackChecks({step:12,publicAppUrl:'https://vault.invalid/'})).every(a=>a.result==='not_run'));
}finally{globalThis.fetch=original;}
assert.deepEqual(attempts.map(a=>a.attackId).sort(),['s02-static-copy','s03-unauth-list','s03-fake-token','s04-query-identity','s04-header-identity','s05-direct-table','s08-other-zone','s06-unregistered','s07-compound','s08-unknown-route','s08-all-notes','s08-write-notice','s09-burst-read'].sort());
const receipt={commit:'a'.repeat(40),checkedAt:new Date().toISOString(),attackAttempts:attempts};
const summary=summarizeChecks(receipt);
assert.deepEqual([summary.total,summary.blocked,summary.failed,summary.notRun],[13,13,0,0]);
assert.equal(summarizeChecks({...receipt,attackAttempts:[{result:'blocked',observed:'not_run'}]}).notRun,1);
assert.throws(()=>summarizeChecks({...receipt,checkedAt:'invalid'}));
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{attackId:'s11-manifest',stage:11,expected:'manifest',result:'blocked',observed:'HTTP 200'}]}));
assert.throws(()=>summarizeChecks({...receipt,attackAttempts:[{attackId:'s08-own',stage:8,expected:'own',result:'blocked',observed:'HTTP 200; jsonReady=true'}]}));
assert.deepEqual(Object.keys(summary).sort(),['checkedAt','commit','total','blocked','notRun','failed'].sort());
// Render exactly the API counts, including unexpected failures; no guessed totals.
const source=await readFile(new URL('../public/operations.mjs',import.meta.url),'utf8');
const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{append(){},textContent:'',disabled:false});return elements.get(id);};
const context=vm.createContext({document:{getElementById:el,createElement:()=>({})},
  createProtectedFetch:()=>()=>{},fetch:async()=>new Response(JSON.stringify({...summary,blocked:summary.total-3,failed:3}),{status:200}),console});
await vm.runInContext(source.replace(/^import .*;\r?\n/,'' ).replace(/\r?\nloadReceipt\(\);\s*$/,'')+'\nloadReceipt();',context);
assert.match(el('receipt').textContent,new RegExp('차단 조건 확인: '+(summary.total-3)));assert.match(el('receipt').textContent,/조건 불충족: 3/);assert.match(el('receipt').textContent,/미실행: 0/);
assert.match(el('receiptSource').textContent,/artifacts\/submission.json/);
assert.match(el('receiptSource').textContent,new RegExp(summary.commit));
context.fetch=async()=>new Response(JSON.stringify({...summary,total:41,blocked:0,failed:0,notRun:41}));
await el('scopeRefresh').onclick();
assert.match(el('receipt').textContent,/점검 항목: 41/);assert.match(el('receipt').textContent,/차단 조건 확인: 0/);
assert.match(el('receipt').textContent,/미실행: 41/);assert.match(el('receiptSource').textContent,/항목: 41건/);
context.fetch=async()=>new Response('{}',{status:503});await vm.runInContext('loadReceipt()',context);
assert.equal(el('receipt').textContent.includes('20'),false);
assert.match(el('receiptSource').textContent,/확인 실패/);assert.equal(el('receiptSource').textContent.includes(summary.commit),false);
assert.equal(el('scopeRefresh').disabled,false);
context.fetch=async()=>new Response(JSON.stringify({...summary,blocked:41}));await el('receiptRefresh').onclick();
assert.match(el('receipt').textContent,/읽지 못했습니다/);
context.fetch=async()=>new Response(JSON.stringify({...summary,commit:'invalid'}));await el('scopeRefresh').onclick();
assert.match(el('receiptSource').textContent,/확인 실패/);
let resolveFetch;
context.fetch=()=>new Promise(resolve=>{resolveFetch=resolve;});
const pending=vm.runInContext('loadReceipt()',context);
assert.match(el('receipt').textContent,/조회 중/);assert.equal(el('receipt').textContent.includes('점검 항목:'),false);
assert.equal(el('receiptRefresh').disabled,true);assert.equal(el('scopeRefresh').disabled,true);
resolveFetch(new Response(JSON.stringify(summary)));await pending;
assert.match(el('receipt').textContent,new RegExp('점검 항목: '+summary.total));
console.log('step12: evidence IDs, GET-only, supported observations, failure/not_run accounting and API-to-screen counts passed');

const receiptPath=new URL('../artifacts/submission.json',import.meta.url);
let previous;try{previous=await readFile(receiptPath);}catch{}
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
const {default:checks}=await import('../api/checks.mjs');
async function call(query={},method='GET'){
 const res={headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.code=n;return this;},json(d){this.data=d;return this;}};
 await checks({method,query},res);return res;
}
try{
 await writeFile(receiptPath,JSON.stringify(receipt));
 assert.deepEqual((await call()).data,summary);
 const allUnrun={...receipt,attackAttempts:receipt.attackAttempts.map(a=>({...a,observed:'not_run',result:'not_run'}))};
 await writeFile(receiptPath,JSON.stringify(allUnrun));
 const reread=(await call()).data;
 assert.deepEqual([reread.total,reread.blocked,reread.failed,reread.notRun],[13,0,0,13]);
 await writeFile(receiptPath,JSON.stringify(receipt));
 assert.deepEqual((await call()).data,summary);
 assert.equal((await call({case:'s08-own'})).data.ready,true);
 assert.equal((await call({},'POST')).code,405);
 assert.equal((await call({owner:'other'})).code,400);
 const incomplete41={...receipt,attackAttempts:Array.from({length:41},()=>({result:'blocked',observed:'HTTP 403'}))};
 await writeFile(receiptPath,JSON.stringify(incomplete41));
 assert.deepEqual([(await call()).code,...['total','blocked','failed','notRun'].map(k=>(summarizeChecks(incomplete41))[k])],[200,41,0,0,41]);
 const apiIncomplete=(await call()).data;
 assert.deepEqual([apiIncomplete.total,apiIncomplete.blocked,apiIncomplete.failed,apiIncomplete.notRun],[41,0,0,41]);
 await rm(receiptPath);assert.equal((await call()).code,503);
 await writeFile(receiptPath,'{}');assert.equal((await call()).code,503);
 console.log('step12: stored receipt API, invalid receipt, read-only and existing virtual-case boundaries passed');
}finally{if(previous)await writeFile(receiptPath,previous);else await rm(receiptPath,{force:true});}

// The public root uses the official sample's semantic count slots, including all-unrun.
const receiptUI=await readFile(new URL('../public/receipt.mjs',import.meta.url),'utf8');
const cells=['total','blocked','failed','notRun'].map(k=>({dataset:{k},textContent:'-'}));
const meta={textContent:''};
const rootContext=vm.createContext({document:{querySelectorAll:()=>cells,getElementById:()=>meta},fetch:async()=>new Response(JSON.stringify(summary))});
await vm.runInContext(receiptUI+'\nloadOps();',rootContext);
assert.deepEqual(cells.map(c=>c.textContent),['13','13','0','0']);
rootContext.fetch=async()=>new Response(JSON.stringify({...summary,blocked:0,notRun:13}));
await vm.runInContext('loadOps()',rootContext);
assert.deepEqual(cells.map(c=>c.textContent),['13','0','0','13']);
rootContext.fetch=async()=>new Response('{}',{status:503});await vm.runInContext('loadOps()',rootContext);
assert.deepEqual(cells.map(c=>c.textContent),['-','-','-','-']);
console.log('step12: official root count slots, all-unrun and unavailable record display passed');

// Requested 41-case boundary: absent/incomplete observations never become successes.
const fixture=(i,result,observed)=>({attackId:'review-'+i,stage:12,expected:'deny unauthorized',result,observed});
const count=attackAttempts=>summarizeChecks({...receipt,attackAttempts});
const fields=s=>[s.total,s.blocked,s.failed,s.notRun];
assert.deepEqual(fields(count(Array.from({length:41},(_,i)=>fixture(i,'not_run','not_run')))),[41,0,0,41]);
assert.deepEqual(fields(count(Array.from({length:41},()=>({result:'blocked',observed:'HTTP 403'})))),[41,0,0,41]);
assert.deepEqual(fields(count(Array.from({length:41},(_,i)=>({...fixture(i,'breached',undefined)})))),[41,0,0,41]);
assert.deepEqual(fields(count([fixture(1,'blocked','HTTP 403'),fixture(2,'breached','HTTP 200')])),[2,1,1,0]);
const mixed=[...Array.from({length:41},(_,i)=>fixture(i,'not_run','not_run')),fixture(42,'blocked','HTTP 401'),fixture(43,'breached','HTTP 200')];
assert.deepEqual(fields(count(mixed)),[43,1,1,41]);
assert.equal(count([fixture(1,'blocked','network_error')]).notRun,1);
assert.equal(count([null,{},fixture(1,undefined,'HTTP 403')]).notRun,3);
assert.throws(()=>count([]),/invalid_check_receipt/);
assert.equal(count(mixed).total,count(mixed).blocked+count(mixed).failed+count(mixed).notRun);
console.log('step12: 41 unrun, incomplete observations, actual deny/allow and mixed totals passed');
