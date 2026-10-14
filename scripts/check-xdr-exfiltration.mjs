import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {decide} from '../xdr/exfiltration/decide.mjs';
import {readAlerts,extractAlerts} from '../xdr/exfiltration/read-alerts.mjs';
import {respond} from '../xdr/exfiltration/respond.mjs';
import {buildDenyRules,canonicalAddress} from '../xdr/exfiltration/deny-rules.mjs';
import {runXdr} from './xdr-run.mjs';
import {decide as decideBase} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const fixtureFile=new URL('../xdr/fixtures/exfiltration.json',import.meta.url);
const raw=await readFile(fixtureFile),hash=createHash('sha256').update(raw).digest('hex');
assert.equal(hash,'1b04986dc31fd46837f6f587c3a113b876c601746217f856d13b4b958abeb0aa');
const fixture=JSON.parse(raw),rows=await readAlerts();
assert.equal(rows.length,30);
assert.ok(rows.every(r=>Object.keys(r).sort().join()==='account,description,ruleLevel,sourceAddress,timestamp'));
for(const description of ['{"token":"sample-sensitive-value with spaces"}',"password='sample-sensitive-value'",'Bearer sample-sensitive-value']){
  assert.equal(JSON.stringify(extractAlerts({...fixture,alerts:[{rule:{description}}]})).includes('sample-sensitive-value'),false);
}
const source=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
assert.equal(/^\s*import\b/m.test(source),false);assert.equal(/\b(?:fetch|eval|Function|require)\s*\(/.test(source),false);
const isolated=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
assert.deepEqual(Object.keys(isolated),['decide']);
const patterns=JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json',import.meta.url),'utf8')).patterns;
for(let i=0;i<fixture.alerts.length;i++){
  const a=fixture.alerts[i],before=JSON.stringify(a),started=performance.now(),out=isolated.decide(a);
  assert.ok(performance.now()-started<2000);assert.equal(out.action,i<10?'block':i<20?'alert':'record');
  assert.equal(JSON.stringify(a),before);
  assert.deepEqual(out,decide({...a,id:'unrelated-id',data:{...a.data,srcuser:'renamed',srcip:'192.0.2.201',dstip:'203.0.113.201'}}));
  assert.deepEqual(Object.keys(out).sort(),['action','confidence','reason']);
  assert.ok(Number.isFinite(out.confidence)&&out.confidence>=0&&out.confidence<=1);
  assert.equal(out.action,out.confidence>=0.85?'block':out.confidence>=0.5?'alert':'record');
  assert.ok(patterns.some(p=>p.name===out.reason&&p.condition&&p.evidence));
}
for(const a of [null,{},[],{rule:{level:'12'}},{rule:{description:null}}])assert.equal(decide(a).action,'record');
for(const a of fixture.alerts.slice(10,20))assert.notEqual(decide({...a,rule:{...a.rule,level:15}}).action,'block');
for(const bytes of ['49999999','invalid','-1','Infinity','9007199254740992',null])
  assert.equal(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,bytes}}).action,'alert');
assert.equal(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,bytes:'50000000'}}).action,'block');
assert.equal(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,files:'49'}}).action,'alert');
assert.equal(decide({...fixture.alerts[2],data:{...fixture.alerts[2].data,count:'4'}}).action,'alert');
assert.equal(decide({...fixture.alerts[0],rule:{...fixture.alerts[0].rule,level:5}}).action,'alert');
assert.equal(decide({...fixture.alerts[0],rule:{level:15,description:'처음 보는 목적지 반출 패턴을 설명하는 정책 안내입니다.'}}).action,'record');
const result=await runXdr({root,moduleKey:'exfiltration',writeError:()=>assert.fail('invalid_decision')});
assert.deepEqual(result.counts,{block:10,alert:10,record:10});
const outputDirectory=await mkdtemp(join(tmpdir(),'xdr-exfiltration-test-'));
let time=Date.now();
// LOCAL verified transport simulation, not a browser destination assertion or operational engine.
const requests=new Map();
const requestTo=(destinationAddress,changes={})=>{
  const request={...fixtureRequests().normal,...changes};
  requests.set(request.requestId,{verified:true,classId:request.classId,projectId:request.projectId,destinationAddress});
  return request;
};
const destinations=new Set(fixture.alerts.map(a=>a.data.dstip).filter(Boolean));
const resolveDestination=async alert=>destinations.has(alert.data?.dstip)
  ?{verified:true,classId:'class_fixture',projectId:'project_fixture',destinationAddress:alert.data.dstip}:undefined;
const resolveRequestDestination=async request=>requests.get(request.requestId);
const pipeline=await respond({alerts:fixture.alerts,decideBase,resolveDestination,resolveRequestDestination,
  outputDirectory,clock:()=>time,logFile:join(outputDirectory,'alerts.log')});
for(const a of fixture.alerts.slice(0,10))assert.equal((await pipeline.enforce(requestTo(a.data.dstip))).decision,'deny');
for(const a of fixture.alerts.slice(10))if(a.data.dstip)assert.equal((await pipeline.enforce(requestTo(a.data.dstip))).decision,'allow');
const badDestination=fixture.alerts[0].data.dstip;
assert.equal((await pipeline.enforce(requestTo(badDestination,{deviceId:'b'.repeat(16),subjectId:'other_subject'}))).decision,'deny');
for(const key of ['classId','projectId'])assert.equal((await pipeline.enforce(requestTo(badDestination,{[key]:'another_scope'}))).decision,'allow');
assert.equal((await pipeline.enforce(requestTo(badDestination,{deviceRegistered:false}))).reasonCode,'device_not_registered');
const suspicious=requestTo(badDestination,{...fixtureRequests().suspicious});
assert.equal((await pipeline.enforce(suspicious)).decision,'step_up');
assert.equal(pipeline.rules.length,10);
assert.ok(Object.isFrozen(pipeline.rules)&&pipeline.rules.every(Object.isFrozen));
assert.equal((await readFile(join(outputDirectory,'alerts.log'),'utf8')).trim().split('\n').length,20);
assert.equal(JSON.stringify(pipeline.rules).includes('user01'),false);
// Missing/unverified/mismatched server context is not quietly accepted, even if caller supplies a second argument.
const noContext=fixtureRequests().normal;
await assert.rejects(()=>pipeline.enforce(noContext,{verified:true,destinationAddress:'192.0.2.10'}));
for(const context of [
  {verified:false,classId:noContext.classId,projectId:noContext.projectId,destinationAddress:'192.0.2.10'},
  {verified:true,classId:'wrong_class',projectId:noContext.projectId,destinationAddress:'192.0.2.10'},
  {verified:true,classId:noContext.classId,projectId:noContext.projectId,destinationAddress:'invalid'}
]){requests.set(noContext.requestId,context);await assert.rejects(()=>pipeline.enforce(noContext));}
const existingLog=join(outputDirectory,'existing.log');await writeFile(existingLog,'preserve\n');
const ruleFile=join(outputDirectory,'deny-rules.json'),rulesBefore=await readFile(ruleFile,'utf8');
for(const options of [
  {alerts:[fixture.alerts[0],{...fixture.alerts[20],id:fixture.alerts[0].id}],resolveDestination},
  {alerts:[null],resolveDestination},
  {alerts:[{...fixture.alerts[10],id:'token=sample-sensitive-value'}],resolveDestination},
  {alerts:[fixture.alerts[0]],resolveDestination:async a=>({verified:false,classId:'class_fixture',projectId:'project_fixture',destinationAddress:a.data.dstip})},
  {alerts:[fixture.alerts[0]],resolveDestination:async()=>({verified:true,classId:'class_fixture',projectId:'project_fixture',destinationAddress:'192.0.2.10'})},
  {alerts:[fixture.alerts[0]],resolveDestination:async a=>({verified:true,destinationAddress:a.data.dstip})},
  {alerts:[{...fixture.alerts[0],data:{...fixture.alerts[0].data,dstip:'invalid'}}],resolveDestination}
]){
  await assert.rejects(()=>respond({...options,decideBase,resolveRequestDestination,outputDirectory,logFile:existingLog,clock:()=>time}));
  assert.equal(await readFile(existingLog,'utf8'),'preserve\n');assert.equal(await readFile(ruleFile,'utf8'),rulesBefore);
}
const blockDecision={alertId:fixture.alerts[0].id,...decide(fixture.alerts[0])};
for(const decisions of [[],[blockDecision,blockDecision],[{...blockDecision,confidence:0.8}]])
  await assert.rejects(()=>buildDenyRules([fixture.alerts[0]],decisions,{resolveDestination,now:time}));
for(const value of ['invalid','192.0.2.10:80','https://192.0.2.10','fe80::1%eth0'])assert.equal(canonicalAddress(value),null);
assert.equal(canonicalAddress('2001:0db8:0:0:0:0:0:1'),'2001:db8::1');
const ipv6Alert={...fixture.alerts[0],data:{...fixture.alerts[0].data,dstip:'2001:0db8:0:0:0:0:0:1'}};
const v6pipeline=await respond({alerts:[ipv6Alert],decideBase,resolveDestination:async()=>({verified:true,classId:'class_fixture',
  projectId:'project_fixture',destinationAddress:'2001:db8::1'}),resolveRequestDestination,outputDirectory,
  clock:()=>time,logFile:existingLog});
assert.equal((await v6pipeline.enforce(requestTo('2001:db8::1'))).decision,'deny');
const beforeNormal=await readFile(existingLog,'utf8');
const normalPipeline=await respond({alerts:fixture.alerts.slice(20),decideBase,resolveDestination,resolveRequestDestination,
  outputDirectory,clock:()=>time,logFile:existingLog});
assert.equal(normalPipeline.rules.length,0);assert.equal(await readFile(existingLog,'utf8'),beforeNormal);
assert.equal((await normalPipeline.enforce(requestTo(badDestination))).decision,'allow');
time+=900001;assert.equal((await pipeline.enforce(requestTo(badDestination))).decision,'allow');
assert.equal(createHash('sha256').update(await readFile(fixtureFile)).digest('hex'),hash);
if(process.argv.includes('--write-example'))await respond({alerts:fixture.alerts,decideBase,resolveDestination,
  resolveRequestDestination,outputDirectory:join(root,'xdr','exfiltration')});
console.log(JSON.stringify({counts:result.counts,readerRows:rows.length,normalBlocked:0,standalone:true,
  actualBaseFunctionTested:true,localDestinationBlock:true,liveEngineConnected:false}));
