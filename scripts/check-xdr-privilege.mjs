import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {decide} from '../xdr/privilege/decide.mjs';
import {readAlerts,extractAlerts} from '../xdr/privilege/read-alerts.mjs';
import {respond} from '../xdr/privilege/respond.mjs';
import {buildDenyRules} from '../xdr/privilege/deny-rules.mjs';
import {runXdr} from './xdr-run.mjs';
import {decide as decideBase} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const fixtureFile=new URL('../xdr/fixtures/privilege.json',import.meta.url);
const raw=await readFile(fixtureFile),hash=createHash('sha256').update(raw).digest('hex');
assert.equal(hash,'e5e4b41e81138c79de7a62ad23859ce166cbf078fd8f9a2bac54a79e6f547a85');
const fixture=JSON.parse(raw),rows=await readAlerts();
assert.equal(rows.length,26);
assert.ok(rows.every(r=>Object.keys(r).sort().join()==='account,description,ruleLevel,sourceAddress,timestamp'));
for(const description of ['{"token":"sample-sensitive-value with spaces"}',"password='sample-sensitive-value'",'Bearer sample-sensitive-value']){
  const safe=extractAlerts({...fixture,alerts:[{rule:{description}}]});
  assert.equal(JSON.stringify(safe).includes('sample-sensitive-value'),false);
}
const source=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
assert.equal(/^\s*import\b/m.test(source),false);
assert.equal(/\b(?:fetch|eval|Function|require)\s*\(/.test(source),false);
const isolated=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
assert.deepEqual(Object.keys(isolated),['decide']);
const patterns=JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json',import.meta.url),'utf8')).patterns;
for(let i=0;i<fixture.alerts.length;i++){
  const a=fixture.alerts[i],before=JSON.stringify(a),started=performance.now(),out=isolated.decide(a);
  assert.ok(performance.now()-started<2000);
  assert.equal(out.action,i<9?'block':i<17?'alert':'record');
  assert.equal(JSON.stringify(a),before);
  assert.deepEqual(out,decide({...a,id:'unrelated-id',data:{...a.data,srcuser:'renamed-account',srcip:'192.0.2.200'}}));
  assert.deepEqual(Object.keys(out).sort(),['action','confidence','reason']);
  assert.ok(patterns.some(p=>p.name===out.reason&&p.condition&&p.evidence));
  assert.ok(Number.isFinite(out.confidence)&&out.confidence>=0&&out.confidence<=1);
  assert.equal(out.action,out.confidence>=0.85?'block':out.confidence>=0.5?'alert':'record');
}
for(const a of [null,{},[],{rule:{level:'12'}},{rule:{description:null}}])assert.equal(decide(a).action,'record');
for(const a of fixture.alerts.slice(9,17))assert.notEqual(decide({...a,rule:{...a.rule,level:15}}).action,'block');
assert.equal(decide({...fixture.alerts[0],rule:{...fixture.alerts[0].rule,level:5}}).action,'alert');
assert.equal(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,group:'project-week3'}}).action,'alert');
assert.equal(decide({...fixture.alerts[4],data:{...fixture.alerts[4].data,count:'1'}}).action,'alert');
assert.equal(decide({...fixture.alerts[8],data:{...fixture.alerts[8].data,count:'1'}}).action,'alert');
assert.equal(decide({...fixture.alerts[0],rule:{level:15,description:'원격 관리자 그룹 추가를 설명하는 수업 자료입니다.'}}).action,'record');
const result=await runXdr({root,moduleKey:'privilege',writeError:()=>assert.fail('invalid_decision')});
assert.deepEqual(result.counts,{block:9,alert:8,record:9});
const outputDirectory=await mkdtemp(join(tmpdir(),'xdr-privilege-test-'));
let time=Date.now();
// Explicit LOCAL registry simulation, never an operational account mapping.
const names=['user01','user02','user03','user04','user05','user06','user07','user08','admin01','svc-lab'];
const registry=new Map(names.map(name=>[name,Object.freeze({verified:true,classId:'class_fixture',
  projectId:'project_fixture',subjectId:createHash('sha256').update('local-privilege:'+name).digest('hex')})]));
const resolveSubject=async alert=>registry.get(alert.data.srcuser);
const pipeline=await respond({alerts:fixture.alerts,decideBase,resolveSubject,outputDirectory,
  clock:()=>time,logFile:join(outputDirectory,'alerts.log')});
const requestFor=name=>({...fixtureRequests().normal,subjectId:registry.get(name).subjectId});
for(const name of names.slice(0,8))assert.equal((await pipeline.enforce(requestFor(name))).decision,'deny');
const compromised=requestFor('user01'),healthy=requestFor('admin01');
assert.equal((await pipeline.enforce({...compromised,deviceId:'b'.repeat(16)})).decision,'deny');
assert.equal((await pipeline.enforce(healthy)).decision,'allow');
assert.equal((await pipeline.enforce(requestFor('svc-lab'))).decision,'allow');
for(const key of ['classId','projectId'])assert.equal((await pipeline.enforce({...compromised,[key]:'another_scope'})).decision,'allow');
assert.equal((await pipeline.enforce({...compromised,deviceRegistered:false})).reasonCode,'device_not_registered');
assert.equal((await pipeline.enforce({...fixtureRequests().suspicious,subjectId:compromised.subjectId})).decision,'step_up');
assert.equal(pipeline.rules.length,9);
assert.ok(Object.isFrozen(pipeline.rules)&&pipeline.rules.every(Object.isFrozen));
assert.equal((await readFile(join(outputDirectory,'alerts.log'),'utf8')).trim().split('\n').length,17);
assert.equal(JSON.stringify(pipeline.rules).includes('user01'),false);
const existingLog=join(outputDirectory,'existing.log');await writeFile(existingLog,'preserve\n');
const ruleFile=join(outputDirectory,'deny-rules.json'),rulesBefore=await readFile(ruleFile,'utf8');
for(const options of [
  {alerts:[fixture.alerts[0],{...fixture.alerts[17],id:fixture.alerts[0].id}],resolveSubject},
  {alerts:[null],resolveSubject},
  {alerts:[{...fixture.alerts[9],id:'token=sample-sensitive-value'}],resolveSubject},
  {alerts:[fixture.alerts[0]],resolveSubject:async()=>({...registry.get('user01'),verified:false})},
  {alerts:[fixture.alerts[0]],resolveSubject:async()=>({verified:true,subjectId:registry.get('user01').subjectId})},
  {alerts:[fixture.alerts[0]],resolveSubject:async()=>({...registry.get('user01'),subjectId:'token=sample-sensitive-value'})}
]){
  await assert.rejects(()=>respond({...options,decideBase,outputDirectory,logFile:existingLog,clock:()=>time}));
  assert.equal(await readFile(existingLog,'utf8'),'preserve\n');
  assert.equal(await readFile(ruleFile,'utf8'),rulesBefore);
}
const blockDecision={alertId:fixture.alerts[0].id,...decide(fixture.alerts[0])};
for(const decisions of [[],[blockDecision,blockDecision],[{...blockDecision,confidence:0.8}]])
  await assert.rejects(()=>buildDenyRules([fixture.alerts[0]],decisions,{resolveSubject,now:time}));
const normalPipeline=await respond({alerts:fixture.alerts.slice(17),decideBase,resolveSubject,outputDirectory,
  clock:()=>time,logFile:existingLog});
assert.equal(normalPipeline.rules.length,0);assert.equal(await readFile(existingLog,'utf8'),'preserve\n');
assert.equal((await normalPipeline.enforce(requestFor('user01'))).decision,'allow');
time+=900001;assert.equal((await pipeline.enforce(requestFor('user01'))).decision,'allow');
assert.equal(createHash('sha256').update(await readFile(fixtureFile)).digest('hex'),hash);
if(process.argv.includes('--write-example')){
  await respond({alerts:fixture.alerts,decideBase,resolveSubject,outputDirectory:join(root,'xdr','privilege')});
}
console.log(JSON.stringify({counts:result.counts,readerRows:rows.length,normalBlocked:0,standalone:true,
  actualBaseFunctionTested:true,localAccountRevocation:true,liveEngineConnected:false}));
