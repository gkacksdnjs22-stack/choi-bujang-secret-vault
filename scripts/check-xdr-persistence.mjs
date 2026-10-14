import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {decide} from '../xdr/persistence/decide.mjs';
import {readAlerts,extractAlerts} from '../xdr/persistence/read-alerts.mjs';
import {respond} from '../xdr/persistence/respond.mjs';
import {runXdr} from './xdr-run.mjs';
import {decide as decideBase} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';

const raw=await readFile(new URL('../xdr/fixtures/persistence.json',import.meta.url));
const hash=createHash('sha256').update(raw).digest('hex');
assert.equal(hash,'1dd5adeab11f8b222ec5f4880955a4f428a29728098e139bcd9a3fc4b0f970d3');
const fixture=JSON.parse(raw),rows=await readAlerts();
assert.equal(rows.length,24);
assert.ok(rows.every(r=>Object.keys(r).sort().join()==='account,description,ruleLevel,sourceAddress,timestamp'));
for(const description of ['{"token":"sample-sensitive-value with spaces"}',"password='sample-sensitive-value'"]){
  const safe=extractAlerts({schema:fixture.schema,moduleKey:fixture.moduleKey,alerts:[{rule:{description}}]});
  assert.equal(JSON.stringify(safe).includes('sample-sensitive-value'),false);
}
const source=await readFile(new URL('../xdr/persistence/decide.mjs',import.meta.url),'utf8');
assert.equal(/^\s*import\b/m.test(source),false);
assert.equal(/\b(?:fetch|eval|Function|require)\s*\(/.test(source),false);
const isolated=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const patterns=JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json',import.meta.url),'utf8')).patterns;
for(let i=0;i<fixture.alerts.length;i++){
  const a=fixture.alerts[i],before=JSON.stringify(a),out=isolated.decide(a);
  assert.equal(out.action,i<8?'block':i<16?'alert':'record');
  assert.equal(JSON.stringify(a),before);assert.deepEqual(out,decide({...a,id:'unrelated-id'}));
  assert.deepEqual(Object.keys(out).sort(),['action','confidence','reason']);
  assert.ok(patterns.some(p=>p.name===out.reason&&p.condition&&p.evidence));
  assert.ok(out.confidence>=0&&out.confidence<=1);
}
assert.equal(decide(null).action,'record');
for(const a of fixture.alerts.slice(8,16))assert.notEqual(decide({...a,rule:{...a.rule,level:15}}).action,'block');
assert.equal(decide({...fixture.alerts[0],rule:{level:5,description:fixture.alerts[0].rule.description}}).action,'alert');
assert.equal(decide({rule:{level:15,description:'서명 없는 새 서비스 등록을 설명하는 수업 자료입니다.'},data:fixture.alerts[0].data}).action,'record');
const result=await runXdr({root:fileURLToPath(new URL('../',import.meta.url)),moduleKey:'persistence',writeError:()=>assert.fail('invalid_decision')});
assert.deepEqual(result.counts,{block:8,alert:8,record:8});
const outputDirectory=await mkdtemp(join(tmpdir(),'xdr-persistence-test-'));
let time=Date.now();
// Explicit local registry simulation, NOT inferred from the common agent name or IP.
const isolatedDevice='a'.repeat(16),healthyDevice='b'.repeat(16);
const resolveDevice=async()=>({verified:true,deviceId:isolatedDevice});
const pipeline=await respond({alerts:fixture.alerts,decideBase,resolveDevice,outputDirectory,
  clock:()=>time,logFile:join(outputDirectory,'alerts.log')});
const {normal,suspicious}=fixtureRequests();
const fromIsolated={...normal,deviceId:isolatedDevice},fromHealthy={...normal,deviceId:healthyDevice};
assert.equal((await pipeline.enforce(fromIsolated)).decision,'deny');
assert.equal((await pipeline.enforce(fromHealthy)).decision,'allow');
assert.equal((await pipeline.enforce({...fromIsolated,deviceRegistered:false})).reasonCode,'device_not_registered');
assert.equal((await pipeline.enforce({...suspicious,deviceId:isolatedDevice})).decision,'step_up');
assert.equal(pipeline.rules.length,8);
assert.equal((await readFile(join(outputDirectory,'alerts.log'),'utf8')).trim().split('\n').length,16);
const existingLog=join(outputDirectory,'existing.log');await writeFile(existingLog,'preserve\n');
const ruleFile=join(outputDirectory,'deny-rules.json'),rulesBefore=await readFile(ruleFile,'utf8');
for(const options of [
  {alerts:[fixture.alerts[0],{...fixture.alerts[16],id:fixture.alerts[0].id}],resolveDevice},
  {alerts:[{...fixture.alerts[8],id:'token=sample-sensitive-value'}],resolveDevice},
  {alerts:[fixture.alerts[0]],resolveDevice:async()=>({deviceId:isolatedDevice,verified:false})},
  {alerts:[fixture.alerts[0]],resolveDevice:async()=>({deviceId:fixture.alerts[0].agent.name,verified:true})}
]){
  await assert.rejects(()=>respond({...options,decideBase,outputDirectory,logFile:existingLog,clock:()=>time}));
  assert.equal(await readFile(existingLog,'utf8'),'preserve\n');assert.equal(await readFile(ruleFile,'utf8'),rulesBefore);
}
const normalPipeline=await respond({alerts:fixture.alerts.slice(16),decideBase,resolveDevice,outputDirectory,
  clock:()=>time,logFile:existingLog});
assert.equal(normalPipeline.rules.length,0);assert.equal(await readFile(existingLog,'utf8'),'preserve\n');
assert.equal((await normalPipeline.enforce(fromHealthy)).decision,'allow');
time+=900001;assert.equal((await pipeline.enforce(fromIsolated)).decision,'allow');
assert.equal(createHash('sha256').update(await readFile(new URL('../xdr/fixtures/persistence.json',import.meta.url))).digest('hex'),hash);
console.log(JSON.stringify({counts:result.counts,readerRows:rows.length,normalBlocked:0,
  standalone:true,actualBaseFunctionTested:true,localDeviceIsolation:true,liveEngineConnected:false}));
