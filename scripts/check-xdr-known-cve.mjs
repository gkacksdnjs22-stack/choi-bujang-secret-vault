import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {decide} from '../xdr/known-cve/decide.mjs';
import {readAlerts,extractAlerts} from '../xdr/known-cve/read-alerts.mjs';
import {respond} from '../xdr/known-cve/respond.mjs';
import {runXdr} from './xdr-run.mjs';
import {decide as decideBase} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';

const raw=await readFile(new URL('../xdr/fixtures/known-cve.json',import.meta.url));
const hash=createHash('sha256').update(raw).digest('hex');
assert.equal(hash,'db2dad63fd08f4da6de25135c1744357809290cd3f960570bb1eb5a848cde046');
const fixture=JSON.parse(raw),rows=await readAlerts();
assert.equal(rows.length,fixture.alerts.length);
assert.ok(rows.every(row=>Object.keys(row).sort().join()==='account,description,ruleLevel,sourceAddress,timestamp'));
const masked=extractAlerts({schema:fixture.schema,moduleKey:fixture.moduleKey,alerts:[{
  timestamp:'time',rule:{level:6,description:'token=sample-sensitive-value'},data:{srcuser:'password=sample-sensitive-value'}}]});
assert.equal(JSON.stringify(masked).includes('sample-sensitive-value'),false);
for(const description of ['{"token": "sample-sensitive-value with spaces"}',
  "api_key='sample-sensitive-value with spaces'",'password = "sample-sensitive-value\\\" escaped"']){
  const safe=extractAlerts({schema:fixture.schema,moduleKey:fixture.moduleKey,alerts:[{rule:{description}}]});
  assert.equal(JSON.stringify(safe).includes('sample-sensitive-value'),false);
  assert.equal(JSON.stringify(safe).includes('with spaces'),false);
}
const source=await readFile(new URL('../xdr/known-cve/decide.mjs',import.meta.url),'utf8');
assert.equal(/^\s*import\b/m.test(source),false);
assert.equal(/\b(?:fetch|eval|Function|require)\s*\(/.test(source),false);
const isolated=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const patterns=JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json',import.meta.url),'utf8')).patterns;
for(let i=0;i<fixture.alerts.length;i++){
  const a=fixture.alerts[i],before=JSON.stringify(a),out=isolated.decide(a);
  assert.equal(out.action,i<8?'block':i<16?'alert':'record');
  assert.equal(JSON.stringify(a),before);
  assert.deepEqual(out,decide({...a,id:'unrelated-id'}));
  assert.ok(patterns.some(p=>p.name===out.reason&&p.evidence&&p.source));
  assert.deepEqual(Object.keys(out).sort(),['action','confidence','reason']);
}
assert.equal(decide(null).action,'record');
assert.notEqual(decide({rule:{level:15,description:'CVE-2021-44228 수업 자료'},data:{url:'/docs'}}).action,'block');
assert.equal(decide({rule:{level:15,description:'정상 문서'},data:{url:'/docs'}}).action,'record');
assert.equal(decide({...fixture.alerts[0],rule:{level:5,description:'검토 필요'}}).action,'alert');
const errors=[],root=fileURLToPath(new URL('../',import.meta.url));
const result=await runXdr({root,moduleKey:'known-cve',writeError:line=>errors.push(line)});
assert.deepEqual(errors,[]);assert.deepEqual(result.counts,{block:8,alert:8,record:8});
const outputDirectory=await mkdtemp(join(tmpdir(),'xdr-known-cve-test-'));
let time=Date.now();
const pipeline=await respond({alerts:fixture.alerts,decideBase,outputDirectory,
  clock:()=>time,logFile:join(outputDirectory,'alerts.log')});
const {normal,suspicious}=fixtureRequests();
const context=a=>({sourceAddress:a.data.srcip,httpObservation:a.data,registeredDenyReasonCode:'local_test_xdr_denied'});
for(let i=0;i<fixture.alerts.length;i++)
  assert.equal((await pipeline.enforce(normal,context(fixture.alerts[i]))).decision,i<8?'deny':'allow');
assert.equal((await pipeline.enforce({...normal,deviceRegistered:false},context(fixture.alerts[0]))).reasonCode,'device_not_registered');
assert.equal((await pipeline.enforce(suspicious,context(fixture.alerts[0]))).decision,'step_up');
await assert.rejects(()=>pipeline.enforce(normal,{sourceAddress:fixture.alerts[0].data.srcip,httpObservation:fixture.alerts[0].data}),/registered_xdr_reason_code_required/);
assert.equal((await pipeline.enforce(normal,{...context(fixture.alerts[0]),httpObservation:{url:'/health'}})).decision,'allow');
assert.equal((await pipeline.enforce(normal,{sourceAddress:fixture.alerts[0].data.srcip})).decision,'allow');
assert.equal((await pipeline.enforce({...normal,srcip:fixture.alerts[0].data.srcip},{})).decision,'deny');
const normalLog=join(outputDirectory,'normal-only.log');
await writeFile(normalLog,'existing log\n');
const normalPipeline=await respond({alerts:fixture.alerts.slice(16),decideBase,outputDirectory,
  logFile:normalLog,clock:()=>time});
assert.equal(normalPipeline.rules.length,0);assert.equal(await readFile(normalLog,'utf8'),'existing log\n');
const duplicateLog=join(outputDirectory,'duplicate-evidence.log');
const rulesBeforeInvalid=await readFile(join(outputDirectory,'deny-rules.json'),'utf8');
await assert.rejects(()=>respond({alerts:[fixture.alerts[0],{...fixture.alerts[16],id:fixture.alerts[0].id}],
  decideBase,outputDirectory,logFile:duplicateLog,clock:()=>time}),/invalid_alert_identity/);
await assert.rejects(()=>readFile(duplicateLog),{code:'ENOENT'});
await assert.rejects(()=>respond({alerts:[{...fixture.alerts[8],id:'token=sample-sensitive-value'}],
  decideBase,outputDirectory,logFile:duplicateLog,clock:()=>time}),/invalid_alert_identity/);
await assert.rejects(()=>readFile(duplicateLog),{code:'ENOENT'});
assert.equal(await readFile(join(outputDirectory,'deny-rules.json'),'utf8'),rulesBeforeInvalid);
assert.equal(pipeline.rules.length,8);
assert.equal((await readFile(join(outputDirectory,'alerts.log'),'utf8')).trim().split('\n').length,16);
time+=900001;
assert.equal((await pipeline.enforce(normal,context(fixture.alerts[0]))).decision,'allow');
assert.equal(createHash('sha256').update(await readFile(new URL('../xdr/fixtures/known-cve.json',import.meta.url))).digest('hex'),hash);
console.log(JSON.stringify({counts:result.counts,readerRows:rows.length,normalBlocked:0,
  standalone:true,actualBaseFunction:true,localPipeline:true,liveEngineConnected:false}));
