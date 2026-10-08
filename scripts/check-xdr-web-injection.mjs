import assert from 'node:assert/strict';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/web-injection/decide.mjs';
import { readAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { respond } from '../xdr/web-injection/respond.mjs';
import { runXdr } from './xdr-run.mjs';
import { fileURLToPath } from 'node:url';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json',import.meta.url),'utf8'));
assert.equal((await readAlerts()).length,fixture.alerts.length);
const source=await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url),'utf8');
assert.ok(!/^\s*import\s/mu.test(source));
const isolated=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
for(let i=0;i<fixture.alerts.length;i++) {
  const a=fixture.alerts[i]; const out=isolated.decide(a);
  assert.deepEqual(out,decide({...a,id:'different-id'}));
  assert.equal(out.action,i<8?'block':i<17?'alert':'record');
}
for(const description of ['SQL 구문을 반복하지 말라는 정책 안내입니다.','스크립트 삽입 표식 9번 반복을 금지하는 수업입니다.','select 라는 수업 안내입니다.']) {
  assert.notEqual(decide({rule:{level:12,description},data:{count:20}}).action,'block');
}
const root=fileURLToPath(new URL('../',import.meta.url));
const errors=[];
const result=await runXdr({root,moduleKey:'web-injection',writeError:line=>errors.push(line)});
assert.deepEqual(errors,[]);
const outputDirectory=await mkdtemp(join(tmpdir(),'xdr-web-test-'));
let time=Date.now();
const base=r=>({schema:'aleph.decision.v1',requestId:r.requestId,decision:'allow',reasonCode:'approved',ruleIds:['local_test_baseline']});
const pipeline=await respond({alerts:fixture.alerts,decideBase:base,outputDirectory,
  logFile:join(outputDirectory,'alerts.log'),clock:()=>time});
const context=a=>({sourceAddress:a.data.srcip,registeredDenyReasonCode:'local_test_xdr_denied'});
for(let i=0;i<fixture.alerts.length;i++)assert.equal((await pipeline.enforce({requestId:'local'},context(fixture.alerts[i]))).decision,i<8?'deny':'allow');
assert.equal(pipeline.rules.length,8);
assert.equal((await readFile(join(outputDirectory,'alerts.log'),'utf8')).trim().split('\n').length,17);
time+=900001;
assert.equal((await pipeline.enforce({requestId:'local'},context(fixture.alerts[0]))).decision,'allow');
console.log(JSON.stringify({counts:result.counts,normalBlocked:0,standalone:true,localPipeline:true,liveEngineConnected:false}));
