import assert from 'node:assert/strict';
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { runXdr } from './xdr-run.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { buildDenyRules, isBlocked } from '../xdr/brute-force/deny-rules.mjs';
import { createEnforcer } from '../xdr/brute-force/enforce.mjs';
import { decide as originalDecider } from '../src/decider.mjs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const source = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url),'utf8');
assert.ok(!/^\s*import\s/mu.test(source));
const standalone = await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
for(const alert of fixture.alerts) assert.deepEqual(standalone.decide(alert),decide(alert));
const errors = [];
const result = await runXdr({root, moduleKey:'brute-force', writeError:line => errors.push(line)});
assert.deepEqual(errors, []);
// Independent expected behavior from the published fixture descriptions; no answer key is used.
for (let i = 0; i < fixture.alerts.length; i++) {
  assert.equal(result.decisions[i].action, i < 10 ? 'block' : i < 19 ? 'alert' : 'record');
}
assert.equal(decide({...fixture.alerts[0],id:'changed',data:{...fixture.alerts[0].data,srcip:'192.0.2.250'}}).action,'block');
const now = Date.now();
const rules = buildDenyRules(fixture.alerts, result.decisions, {now});
assert.equal(rules.length, 10);
assert.ok(isBlocked(fixture.alerts[0].data.srcip, rules, now));
assert.ok(!isBlocked(fixture.alerts[19].data.srcip, rules, now));
assert.ok(!isBlocked(fixture.alerts[0].data.srcip, rules, now + 15 * 60_000));
const request = {schema:'aleph.decision.v1',requestId:'local-replay'};
const allowed = {schema:request.schema,requestId:request.requestId,decision:'allow',reasonCode:'approved',ruleIds:['local_test_baseline']};
const enforce = createEnforcer({decideBase:async()=>allowed,rules,now:()=>now});
const context = address => ({sourceAddress:address,registeredDenyReasonCode:'local_test_xdr_denied'});
assert.equal((await enforce(request,context(fixture.alerts[0].data.srcip))).decision,'deny');
assert.deepEqual(await enforce(request,context(fixture.alerts[19].data.srcip)),allowed);
assert.deepEqual(await enforce({...request,sourceAddress:fixture.alerts[0].data.srcip},{}),allowed);
assert.deepEqual(await createEnforcer({decideBase:async()=>allowed,rules,now:()=>now+15*60_000})(request,context(fixture.alerts[0].data.srcip)),allowed);
const original = await originalDecider(request);
assert.deepEqual(await createEnforcer({decideBase:originalDecider,rules})(request,context(fixture.alerts[0].data.srcip)),original);
await assert.rejects(()=>enforce(request,{sourceAddress:fixture.alerts[0].data.srcip}),/registered_xdr_reason_code_required/);
await writeFile(new URL('../xdr/brute-force/deny-candidates.json', import.meta.url),
  JSON.stringify({schema:'aleph.xdr.deny-candidates.local.v1', liveConnected:false, rules},null,2)+'\n');
await appendFile(new URL('../xdr/alerts.log', import.meta.url), result.decisions.filter(d=>d.action!=='record')
  .map(d=>JSON.stringify({alertId:d.alertId,action:d.action,confidence:d.confidence,reason:d.reason})).join('\n')+'\n');
console.log(JSON.stringify({counts:result.counts,normalBlocked:0,ruleCandidates:rules.length,
  judgeStandalone:true,ztnaLiveConnected:false}));
