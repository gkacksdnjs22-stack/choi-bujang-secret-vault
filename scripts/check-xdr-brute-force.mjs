import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { runXdr } from './xdr-run.mjs';
import { createDecider } from '../xdr/brute-force/decide.mjs';
import { buildDenyRules, isBlocked } from '../xdr/brute-force/deny-rules.mjs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const errors = [];
const result = await runXdr({root, moduleKey:'brute-force', writeError:line => errors.push(line)});
assert.deepEqual(errors, []);
// Independent expected behavior from the published fixture descriptions; no answer key is used.
for (let i = 0; i < fixture.alerts.length; i++) {
  assert.equal(result.decisions[i].action, i < 10 ? 'block' : i < 19 ? 'alert' : 'record');
}
const uncertain = fixture.alerts[10];
assert.equal((await createDecider({askJev:async()=>({confidence:0.9,pattern:'repeated_password_guessing'})})(uncertain)).action,'block');
assert.equal((await createDecider({askJev:async()=>{throw new Error();}})(uncertain)).action,'alert');
assert.equal((await createDecider({askJev:()=>new Promise(()=>{}),timeoutMs:10})(uncertain)).action,'alert');
assert.equal((await createDecider({askJev:async()=>({confidence:NaN,pattern:'invented'})})(uncertain)).action,'alert');
assert.equal((await createDecider()( {...fixture.alerts[0], id:'changed', data:{...fixture.alerts[0].data,srcip:'192.0.2.250'}})).action,'block');
const now = Date.now();
const rules = buildDenyRules(fixture.alerts, result.decisions, {now});
assert.equal(rules.length, 10);
assert.ok(isBlocked(fixture.alerts[0].data.srcip, rules, now));
assert.ok(!isBlocked(fixture.alerts[19].data.srcip, rules, now));
assert.ok(!isBlocked(fixture.alerts[0].data.srcip, rules, now + 15 * 60_000));
await writeFile(new URL('../xdr/brute-force/deny-candidates.json', import.meta.url),
  JSON.stringify({schema:'aleph.xdr.deny-candidates.local.v1', liveConnected:false, rules},null,2)+'\n');
await writeFile(new URL('../xdr/alerts.log', import.meta.url), result.decisions.filter(d=>d.action!=='record')
  .map(d=>JSON.stringify({alertId:d.alertId,action:d.action,confidence:d.confidence,reason:d.reason})).join('\n')+'\n');
console.log(JSON.stringify({counts:result.counts,normalBlocked:0,ruleCandidates:rules.length,
  jevLiveConnected:false,ztnaLiveConnected:false}));
