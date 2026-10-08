import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { decide } from './decide.mjs';
import { buildDenyRules } from './deny-rules.mjs';
import { createEnforcer } from './enforce.mjs';

// Caller supplies verified alerts and the existing policy. This module does
// not grant access, invent engine identity fields, or activate fixture IPs in production.
export async function respond({ alerts, decideBase, outputDirectory, clock = () => Date.now() }) {
  if (!Array.isArray(alerts) || typeof decideBase !== 'function') throw new TypeError('invalid_response_input');
  const decisions = alerts.map(alert => ({alertId:alert.id,...decide(alert)}));
  const rules = buildDenyRules(alerts, decisions, {now:clock()});
  await mkdir(outputDirectory, {recursive:true});
  await appendFile(join(outputDirectory,'alerts.log'), decisions.filter(d=>d.action!=='record')
    .map(d=>JSON.stringify(d)).join('\n')+'\n');
  await writeFile(join(outputDirectory,'deny-rules.json'), JSON.stringify({rules},null,2)+'\n');
  return { decisions, rules, enforce:createEnforcer({decideBase,rules,now:clock}) };
}
