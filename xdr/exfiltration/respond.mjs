import {appendFile,mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {decide} from './decide.mjs';
import {buildDenyRules} from './deny-rules.mjs';
import {createEnforcer} from './enforce.mjs';
export async function respond({alerts,decideBase,resolveDestination,resolveRequestDestination,outputDirectory,
    clock=()=>Date.now(),logFile=new URL('../alerts.log',import.meta.url),denyReasonCode='policy_denied'}){
  if(!Array.isArray(alerts)||typeof decideBase!=='function'||typeof clock!=='function')throw TypeError('invalid_response_input');
  const decisions=alerts.map(alert=>({alertId:alert?.id,...decide(alert)}));
  const rules=await buildDenyRules(alerts,decisions,{resolveDestination,now:clock()});
  const enforce=createEnforcer({decideBase,rules,resolveRequestDestination,now:clock,denyReasonCode});
  await mkdir(outputDirectory,{recursive:true});
  const notifications=decisions.filter(d=>d.action!=='record').map(d=>JSON.stringify(d));
  if(notifications.length)await appendFile(logFile,notifications.join('\n')+'\n');
  await writeFile(join(outputDirectory,'deny-rules.json'),JSON.stringify({
    schema:'aleph.xdr.deny-candidates.local.v1',liveConnected:false,rules},null,2)+'\n');
  return {decisions,rules,enforce};
}
