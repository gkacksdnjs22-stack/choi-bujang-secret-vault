import {isIP} from 'node:net';
const scopeKeys=['classId','projectId'];
const safeId=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(value);
export function canonicalAddress(value){
  if(typeof value!=='string'||!isIP(value))return null;
  try{return isIP(value)===4?value:new URL(`http://[${value}]/`).hostname.slice(1,-1);}
  catch{return null;}
}
// SERVER-owned mapping: identify the protected class/project and actual destination.
export async function buildDenyRules(alerts,decisions,{resolveDestination,now=Date.now(),ttlMs=15*60000}={}){
  if(!Array.isArray(alerts)||!Array.isArray(decisions)||typeof resolveDestination!=='function'
      ||!Number.isFinite(now)||!Number.isFinite(ttlMs)||ttlMs<=0||ttlMs>3600000)
    throw TypeError('invalid_rule_input');
  const byId=new Map();
  for(const alert of alerts){
    if(!alert||typeof alert.id!=='string'||!/^[\w-]{1,80}$/u.test(alert.id)||byId.has(alert.id))
      throw TypeError('invalid_alert_identity');
    byId.set(alert.id,alert);
  }
  const rules=[],seen=new Set();
  for(const decision of decisions){
    if(!decision||!byId.has(decision.alertId)||seen.has(decision.alertId))throw TypeError('invalid_decision_identity');
    seen.add(decision.alertId);
    if(decision.action!=='block')continue;
    if(!Number.isFinite(decision.confidence)||decision.confidence<0.85||decision.confidence>1)
      throw TypeError('invalid_block_confidence');
    const alert=byId.get(decision.alertId),address=canonicalAddress(alert?.data?.dstip);
    const binding=await resolveDestination(alert);
    if(!address||binding?.verified!==true||scopeKeys.some(key=>!safeId(binding[key]))
        ||canonicalAddress(binding.destinationAddress)!==address)throw TypeError('verified_destination_mapping_required');
    rules.push(Object.freeze({ruleId:'xdr_exfiltration',...Object.fromEntries(scopeKeys.map(key=>[key,binding[key]])),
      destinationAddress:address,alertId:alert.id,createdAt:new Date(now).toISOString(),expiresAt:new Date(now+ttlMs).toISOString()}));
  }
  if(seen.size!==byId.size)throw TypeError('incomplete_decisions');
  return Object.freeze(rules);
}
export function isBlocked(request,verifiedDestination,rules,now=Date.now()){
  const address=canonicalAddress(verifiedDestination?.destinationAddress);
  if(verifiedDestination?.verified!==true||!address||scopeKeys.some(key=>!safeId(request?.[key])
      ||verifiedDestination[key]!==request[key]))throw TypeError('verified_request_destination_required');
  return rules.some(rule=>rule.destinationAddress===address&&scopeKeys.every(key=>rule[key]===request[key])
    &&Date.parse(rule.createdAt)<=now&&Date.parse(rule.expiresAt)>now);
}
