// resolveSubject must be a SERVER-owned lookup of issuer/class/project-bound identity.
// Never copy a fixture username, Supabase UUID, IP or client assertion into subjectId.
const scopeKeys=['classId','projectId','subjectId'];
const safeId=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(value);
export async function buildDenyRules(alerts,decisions,{resolveSubject,now=Date.now(),ttlMs=15*60000}={}){
  if(!Array.isArray(alerts)||!Array.isArray(decisions)||typeof resolveSubject!=='function'
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
    const binding=await resolveSubject(byId.get(decision.alertId));
    if(binding?.verified!==true||scopeKeys.some(key=>!safeId(binding[key])))
      throw TypeError('verified_subject_mapping_required');
    rules.push(Object.freeze({ruleId:'xdr_privilege',...Object.fromEntries(scopeKeys.map(key=>[key,binding[key]])),
      alertId:decision.alertId,createdAt:new Date(now).toISOString(),expiresAt:new Date(now+ttlMs).toISOString()}));
  }
  if(seen.size!==byId.size)throw TypeError('incomplete_decisions');
  return Object.freeze(rules);
}
export function isBlocked(request,rules,now=Date.now()){
  return scopeKeys.every(key=>safeId(request?.[key]))&&rules.some(rule=>
    scopeKeys.every(key=>rule[key]===request[key])&&Date.parse(rule.createdAt)<=now&&Date.parse(rule.expiresAt)>now);
}
