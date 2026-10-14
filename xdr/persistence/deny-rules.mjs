// resolveDevice is a SERVER-owned registry lookup, never an alert/browser assertion.
export async function buildDenyRules(alerts,decisions,{resolveDevice,now=Date.now(),ttlMs=15*60000}={}){
  if(!Array.isArray(alerts)||!Array.isArray(decisions)||typeof resolveDevice!=='function'
    ||!Number.isFinite(now)||!Number.isFinite(ttlMs)||ttlMs<=0||ttlMs>3600000)throw TypeError('invalid_rule_input');
  const byId=new Map();
  for(const alert of alerts){
    if(!alert||typeof alert.id!=='string'||!/^[\w-]{1,80}$/u.test(alert.id)||byId.has(alert.id))throw TypeError('invalid_alert_identity');
    byId.set(alert.id,alert);
  }
  const rules=[];
  for(const decision of decisions){
    if(decision.action!=='block'||!Number.isFinite(decision.confidence)||decision.confidence<0.85||decision.confidence>1)continue;
    const alert=byId.get(decision.alertId);
    if(!alert)throw TypeError('invalid_block_evidence');
    const device=await resolveDevice(alert);
    if(device?.verified!==true||!/^[a-f0-9]{16}$/.test(device?.deviceId??''))throw TypeError('verified_device_mapping_required');
    rules.push({ruleId:'xdr_persistence',deviceId:device.deviceId,alertId:alert.id,
      createdAt:new Date(now).toISOString(),expiresAt:new Date(now+ttlMs).toISOString()});
  }
  return rules;
}
export function isBlocked(deviceId,rules,now=Date.now()){
  return /^[a-f0-9]{16}$/.test(deviceId??'')&&rules.some(rule=>rule.deviceId===deviceId
    &&Date.parse(rule.createdAt)<=now&&Date.parse(rule.expiresAt)>now);
}
