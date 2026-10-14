import {isBlocked} from './deny-rules.mjs';
// resolveRequestDestination belongs to server configuration, not the browser body.
export function createEnforcer({decideBase,rules,resolveRequestDestination,now=()=>Date.now(),denyReasonCode='policy_denied'}){
  if(typeof decideBase!=='function'||typeof resolveRequestDestination!=='function'||typeof now!=='function'
      ||!Array.isArray(rules)||!/^[a-z][a-z0-9_]{0,63}$/u.test(denyReasonCode))
    throw TypeError('invalid_enforcer_configuration');
  const snapshot=Object.freeze(rules.map(rule=>Object.freeze({...rule})));
  return async request=>{
    const base=await decideBase(request);
    if(base?.decision!=='allow')return base;
    const destination=await resolveRequestDestination(request);
    if(!isBlocked(request,destination,snapshot,now()))return base;
    return {...base,decision:'deny',reasonCode:denyReasonCode,
      ruleIds:[...new Set([...base.ruleIds,'xdr_exfiltration'])]};
  };
}
