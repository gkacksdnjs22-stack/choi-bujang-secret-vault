import {isBlocked} from './deny-rules.mjs';
export function createEnforcer({decideBase,rules,now=()=>Date.now(),denyReasonCode='policy_denied'}){
  if(typeof decideBase!=='function'||!Array.isArray(rules)||!/^[a-z][a-z0-9_]{0,63}$/.test(denyReasonCode))
    throw TypeError('invalid_enforcer_configuration');
  return async request=>{
    const base=await decideBase(request);
    if(base?.decision!=='allow'||!isBlocked(request?.deviceId,rules,now()))return base;
    return {...base,decision:'deny',reasonCode:denyReasonCode,
      ruleIds:[...new Set([...base.ruleIds,'xdr_persistence'])]};
  };
}
