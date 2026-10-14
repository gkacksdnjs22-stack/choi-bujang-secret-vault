import {isBlocked} from './deny-rules.mjs';
export function createEnforcer({decideBase,rules,now=()=>Date.now(),denyReasonCode='policy_denied'}){
  if(typeof decideBase!=='function'||typeof now!=='function'||!Array.isArray(rules)
      ||!/^[a-z][a-z0-9_]{0,63}$/u.test(denyReasonCode))throw TypeError('invalid_enforcer_configuration');
  const snapshot=Object.freeze(rules.map(rule=>Object.freeze({...rule})));
  return async request=>{
    const base=await decideBase(request);
    if(base?.decision!=='allow'||!isBlocked(request,snapshot,now()))return base;
    return {...base,decision:'deny',reasonCode:denyReasonCode,
      ruleIds:[...new Set([...base.ruleIds,'xdr_privilege'])]};
  };
}
