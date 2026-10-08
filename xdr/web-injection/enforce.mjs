import { isBlocked } from './deny-rules.mjs';

// Engine integration boundary: sourceAddress must come from a verified engine
// transport context, never the browser body or the 18-field decision request.
// Existing policy decisions are preserved unless an active XDR rule denies.
export function createEnforcer({ decideBase, rules, now = () => Date.now() }) {
  if (typeof decideBase !== 'function' || !Array.isArray(rules)) {
    throw new TypeError('invalid_enforcer_configuration');
  }
  return async function enforce(request, trustedTransportContext) {
    const base = await decideBase(request);
    if (base?.decision !== 'allow') return base;
    const time = now();
    const address = trustedTransportContext?.sourceAddress;
    if (!isBlocked(address, rules, time)) return base;
    // Do not invent an engine reasonCode: the integration must explicitly
    // supply one registered by the operating engine before it is usable.
    const reasonCode = trustedTransportContext?.registeredDenyReasonCode;
    if (typeof reasonCode !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(reasonCode)) {
      throw new TypeError('registered_xdr_reason_code_required');
    }
    return {...base, decision:'deny', reasonCode,
      ruleIds:[...new Set([...base.ruleIds, 'xdr_web_injection'])]};
  };
}
