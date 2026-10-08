import { isIP } from 'node:net';

// This adapter consumes a trusted source address separately from the ZTNA request.
// The current decision contract has no source-IP field, so it is not wired into src/decider.mjs.
export function buildDenyRules(alerts, decisions, { now = Date.now(), ttlMs = 15 * 60_000 } = {}) {
  if (!Number.isFinite(now) || !Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > 3600_000) {
    throw new TypeError('invalid_rule_lifetime');
  }
  const byId = new Map(alerts.map(a => [a.id, a]));
  return decisions.filter(d => d.action === 'block' && d.confidence >= 0.85).map(d => {
    const alert = byId.get(d.alertId);
    const address = alert?.data?.srcip;
    if (!isIP(address ?? '') || !/^[\w-]{1,80}$/u.test(d.alertId)) throw new TypeError('invalid_block_evidence');
    return {ruleId:'xdr_brute_force', sourceAddress:address, alertId:d.alertId,
      createdAt:new Date(now).toISOString(), expiresAt:new Date(now + ttlMs).toISOString()};
  });
}

export function isBlocked(sourceAddress, rules, now = Date.now()) {
  return Boolean(isIP(sourceAddress ?? '') && rules.some(r => r.sourceAddress === sourceAddress
    && Date.parse(r.createdAt) <= now && Date.parse(r.expiresAt) > now));
}
