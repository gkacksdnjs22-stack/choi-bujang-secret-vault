import { isIP } from 'node:net';
import { createHash } from 'node:crypto';

// This separate transport-context contract belongs to the local adapter,
// not the operating engine's 18-field decision request.
export function requestFingerprint(observation) {
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)) return null;
  const fields=['url','useragent'].map(key=>typeof observation[key]==='string'?observation[key]:'');
  if(!fields.some(Boolean))return null;
  return createHash('sha256').update(JSON.stringify(fields)).digest('hex');
}

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
    const fingerprint=requestFingerprint(alert?.data);
    if (!isIP(address ?? '') || !fingerprint || !/^[\w-]{1,80}$/u.test(d.alertId)) throw new TypeError('invalid_block_evidence');
    return {ruleId:'xdr_known_cve', sourceAddress:address, alertId:d.alertId,
      requestFingerprint:fingerprint,
      createdAt:new Date(now).toISOString(), expiresAt:new Date(now + ttlMs).toISOString()};
  });
}

export function isBlocked(sourceAddress, observation, rules, now = Date.now()) {
  const fingerprint=requestFingerprint(observation);
  return Boolean(isIP(sourceAddress ?? '') && rules.some(r => r.sourceAddress === sourceAddress
    && fingerprint && r.requestFingerprint===fingerprint
    && Date.parse(r.createdAt) <= now && Date.parse(r.expiresAt) > now));
}
