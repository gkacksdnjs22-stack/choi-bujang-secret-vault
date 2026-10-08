import { readFile } from 'node:fs/promises';
import { extractAlerts } from './read-alerts.mjs';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const names = new Set(patterns.map(p => p.name));
const decision = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});

// Injection point for an official Jev adapter. No guessed endpoint or credentials.
export function createDecider({ askJev = null, timeoutMs = 1500 } = {}) {
  return async function decide(alert) {
    const [safe] = extractAlerts({schema:'aleph.xdr.fixture.v1', moduleKey:'brute-force', alerts:[alert]});
    const text = safe.description;
    const failures = Number(alert?.data?.count);
    const level = safe.ruleLevel ?? 0;
    const authFailure = /(?:로그인|비밀번호).*실패|실패.*(?:로그인|비밀번호)/u.test(text);
    const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some(x => /^T1110(?:\.|$)/u.test(x));
    const minutes = text.match(/(\d+)분/u);
    const shortWindow = !minutes || Number(minutes[1]) <= 5;
    const spray = /(?:여러|서로 다른).*계정.*같은 비밀번호/u.test(text)
      || (/계정\s*(\d+)개/u.test(text) && Number(text.match(/계정\s*(\d+)개/u)[1]) >= 10
        && /같은 간격/u.test(text) && authFailure);
    if (level >= 10 && spray) return decision(0.95, 'password_spraying');
    if (authFailure && failures >= 20 && shortWindow && (mitre || level >= 10)) {
      return decision(0.95, 'repeated_password_guessing');
    }
    const uncertain = (authFailure && (failures >= 2 || level >= 5))
      || (/실패/u.test(text) && level >= 5);
    if (!uncertain) return decision(0.1, 'normal_authentication_event');
    if (!askJev) return decision(0.5, 'uncertain_authentication_failures: jev_unavailable');
    let timer;
    try {
      const response = await Promise.race([
        Promise.resolve().then(() => askJev(safe, patterns)),
        new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);}),
      ]);
      if (!Number.isFinite(response?.confidence) || response.confidence < 0 || response.confidence > 1
          || !names.has(response.pattern)) throw new Error('invalid_jev_response');
      return decision(response.confidence, response.pattern);
    } catch {
      return decision(0.5, 'uncertain_authentication_failures: jev_unavailable');
    } finally {clearTimeout(timer);}
  };
}

export const decide = createDecider();
