import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

// Only these fields leave the reader; raw data, tokens and passwords are omitted.
function safeText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/\bBearer\s+\S+/giu, '[REDACTED]')
    .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu, '[REDACTED]')
    .replace(/\b(?:sb_secret_|sk-)[\w-]+/gu, '[REDACTED]')
    .replace(/((?:password|passwd|token|secret|api[_ -]?key|비밀번호|토큰|비밀키)\s*[:=]\s*)\S+/giu, '$1[REDACTED]')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gu, '[REDACTED]');
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_brute_force_fixture');
  }
  return fixture.alerts.map(alert => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts(file = new URL('../fixtures/brute-force.json', import.meta.url)) {
  return extractAlerts(JSON.parse(await readFile(file, 'utf8')));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    for (const alert of await readAlerts()) console.log(JSON.stringify(alert));
  } catch {
    console.error('경보 파일 형식을 확인해 주세요.');
    process.exitCode = 1;
  }
}
