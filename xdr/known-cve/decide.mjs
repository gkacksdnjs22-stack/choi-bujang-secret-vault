// Standalone: no imports, IO, network calls, lookup evaluation or alert-ID answers.
// Patterns copied from patterns.json. Severity/confidence combinations are local policy.
const PATTERNS=Object.freeze({
  remote_jndi_request:/\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns)\s*:\/\/[^{}]+\}/iu,
  possible_cve_probe:/CVE-2021-44228|jndi|log4j|log4shell|취약점|원격 조회|조회 형태|중괄호|점검 도구|라이브러리|scanner/iu,
  normal_request:'원격 조회나 관련 의심 신호가 없는 정상 이벤트'
});
const result=(confidence,reason)=>({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason});
export function decide(alert){
  const data=alert?.data;
  const request=['useragent','url'].map(key=>typeof data?.[key]==='string'?data[key]:'');
  const description=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number.isInteger(alert?.rule?.level)?alert.rule.level:0;
  if(request.some(text=>PATTERNS.remote_jndi_request.test(text)))
    return result(level>=10?0.95:0.7,'remote_jndi_request');
  if(level>=5 && [...request,description].some(text=>PATTERNS.possible_cve_probe.test(text)))
    return result(0.55,'possible_cve_probe');
  return result(0.1,'normal_request');
}
