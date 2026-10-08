// Self-contained judge module: no imports, filesystem, network, or credentials.
// Local thresholds derive from patterns.json; they are not MITRE-prescribed numbers.
const PATTERNS = Object.freeze(["repeated_password_guessing","password_spraying","uncertain_authentication_failures"]);
const decision = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason,
});
export function decide(alert) {
    const text = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
    const failures = Number(alert?.data?.count);
    const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
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
    return decision(0.5, 'uncertain_authentication_failures');

}
