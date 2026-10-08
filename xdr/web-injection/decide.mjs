// Standalone sandbox module; thresholds are local policy, not MITRE prescribed.
const PATTERNS = Object.freeze({
  sql_injection:'SQL 구문·데이터베이스 조회를 요청에 이어 붙이는 반복 시도',
  script_injection:'스크립트 삽입 표식이 반복되는 요청',
  path_traversal:'여러 단계 경로 이탈 표식이 반복되는 요청',
  command_injection:'명령 구분자 표식이 연속되는 요청',
  ambiguous_web_input:'일회성 특이 입력 또는 주입과 구별하기 어려운 경보',
  normal_web_event:'주입 신호 없는 정상 자료·화면 조회',
});
const result = (confidence, reason) => ({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason});
export function decide(alert) {
  const text = typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level = Number.isInteger(alert?.rule?.level)?alert.rule.level:0;
  const count = Number(alert?.data?.count);
  const repeat = Number.isFinite(count)&&count>=5 || /(?:[5-9]|[1-9]\d+)번.*(?:반복|들어왔|있습니다)|반복.*(?:[5-9]|[1-9]\d+)번/u.test(text);
  const educational = /수업|정책|금지.*안내|예방.*안내/u.test(text);
  let pattern;
  if (/SQL.*(?:구문|표식)|데이터베이스 조회.*이어 붙/u.test(text)) pattern='sql_injection';
  else if (/스크립트.*(?:삽입|표식)/u.test(text)) pattern='script_injection';
  else if (/경로.*(?:이탈|거슬러)/u.test(text)) pattern='path_traversal';
  else if (/명령 구분자/u.test(text)) pattern='command_injection';
  if (pattern && repeat && level>=10 && !educational
      && !/반복은 없습니다|반복되지|삽입 표식은 아닙니다|공격 표기는 없습니다/u.test(text)) return result(0.95,pattern);
  if (level>=5 && /검색|주소|경로|SQL|스크립트|주입|구분 문자/u.test(text)) return result(0.5,'ambiguous_web_input');
  return result(0.1,'normal_web_event');
}
