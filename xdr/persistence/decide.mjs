// Standalone pattern matching; no import, IO, network or OS/service actions.
const PATTERNS=Object.freeze({
  unsigned_service:'서명 없는 서비스 생성/변경과 임시 파일 또는 원격 반복 등록',
  unfamiliar_task:'낯선 예약 작업과 임시 실행 파일',
  unexpected_autostart:'새 Startup 항목 또는 복수 자동 실행 지점/재부팅 지속',
  possible_persistence:'확정되지 않은 서비스·작업·시작 항목 변경',
  normal_event:'기존 정상 서비스·작업·읽기 또는 지속성 신호 없음',
  temp_executable:/\\(?:temp|tmp)\\[^\\]+\.exe$/iu,
  startup_path:/\\Startup\\/iu
});
const output=(confidence,reason)=>({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason});
export function decide(alert){
  const text=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number.isInteger(alert?.rule?.level)?alert.rule.level:0;
  const path=typeof alert?.data?.path==='string'?alert.data.path:'';
  const count=Number(alert?.data?.count);
  const temp=PATTERNS.temp_executable.test(path);
  const unfamiliar=/평소 목록에 없는|처음 보는|임의 문자열/u.test(text);
  const unsigned=/서명\s*(?:이\s*)?(?:없는|없습니다)/u.test(text);
  const service=/서비스/u.test(text),task=/예약 작업/u.test(text);
  const change=/등록|추가|바뀌|변경|새 서비스/u.test(text);
  const benign=/수업 자료|정책 안내|읽기만|등록은 없습니다|실행 파일은 그대로|서명된 채/u.test(text);
  if(level>=10&&!benign){
    if(service&&change&&unsigned&&(temp||(/원격/u.test(text)&&Number.isFinite(count)&&count>=3)))
      return output(0.96,'unsigned_service');
    if(task&&unfamiliar&&temp)return output(0.95,'unfamiliar_task');
    if((unfamiliar&&PATTERNS.startup_path.test(path)&&/추가/u.test(text))
      ||(service&&unfamiliar&&temp&&/다시 켜도|재부팅/u.test(text))
      ||(task&&temp&&/시작 프로그램/u.test(text)&&/같은|함께/u.test(text)))
      return output(0.93,'unexpected_autostart');
  }
  if(/수업 자료|정책 안내|읽기만|서명된 채/u.test(text))return output(0.1,'normal_event');
  if(level>=5&&(service||task||/시작 항목|시작 폴더|시작 프로그램|임시 폴더/u.test(text)||temp))
    return output(0.55,'possible_persistence');
  return output(0.1,'normal_event');
}
