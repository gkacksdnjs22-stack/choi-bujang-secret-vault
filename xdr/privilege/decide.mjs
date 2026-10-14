// Standalone course-alert classification: no imports, IO, network or account changes.
const PATTERNS=Object.freeze({
  unusual_admin_membership:'원격 관리자 그룹 추가 또는 반복·다수 계정 관리자 편입',
  new_admin_execution:'막 승격된/평범한 계정의 관리자 명령 실행',
  unusual_hours_execution:'업무 밖 시각과 낯선 주소 또는 그룹 추가·명령의 결합',
  changed_session_authority:'낯선 주소의 세션 권한 변경 또는 다른 계정 권한 사용',
  possible_privilege_change:'불완전한 권한·그룹 변경 또는 관리자 명령 경보',
  normal_event:'평소 로그인·읽기·관리 작업 등 권한 상승 증거 없음'
});
const output=(confidence,reason)=>({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason});
export function decide(alert){
  const text=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number.isInteger(alert?.rule?.level)?alert.rule.level:0;
  const group=typeof alert?.data?.group==='string'?alert.data.group.toLowerCase():'';
  const count=Number(alert?.data?.count);
  const adminGroup=group==='administrators'&&/관리자 그룹/u.test(text);
  const command=/관리자 명령|권한 명령|명령 실행/u.test(text)&&/실행/u.test(text);
  const unfamiliar=/처음 보는|처음 봅니다/u.test(text);
  const outside=/수업 시간 밖|업무처럼 보이지 않는 시각|업무 시간 밖/u.test(text);
  const incomplete=/취소|실패|변경은 없습니다|명령은 없습니다|관리자 그룹은 아닙니다|설명만/u.test(text);
  const educational=/수업 자료|정책 안내|읽기만/u.test(text);
  if(level>=10&&!incomplete&&!educational){
    if(adminGroup&&((/추가/u.test(text)&&/원격/u.test(text))
        ||(/추가/u.test(text)&&Number.isFinite(count)&&count>=3)
        ||(/빠진 계정/u.test(text)&&/다시 관리자로/u.test(text)&&Number.isFinite(count)&&count>=2)))
      return output(0.96,'unusual_admin_membership');
    if(command&&(/방금 관리자가 된/u.test(text)||(/평범한 계정/u.test(text)&&adminGroup)))
      return output(0.96,'new_admin_execution');
    if(outside&&command&&(unfamiliar||(adminGroup&&/추가/u.test(text))))
      return output(0.94,'unusual_hours_execution');
    if((/세션/u.test(text)&&/관리자 권한으로 바뀌/u.test(text)&&unfamiliar)
        ||(command&&/다른 계정의 권한/u.test(text)))
      return output(0.96,'changed_session_authority');
  }
  if(educational)return output(0.1,'normal_event');
  if(level>=5&&/권한|그룹|계정 종류|관리자 명령/u.test(text))
    return output(0.55,'possible_privilege_change');
  return output(0.1,'normal_event');
}
