// Standalone course-alert classification. No imports, IO, network or file transfer.
const PATTERNS=Object.freeze({
  unfamiliar_bulk_transfer:'낯선 목적지로 다수 자료의 큰 전송',
  unusual_archive_transfer:'업무 밖 또는 연속·복수 목적지 압축 파일의 큰 전송',
  repeated_large_transfer:'같은 목적지로 반복되는 큰 전송 또는 명령 통로 반복 반출',
  alternate_channel_transfer:'평소와 다른 포트의 다수 자료 전송 또는 자료실 전체 외부 복사',
  possible_exfiltration:'작거나 불완전한 전송·압축·평소 대비 변화 신호',
  normal_event:'평소 자료 조회·동기화·저장 등 유출 증거 없음',
  largeBytes:50000000,bulkFiles:50,repeatCount:5
});
const output=(confidence,reason)=>({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence,reason});
const number=value=>{
  if(typeof value!=='number'&&(typeof value!=='string'||!/^\d+$/u.test(value)))return null;
  const parsed=Number(value);return Number.isSafeInteger(parsed)&&parsed>=0?parsed:null;
};
export function decide(alert){
  const text=typeof alert?.rule?.description==='string'?alert.rule.description:'';
  const level=Number.isInteger(alert?.rule?.level)?alert.rule.level:0;
  const bytes=number(alert?.data?.bytes),files=number(alert?.data?.files),count=number(alert?.data?.count);
  const large=bytes!==null&&bytes>=PATTERNS.largeBytes;
  const unfamiliar=/처음 보는/u.test(text);
  const outside=/수업 시간 밖|업무 시간 밖/u.test(text);
  const archive=/압축 파일/u.test(text);
  const incomplete=/실패|아직 없습니다|전송은 없습니다|큰 파일은 아닙니다|수업 자료|정책 안내/u.test(text);
  if(level>=10&&large&&!incomplete){
    if(unfamiliar&&files!==null&&files>=PATTERNS.bulkFiles)
      return output(0.96,'unfamiliar_bulk_transfer');
    if(archive&&unfamiliar&&(outside||(files!==null&&files>=2&&/연속|두 곳/u.test(text))))
      return output(0.95,'unusual_archive_transfer');
    if(count!==null&&count>=PATTERNS.repeatCount&&/같은 목적지|명령 통로/u.test(text)
        &&/반복|전송이/u.test(text))return output(0.95,'repeated_large_transfer');
    if((/평소에 쓰지 않던 포트/u.test(text)&&files!==null&&files>=PATTERNS.bulkFiles&&/연속 전송/u.test(text))
        ||(/짧은 시간/u.test(text)&&/자료실 전체/u.test(text)&&/외부 주소/u.test(text)&&/복사/u.test(text)
          &&files!==null&&files>=PATTERNS.bulkFiles))
      return output(0.97,'alternate_channel_transfer');
  }
  if(/수업 자료.*설명|정책 안내/u.test(text))return output(0.1,'normal_event');
  if(level>=5&&/전송|목적지|압축|파일|자료.*읽힌/u.test(text))return output(0.55,'possible_exfiltration');
  return output(0.1,'normal_event');
}
