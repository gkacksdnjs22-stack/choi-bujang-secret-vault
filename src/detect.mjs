// 원본 3항목 연습 계약입니다. 검증된 사건만 전달하며 자료 본문을 보관하지 않습니다.
const WINDOW_MS=600000, LIMIT=120;
function burst(times) {
  times.sort((a,b)=>a-b);
  let start=0;
  for(let end=0;end<times.length;end++) {
    while(times[end]-times[start]>=WINDOW_MS) start++;
    if(end-start+1>LIMIT) return true;
  }
  return false;
}
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const subjects=new Map();
  for(const event of events) {
    const sub=event?.identity?.sub, at=Date.parse(event?.at);
    if(event?.method!=='GET'||typeof sub!=='string'||!sub||!Number.isFinite(at)) continue;
    if(!subjects.has(sub)) subjects.set(sub,[]);
    subjects.get(sub).push(at);
  }
  for(const [subject,times] of subjects) if(burst(times))
    return {action:'propose_revocation',reasonCode:'burst_read',subject};
  return { action: 'observe' };
}

// 아래는 로컬 전용 합성 기기 계약이며 운영 엔진 입력 계약을 뜻하지 않습니다.
// 안내의 복합 조건을 별도 검증합니다. 실제 회수나 등록 변경은 실행하지 않습니다.
export function detectDeviceEvents(events) {
  if(!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const groups=new Map();
  for(const event of events) {
    const at=Date.parse(event?.at), subject=event?.subjectId, deviceId=event?.deviceId;
    if(event?.source!=='local_virtual_fixture'||event.method!=='GET'||event.decision!=='allow'
      ||typeof subject!=='string'||!subject||!/^[a-f0-9]{16}$/.test(deviceId??'')
      ||!Number.isFinite(at)||!['usual','unusual'].includes(event.network)) continue;
    const key=JSON.stringify([subject,deviceId]);
    if(!groups.has(key)) groups.set(key,{subject,deviceId,events:[]});
    // 필요한 값만 복사하며 추가 본문·토큰은 보관하지 않습니다.
    groups.get(key).events.push({at,unusual:event.network==='unusual'});
  }
  for(const {subject,deviceId,events:items} of groups.values()) {
    items.sort((a,b)=>a.at-b.at);
    let start=0,unusual=0;
    for(let end=0;end<items.length;end++) {
      unusual+=Number(items[end].unusual);
      while(items[end].at-items[start].at>=WINDOW_MS) unusual-=Number(items[start++].unusual);
      if(end-start+1>LIMIT&&unusual>0)
        return {action:'propose_revocation',reasonCode:'burst_read',subject,deviceId};
    }
  }
  return {action:'observe'};
}
