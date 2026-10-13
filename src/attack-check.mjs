// Actual requests only. Never include tokens or note bodies in the bundle.
export async function runAttackChecks(config) {
  const app=new URL(config.publicAppUrl);
  const attempts=[];
  for(const method of ['GET','POST','PUT','DELETE']) {
    const path=['PUT','DELETE'].includes(method)?'/api/notes/00000000-0000-4000-8000-000000000001':'/api/notes';
    const r=await fetch(new URL(path,app),{method,redirect:'error',signal:AbortSignal.timeout(10000),
      alephEvidence:{caseId:`anonymous_${method.toLowerCase()}`,requestKey:'read'}});
    attempts.push({attackId:`anonymous_${method.toLowerCase()}`,expected:'무로그인 자료 요청 거부',observed:`HTTP ${r.status}${r.status===401?' 인증 거부 확인':' 예상과 다름'}`});
  }
  const r=await fetch(new URL('/api/notes',app),{headers:{Authorization:'Bearer invalid'},signal:AbortSignal.timeout(10000),
    alephEvidence:{caseId:'invalid_token',requestKey:'read'}});
  attempts.push({attackId:'invalid_token',expected:'잘못된 토큰 요청 거부',observed:`HTTP ${r.status}`});
  const zone = await fetch(new URL('/api/announcements',app),{redirect:'error',signal:AbortSignal.timeout(10000),
    alephEvidence:{caseId:'s08-other-zone',requestKey:'read'}});
  attempts.push({attackId:'s08-other-zone',expected:'무로그인 공지 API 거부 (인증된 타인 소유권 점검은 별도)',observed:`HTTP ${zone.status}`});
  for (const caseId of ['s06-unregistered','s07-compound','s08-own','s08-ownership','s08-unknown-route','s08-all-notes','s08-write-notice','s09-burst-read','s09-device-compound']) {
    const response = await fetch(new URL('/api/checks?case='+caseId,app),{redirect:'error',signal:AbortSignal.timeout(10000),
      alephEvidence:{caseId,requestKey:'read'}});
    let result;
    try {result=await response.json();} catch {result=null;}
    attempts.push({attackId:caseId,expected:'고정 가상 DB에서 정상 허용과 구역/기기/위험 규칙 검증 (실제 계정 시험 아님)',
      observed:`HTTP ${response.status}; virtualReady=${result?.source==='fixed_virtual_fixture'&&result?.ready===true}; decisions=${result?.checks?.map(item=>item.decision).join(',')??result?.action??'unavailable'}`});
  }
  if(config.step>=10){
    for(const method of ['POST','GET']){
      const result=await fetch(new URL('/api/restore/00000000-0000-4000-8000-000000000001',app),{method,redirect:'error',signal:AbortSignal.timeout(10000)});
      attempts.push({attackId:`s10_restore_${method.toLowerCase()}`,expected:method==='POST'?'무로그인 복구 401 거부':'복구 경로의 GET 405 거부',observed:`HTTP ${result.status}`});
    }
  }
  if(config.step>=11){
    const manifestResponse=await fetch(new URL('/manifest.webmanifest',app),{redirect:'error',signal:AbortSignal.timeout(10000)});
    let manifest;try{manifest=await manifestResponse.json();}catch{manifest=null;}
    attempts.push({attackId:'s11-manifest',expected:'설치형 웹앱 manifest 공개',observed:`HTTP ${manifestResponse.status}; standalone=${manifest?.display==='standalone'}; icons=${manifest?.icons?.length??0}`});
    const deviceResponse=await fetch(new URL('/api/device',app),{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',redirect:'error',signal:AbortSignal.timeout(10000)});
    attempts.push({attackId:'s11-anonymous-approval',expected:'무로그인 기기 승인 신청 거부',observed:`HTTP ${deviceResponse.status}`});
  }
  if(config.step>=12){
    const response=await fetch(new URL('/api/operations',app),{redirect:'error',signal:AbortSignal.timeout(10000)});
    attempts.push({attackId:'s12-anonymous-operations',expected:'무로그인 작전실 요약 거부',observed:`HTTP ${response.status}`});
  }
  return attempts;
}
