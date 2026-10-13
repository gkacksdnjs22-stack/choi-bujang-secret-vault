// Official sample case IDs; paths are adapted to this deployment. GET only.
export async function runAttackChecks(config) {
  const base=new URL(typeof config==='string'?config:config.publicAppUrl), attempts=[];
  const denied=(status,data,text)=>[401,403,404,405].includes(status)&&!hasNotes(text);
  const hasNotes=text=>/"(?:content|body)"\s*:/u.test(text);
  async function probe(attackId,stage,path,expected,accepts=denied,headers={}) {
    try {
      const response=await fetch(new URL(path,base),{method:'GET',headers:{accept:'application/json',...headers},
        redirect:'manual',signal:AbortSignal.timeout(10000),alephEvidence:{caseId:attackId,requestKey:'read'}});
      const text=await response.text();let data;try{data=JSON.parse(text);}catch{}
      const ready=typeof data?.ready==='boolean'?data.ready:undefined;
      attempts.push({attackId,stage,expected,observed:`HTTP ${response.status}${ready===undefined?'':'; jsonReady='+ready}`,
        result:accepts(response.status,data,text)?'blocked':'breached'});
    }catch{attempts.push({attackId,stage,expected,observed:'not_run',result:'not_run'});}
  }
  await probe('s02-static-copy',2,'/notes.json','정적 메모 사본 거부');
  await probe('s03-unauth-list',3,'/api/notes','무로그인 목록 거부');
  await probe('s03-fake-token',3,'/api/notes','위조 토큰 거부',denied,{authorization:'Bearer invalid'});
  const id='00000000-0000-4000-8000-000000000001';
  await probe('s04-query-identity',4,`/api/notes?userId=${id}&role=instructor`,'쿼리 신원으로 접근 불가');
  await probe('s04-header-identity',4,'/api/notes','헤더 신원으로 접근 불가',denied,{'x-user-id':id,'x-role':'instructor'});
  await probe('s05-direct-table',5,'/rest/v1/notes','자료실 원본 테이블 경로 직접 조회 거부');
  await probe('s08-other-zone',8,'/api/announcements','무로그인 공지 거부');
  for(const [caseId,stage] of [['s06-unregistered',6],['s07-compound',7],['s08-unknown-route',8],
    ['s08-all-notes',8],['s08-write-notice',8],['s09-burst-read',9]]) {
    await probe(caseId,stage,'/api/checks?case='+caseId,'공식 고정 가상 금지 조건 확인 (실계정 시험 아님)',
      (status,data)=>status===200&&data?.source==='fixed_virtual_fixture'&&data.ready===true);
  }
  return attempts.sort((a,b)=>a.stage-b.stage);
}
