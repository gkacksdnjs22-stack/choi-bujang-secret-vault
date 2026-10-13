// Read-only deployment probes. Evidence metadata is not a header or URL parameter.
export async function runAttackChecks(config) {
  const base = new URL(config.publicAppUrl), attempts = [];
  const skipped = (attackId, stage, expected) => attempts.push({attackId, stage, expected, observed:'not_run', result:'not_run'});
  async function probe(attackId, stage, path, expected, accepts, headers = {}) {
    let response;
    try {
      response = await fetch(new URL(path, base), {method:'GET', headers, redirect:'error',
        signal:AbortSignal.timeout(10000), alephEvidence:{caseId:attackId, requestKey:'read'}});
    } catch { skipped(attackId, stage, expected); return; }
    let data; try {data = await response.json();} catch {}
    const ready = typeof data?.ready === 'boolean' ? data.ready : undefined;
    attempts.push({attackId, stage, expected,
      observed:`HTTP ${response.status}${ready === undefined ? '' : '; jsonReady='+ready}`,
      result:accepts(response.status,data) ? 'blocked' : 'breached'});
  }
  const unauthorized = status => status === 401;
  await probe('anonymous_get',3,'/api/notes','무로그인 목록 거부',unauthorized);
  for(const method of ['post','put','delete']) skipped('anonymous_'+method,3,'쓰기 시험은 별도 실행');
  await probe('invalid_token',3,'/api/notes','잘못된 토큰 거부',unauthorized,{Authorization:'Bearer invalid'});
  await probe('s08-other-zone',8,'/api/announcements','무로그인 공지 조회 거부',unauthorized);
  for(const caseId of ['s06-unregistered','s07-compound','s08-own','s08-ownership','s08-unknown-route','s08-all-notes','s08-write-notice','s09-burst-read','s09-device-compound']) {
    await probe(caseId,Number(caseId.slice(1,3)),'/api/checks?case='+caseId,
      '고정 가상 입력의 정상 허용/금지 거부 조건 충족 (실계정 시험 아님)',
      (status,data)=>status===200&&data?.source==='fixed_virtual_fixture'&&data?.ready===true);
  }
  if(config.step>=10){
    skipped('s10_restore_post',10,'쓰기 복구 시험은 별도 실행');
    await probe('s10_restore_get',10,'/api/restore/00000000-0000-4000-8000-000000000001','복구 GET 거부',status=>status===405);
  }
  if(config.step>=11){
    await probe('s11-manifest',11,'/manifest.webmanifest','설치 manifest 제공',
      (status,data)=>status===200&&data?.display==='standalone'&&data?.icons?.length>=2);
    skipped('s11-anonymous-approval',11,'쓰기 승인 신청 시험은 별도 실행');
  }
  if(config.step>=12) await probe('s12-anonymous-operations',12,'/api/operations','무로그인 작전실 요약 거부',unauthorized);
  return attempts;
}
