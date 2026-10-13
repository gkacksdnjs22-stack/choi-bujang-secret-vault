import {createProtectedFetch} from './request-proof.mjs';
const $=id=>document.getElementById(id),signed=createProtectedFetch(()=>({}));
for(let i=1;i<=41;i++){const item=document.createElement('li');item.textContent=`공식 시험 슬롯 ${String(i).padStart(2,'0')} · 미실행 · 개별 계약/결과 미수신`;$('official').append(item);}
async function summary(){
  $('refresh').disabled=true;
  try{
    const response=await signed('/api/operations');const result=await response.json();
    if(!response.ok)throw Error(`HTTP ${response.status} · ${result.error||'조회 실패'}`);
    $('summary').textContent=`실제 서버 응답 · ${result.checkedAt}\n요청 ID: ${result.requestId}\n판정 규칙: ${result.rules.join(', ')}\n현재 접속: ${result.registration.state} · 만료 ${result.registration.expiresAt}\n본인 메모 수: ${result.ownNoteCount}\n탐지 사건: 미연결 (0건으로 해석하지 않음)\n회수: 미실행 · 현재 접속 등록만 조회\n복구 사본 재검증: ${result.recovery.inspected}/${result.recovery.total}건\n`+result.recovery.versions.map((v,i)=>`${i+1}. ${v.state==='verified'?`검증됨 · 버전 ${v.version} · ${v.capturedAt} · 변경 ${(v.changedFields||[]).join(', ')||'없음'}`:'조회/검증 불가'}`).join('\n');
  }catch(error){$('summary').textContent='실제 결과 조회 실패 · '+error.message;}finally{$('refresh').disabled=false;}
}
$('refresh').onclick=summary;
$('clear').onclick=()=>{$('records').replaceChildren();$('testStatus').textContent='화면 기록만 비웠습니다. 서버 자료/등록부는 변경하지 않았습니다.';};
async function record(name,source,response,expected,validate=()=>true){
  const requestId=response.headers.get('X-Vault-Request-Id'),at=response.headers.get('X-Vault-Checked-At');
  let data;try{data=await response.json();}catch{}
  const passed=response.status===expected&&validate(data);
  const row=document.createElement('tr');
  for(const value of [name+' · '+source,`HTTP ${expected}`,`HTTP ${response.status} · ${passed?'일치':'불일치'}`,requestId||'서버 ID 미제공',at||'서버 시각 미제공']){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}
  $('records').append(row);return {data,passed};
}
$('run').onclick=async()=>{
  $('run').disabled=true;$('testStatus').textContent='실행 중';
  try{
    await record('공개 메모 제거','실제 API',await fetch('/data.json'),200,d=>Array.isArray(d?.notes)&&d.notes.length===0);
    await record('설치 manifest','실제 HTTP',await fetch('/manifest.webmanifest'),200,d=>d?.display==='standalone');
    await record('무인증 복구','실제 API',await fetch('/api/restore/'+crypto.randomUUID(),{method:'POST',credentials:'omit'}),401);
    const normal=await record('본인 목록','실제 API',await signed('/api/notes',{headers:{'Content-Type':'application/json'}}),200,Array.isArray);
    if(!normal.passed)throw Error('정상 접근 실패로 이후 시험을 중단합니다.');
    if(normal.data.length)await record('본인 단건','실제 API',await signed('/api/notes/'+normal.data[0].id),200);
    const id=$('otherId').value.trim();
    if(id){if(!/^[a-f0-9-]{36}$/i.test(id)||normal.data.some(note=>note.id===id))throw Error('타인 시험 ID를 확인하세요.');await record('타인 단건','실제 API',await signed('/api/notes/'+id),403);}
    await record('무인증 목록','실제 API',await fetch('/api/notes',{credentials:'omit'}),401);
    await record('서명 없는 목록','실제 API',await fetch('/api/notes'),403,d=>d?.reasonCode==='app_proof_invalid');
    const randomId=crypto.randomUUID();
    await record('서명 없는 변경','실제 API',await fetch('/api/notes/'+randomId,{method:'PUT',headers:{'Content-Type':'application/json'},body:'{}'}),403);
    const pathChange=createProtectedFetch(()=>({}),(path,options)=>fetch('/api/announcements',options));
    await record('서명 뒤 경로 변조','실제 API',await pathChange('/api/notes'),403,d=>d?.reasonCode==='app_proof_invalid');
    const bodyChange=createProtectedFetch(()=>({}),(path,options)=>fetch(path,{...options,body:'{"title":"changed","body":"virtual changed"}'}));
    await record('서명 뒤 본문 변조','실제 API',await bodyChange('/api/notes/'+randomId,{method:'PUT',headers:{'Content-Type':'application/json'},body:'{"title":"virtual","body":"virtual"}'}),403,d=>d?.reasonCode==='app_proof_invalid');
    await record('구역 밖 경로','실제 API',await signed('/api/notes/all'),400);
    let captured;const once=createProtectedFetch(()=>({}),(path,options)=>{captured={path,options};return fetch(path,options);});
    await record('단회 최초 요청','실제 API',await once('/api/notes'),200);
    await record('서명 재사용','실제 API',await fetch(captured.path,captured.options),403,d=>d?.reasonCode==='app_proof_invalid');
    for(const name of ['s06-unregistered','s07-compound','s08-own','s08-ownership','s09-burst-read'])await record(name,'실제 HTTP / 고정 가상 입력',await fetch('/api/checks?case='+name),200,d=>d?.source==='fixed_virtual_fixture'&&d?.ready===true);
    $('testStatus').textContent='시험 실행 완료 · 각 행의 일치/불일치를 확인하세요. 타인 ID 미입력 시 타인 시험은 미실행입니다. 공식 41종 결과와 별개입니다.';
  }catch(error){$('testStatus').textContent='시험 중단 · '+error.message;}finally{$('run').disabled=false;}
};

async function loadReceipt(){
  $('receiptRefresh').disabled=true;
  try{
    const response=await fetch('/api/checks',{cache:'no-store'}),data=await response.json();
    if(!response.ok||!['total','blocked','failed','notRun'].every(k=>Number.isInteger(data[k])&&data[k]>=0)
      ||data.total!==data.blocked+data.failed+data.notRun)throw Error('기록 검증 실패');
    $('receipt').textContent=`실제 읽기 요청 기록 · ${data.checkedAt}\n검사한 커밋: ${data.commit}\n점검 항목: ${data.total}\n조건 충족: ${data.blocked}\n조건 불충족: ${data.failed}\n미실행: ${data.notRun}\n출처: ${data.source}`;
  }catch{$('receipt').textContent='서버 점검 기록을 읽지 못했습니다. 수치를 표시하지 않습니다.';}
  finally{$('receiptRefresh').disabled=false;}
}
$('receiptRefresh').onclick=loadReceipt;
loadReceipt();
