const $=id=>document.getElementById(id); let session=null; let recoveryPreview=null;
const authHeaders=()=>session?.access_token?{Authorization:'Bearer '+session.access_token}:{};
const message=text=>{$('status').textContent=text};
async function api(path='',method='GET',body){const r=await fetch('/api/notes'+path,{method,headers:{...authHeaders(),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok)throw Error(data.error||'요청 실패');return data}
function noteCard(note) {
  const card=document.createElement('article'); card.className='note-card';
  const row=document.createElement('div'); row.className='note-row';
  const heading=document.createElement('button'); heading.className='note-title'; heading.textContent=note.title;
  const detail=document.createElement('div'); detail.className='note-detail'; detail.id='note-'+note.id; detail.hidden=true;
  heading.setAttribute('aria-expanded','false'); heading.setAttribute('aria-controls',detail.id);
  const text=document.createElement('p'); text.className='note-body'; text.textContent=note.body;
  const edit=document.createElement('button'); edit.textContent='수정'; edit.className='note-edit';
  const remove=document.createElement('button'); remove.textContent='삭제'; remove.className='note-delete';
  heading.onclick=()=>{detail.hidden=!detail.hidden;heading.setAttribute('aria-expanded',String(!detail.hidden));};
  const form=document.createElement('form'); form.className='note-editor'; form.hidden=true;
  const title=document.createElement('input'); title.value=note.title; title.required=true; title.maxLength=200; title.setAttribute('aria-label','메모 제목');
  const body=document.createElement('textarea'); body.value=note.body; body.required=true; body.maxLength=10000; body.setAttribute('aria-label','메모 본문');
  const actions=document.createElement('div'); actions.className='note-actions';
  const save=document.createElement('button'); save.textContent='저장';
  const cancel=document.createElement('button'); cancel.textContent='취소'; cancel.type='button'; cancel.className='note-cancel';
  const finish=()=>{form.hidden=true;heading.hidden=false;edit.hidden=false;remove.hidden=false;};
  edit.onclick=()=>{title.value=note.title;body.value=note.body;detail.hidden=true;heading.setAttribute('aria-expanded','false');form.hidden=false;heading.hidden=true;edit.hidden=true;remove.hidden=true;title.focus();};
  cancel.onclick=finish;
  form.onsubmit=async e=>{e.preventDefault();save.disabled=true;try{await api('/'+note.id,'PUT',{title:title.value,body:body.value});note.title=title.value;note.body=body.value;heading.textContent=note.title;text.textContent=note.body;finish();message('수정했습니다.');}catch(e){message(e.message)}finally{save.disabled=false}};
  remove.onclick=async()=>{try{await api('/'+note.id,'DELETE');await load();message('삭제했습니다.')}catch(e){message(e.message)}};
  actions.append(save,cancel);form.append(title,body,actions);row.append(heading,edit,remove);detail.append(text);card.append(row,detail,form);return card;
}
async function load(){try{const notes=await api();$('notes').replaceChildren(...notes.map(noteCard));message(notes.length?'':'아직 내 메모가 없습니다. 가상 메모를 추가해 주세요.')}catch(e){$('notes').replaceChildren();$('workspace').hidden=true;$('approvalPanel').hidden=false;message(e.message)}}
async function refreshApproval(){
  $('notes').replaceChildren();$('workspace').hidden=true;$('approvalPanel').hidden=false;
  try{const response=await fetch('/api/device',{headers:authHeaders()});const data=await response.json();
    if(response.status===401){await render(null);message('다시 로그인해 주세요.');return;}
    if(!response.ok)throw Error(data.error||'승인 상태 확인 실패');
    $('approvalStatus').textContent=data.registered?'서버 확인: 승인된 기기':'서버 확인: 승인 대기 · 보호 자료는 숨겨져 있습니다.';
    $('requestApproval').hidden=data.registered;
    if(data.registered){$('approvalPanel').hidden=true;$('workspace').hidden=false;$('account').textContent='로그인 완료 · 서버가 기기 승인 확인';await load();}
  }catch(error){$('approvalStatus').textContent=error.message+' · 보호 자료를 표시하지 않습니다.';}
}
async function render(next){
  session=next;recoveryPreview=null;$('restorePreview').textContent='';$('restoreResult').textContent='';$('restoreForm').reset();
  $('accessResult').textContent='';$('accessCheck').reset();$('deviceInfo').textContent='';$('notes').replaceChildren();
  $('login').hidden=!!session;$('workspace').hidden=true;$('approvalPanel').hidden=!session;
  if(session)await refreshApproval();else message('로그인 후 자료를 볼 수 있습니다.');
}
$('refreshApproval').onclick=refreshApproval;
$('requestApproval').onclick=async()=>{
  const button=$('requestApproval');button.disabled=true;
  try{const response=await fetch('/api/device',{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:'{}'});const data=await response.json();
    if(!response.ok||data.requested!==true)throw Error(data.error||'승인 요청 실패');
    $('approvalStatus').textContent='승인 요청 접수 · 관리자의 승인 후 상태를 다시 확인하세요. 요청만으로 권한은 생기지 않습니다.';
  }catch(error){$('approvalStatus').textContent=error.message;}finally{button.disabled=false;}
};
$('loginForm').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})});const data=await r.json();$('password').value='';if(!r.ok)message(data.error||'로그인 정보를 확인하세요.');else await render({access_token:data.access_token})};
$('logout').onclick=async()=>{await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({logout:true})});await render(null)};
$('newNote').onsubmit=async e=>{e.preventDefault();try{const added=await api('','POST',{title:$('title').value,body:$('body').value});$('newNote').reset();await load();message('추가했습니다. 메모 ID: '+added.id)}catch(e){message(e.message)}};
$('deviceStatus').onclick=async()=>{if(!session)return;const button=$('deviceStatus');button.disabled=true;try{const response=await fetch('/api/device',{headers:authHeaders()});const data=await response.json();if(!response.ok)throw Error(data.error||'접속 확인 실패');$('deviceInfo').textContent=[data.registered?'접속 등록 완료':'접속 등록 대기','계정 ID: '+data.userId,'실습 범위: '+data.classId,'프로젝트: '+data.projectId,'사용자 식별자: '+data.subjectId,'브라우저 식별자: '+data.deviceId].join('\n');}catch(e){$('deviceInfo').textContent=e.message}finally{button.disabled=false}};
$('accessCheck').onsubmit=async e=>{e.preventDefault();if(!session)return;const id=$('checkNoteId').value.trim();const result=$('accessResult');if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)){result.textContent='올바른 메모 ID를 입력하세요.';return}const button=$('checkAccess');button.disabled=true;try{const response=await fetch('/api/notes/'+encodeURIComponent(id),{headers:authHeaders()});const data=await response.json();result.textContent=`HTTP ${response.status} · `+(response.ok?'조회 허용':(data.reasonCode||data.error||'조회 거부'));}catch{result.textContent='응답을 확인할 수 없습니다.'}finally{button.disabled=false}};
async function recoveryRequest(id,body){
  const response=await fetch('/api/restore/'+encodeURIComponent(id),{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await response.json();if(!response.ok)throw Error('HTTP '+response.status+' · '+(data.reasonCode||data.error||'복구 거부'));
  return data;
}
function invalidateRecoveryPreview(){recoveryPreview=null;$('restorePreview').textContent='';$('restoreConfirm').checked=false;}
$('restoreNoteId').oninput=invalidateRecoveryPreview;
$('previewRestore').onclick=async()=>{
  if(!session)return;invalidateRecoveryPreview();const id=$('restoreNoteId').value.trim().toLowerCase();
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)){$('restoreResult').textContent='올바른 메모 ID를 입력하세요.';return;}
  const button=$('previewRestore');button.disabled=true;
  try{const data=await recoveryRequest(id,{preview:true});
    if(data.id!==id||data.verified!==true)throw Error('사본 검증 실패');
    if($('restoreNoteId').value.trim().toLowerCase()!==id)return;
    recoveryPreview=data;const names={title:'제목',content:'본문',create:'삭제된 메모 한 건 다시 생성'};
    $('restorePreview').textContent=['사본 검증 완료','사본 시각: '+data.capturedAt,'사본 버전: '+data.version,'대상 ID: '+data.id,'변경 항목: '+(data.changedFields.map(field=>names[field]).join(', ')||'없음'),'다른 메모와 기존 감사 기록은 보존합니다.'].join('\n');
    $('restoreResult').textContent='버전과 변경 항목을 확인한 뒤 복구를 실행하세요.';
  }catch(error){$('restoreResult').textContent=error.message;}finally{button.disabled=false;}
};
$('restoreForm').onsubmit=async e=>{
  e.preventDefault();if(!session)return;const id=$('restoreNoteId').value.trim().toLowerCase();const output=$('restoreResult');
  if(!recoveryPreview||recoveryPreview.id!==id||!$('restoreConfirm').checked){output.textContent='먼저 사본을 검증하고 버전·변경 항목을 확인하세요.';return;}
  const button=$('restoreNote');button.disabled=true;
  try{const data=await recoveryRequest(id,{expectedVersion:recoveryPreview.version,expectedState:recoveryPreview.stateVersion});
    if(data.verified!==true||data.id!==id)throw Error('복구 결과 확인 필요');
    output.textContent='HTTP 200 · 복구 완료 · 사본 재검증 및 대상 ID·소유자·본문 지문 확인';
    invalidateRecoveryPreview();await load();
  }catch(error){invalidateRecoveryPreview();output.textContent=error.message+' · 사본을 다시 검증하세요.';}finally{button.disabled=false;}
};
// 이전 단계의 저장 토큰은 한 번 서버로 이전하고 즉시 삭제합니다. 새 토큰은 저장하지 않습니다.
const legacyToken=sessionStorage.getItem('byte-back-access-token');sessionStorage.removeItem('byte-back-access-token');
if(legacyToken){try{await fetch('/api/auth',{method:'POST',headers:{Authorization:'Bearer '+legacyToken,'Content-Type':'application/json'},body:JSON.stringify({adopt:true})});}catch{}}
await render(legacyToken?{access_token:legacyToken}:{});
let installPrompt;
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();installPrompt=event;$('installApp').hidden=false;});
$('installApp').onclick=async()=>{if(installPrompt){await installPrompt.prompt();installPrompt=null;$('installApp').hidden=true;}};
function networkStatus(){$('networkStatus').textContent=navigator.onLine?'':'오프라인입니다. 보호 자료는 서버 연결 후 다시 확인합니다.';if(!navigator.onLine){$('notes').replaceChildren();$('workspace').hidden=true;}}
window.addEventListener('offline',networkStatus);window.addEventListener('online',()=>{networkStatus();if(session)refreshApproval();});networkStatus();
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});
