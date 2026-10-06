const $=id=>document.getElementById(id); let session=null;
const message=text=>{$('status').textContent=text};
async function api(path='',method='GET',body){const r=await fetch('/api/notes'+path,{method,headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok)throw Error(data.error||'요청 실패');return data}
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
async function load(){try{const notes=await api();$('notes').replaceChildren(...notes.map(noteCard));message(notes.length?'':'아직 내 메모가 없습니다. 가상 메모를 추가해 주세요.')}catch(e){message(e.message)}}
async function render(next){session=next;$('login').hidden=!!session;$('workspace').hidden=!session;$('notes').replaceChildren();if(session){sessionStorage.setItem('byte-back-access-token',session.access_token);$('account').textContent='로그인 완료';await load()}else{sessionStorage.removeItem('byte-back-access-token');message('로그인 후 자료를 볼 수 있습니다.')}}
$('loginForm').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})});const data=await r.json();$('password').value='';if(!r.ok)message(data.error||'로그인 정보를 확인하세요.');else await render({access_token:data.access_token})};
$('logout').onclick=async()=>{await render(null)};
$('newNote').onsubmit=async e=>{e.preventDefault();try{await api('','POST',{title:$('title').value,body:$('body').value});$('newNote').reset();await load();message('추가했습니다.')}catch(e){message(e.message)}};
const savedToken=sessionStorage.getItem('byte-back-access-token');if(savedToken)await render({access_token:savedToken});else await render(null);
