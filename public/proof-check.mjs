import {createProtectedFetch} from './request-proof.mjs';
document.getElementById('run').onclick=async()=>{
  const button=document.getElementById('run'),output=document.getElementById('result');button.disabled=true;output.textContent='검사 중';
  const results=[];
  const record=async(label,response,expected)=>{
    let data;try{data=await response.json();}catch{}
    const passed=response.status===expected&&(expected!==403||data?.reasonCode==='app_proof_invalid');
    results.push(`${label}: HTTP ${response.status} · ${passed?'통과':'실패'}${data?.reasonCode?' · '+data.reasonCode:''}${data?.proofStage?' · '+data.proofStage:''}`);
    return data;
  };
  try{
    const signed=createProtectedFetch(()=>({}));
    const notes=await record('정상 서명',await signed('/api/notes'),200);
    if(!Array.isArray(notes))throw Error('본인 정상 요청을 먼저 확인해야 합니다.');
    await record('서명 누락',await fetch('/api/notes'),403);
    const changedPath=createProtectedFetch(()=>({}),(path,options)=>fetch('/api/announcements',options));
    await record('서명 뒤 경로 변경',await changedPath('/api/notes'),403);
    const missingId=crypto.randomUUID();if(notes.some(note=>note.id===missingId))throw Error('시험 ID 충돌');
    const changedBody=createProtectedFetch(()=>({}),(path,options)=>fetch(path,{...options,body:JSON.stringify({title:'virtual changed',body:'virtual changed after signing'})}));
    await record('서명 뒤 본문 변경',await changedBody('/api/notes/'+missingId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:'virtual',body:'virtual'})}),403);
    let captured;
    const capture=createProtectedFetch(()=>({}),(path,options)=>{captured={path,options};return fetch(path,options);});
    await record('단회 요청 최초 실행',await capture('/api/notes'),200);
    await record('동일 서명 재사용',await fetch(captured.path,captured.options),403);
    output.textContent=results.join('\n')+'\n이 검증은 자체 자료실 HTTP 결과이며 운영 ALEPH 앱 서명 연결을 뜻하지 않습니다.';
  }catch(error){output.textContent=results.join('\n')+'\n검사 중단: '+error.message;}
  finally{button.disabled=false;}
};
