// Same six-field receipt contract as the official sample. No inferred totals.
async function loadOps() {
  const cells=document.querySelectorAll('#ops-stats dd');
  for(const cell of cells)cell.textContent='-';
  try{
    const response=await fetch('/api/checks',{cache:'no-store',headers:{accept:'application/json'}});
    const data=await response.json();
    if(!response.ok||!['total','blocked','failed','notRun'].every(k=>Number.isInteger(data[k])&&data[k]>=0)
      ||data.total!==data.blocked+data.failed+data.notRun)throw Error('invalid_receipt');
    for(const cell of cells)cell.textContent=String(data[cell.dataset.k]);
    document.getElementById('ops-meta').textContent=`기록 시각 ${data.checkedAt} · 검사한 커밋 ${data.commit}`;
  }catch{document.getElementById('ops-meta').textContent='서버 점검 기록을 읽지 못했습니다. 수치를 표시하지 않습니다.';}
}
loadOps();
