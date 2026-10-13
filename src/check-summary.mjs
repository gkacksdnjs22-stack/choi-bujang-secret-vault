// A claimed outcome alone is not a complete observation record.
export function summarizeChecks(receipt) {
  if(!receipt || !/^[a-f0-9]{40}$/.test(receipt.commit) || !Number.isFinite(Date.parse(receipt.checkedAt))
    || !Array.isArray(receipt.attackAttempts) || !receipt.attackAttempts.length)throw Error('invalid_check_receipt');
  const virtualBlocks=new Set(['s06-unregistered','s07-compound','s08-ownership','s08-unknown-route',
    's08-all-notes','s08-write-notice','s09-burst-read','s09-device-compound']);
  const outcomes=receipt.attackAttempts.map(a=>{
    if(!a||typeof a!=='object'||Array.isArray(a))return 'not_run';
    if(a.observed==='not_run'||a.observed==='network_error'||a.result==='not_run')return 'not_run';
    const complete=typeof a.attackId==='string'&&/^[a-z0-9][a-z0-9_.-]{0,79}$/i.test(a.attackId)
      &&Number.isInteger(a.stage)&&a.stage>=1&&a.stage<=12
      &&typeof a.expected==='string'&&a.expected.trim().length>0
      &&typeof a.observed==='string'&&/^HTTP \d{3}(; jsonReady=(true|false))?$/.test(a.observed)
      &&['blocked','breached'].includes(a.result);
    if(!complete)return 'not_run';
    if(a.result==='blocked'&&!/^HTTP (401|403|404|405)$/.test(a.observed)
      &&!(virtualBlocks.has(a.attackId)&&a.observed==='HTTP 200; jsonReady=true'))throw Error('invalid_blocked_result');
    return a.result;
  });
  return {checkedAt:receipt.checkedAt,commit:receipt.commit,total:outcomes.length,
    blocked:outcomes.filter(x=>x==='blocked').length,notRun:outcomes.filter(x=>x==='not_run').length,
    failed:outcomes.filter(x=>x==='breached').length};
}
