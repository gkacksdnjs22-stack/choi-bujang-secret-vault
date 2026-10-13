// Counts come only from an executed receipt, never from displayed success text.
export function summarizeChecks(receipt) {
  if(!receipt || !/^[a-f0-9]{40}$/.test(receipt.commit) || !Number.isFinite(Date.parse(receipt.checkedAt))
    || !Array.isArray(receipt.attackAttempts) || !receipt.attackAttempts.length) throw Error('invalid_check_receipt');
  const attempts=receipt.attackAttempts;
  if(attempts.some(a=>!['blocked','breached','not_run'].includes(a.result)
    || (a.observed==='not_run')!==(a.result==='not_run'))) throw Error('invalid_check_receipt');
  const virtualBlocks=new Set(['s06-unregistered','s07-compound','s08-ownership','s08-unknown-route',
    's08-all-notes','s08-write-notice','s09-burst-read','s09-device-compound']);
  if(attempts.some(a=>a.result==='blocked' && !/^HTTP (401|403|404|405)$/.test(a.observed)
    && !(virtualBlocks.has(a.attackId)&&a.observed==='HTTP 200; jsonReady=true'))) throw Error('invalid_blocked_result');
  const blocked=attempts.filter(a=>a.result==='blocked').length;
  const notRun=attempts.filter(a=>a.result==='not_run').length;
  return {checkedAt:receipt.checkedAt,commit:receipt.commit,total:attempts.length,blocked,notRun,
    failed:attempts.length-blocked-notRun,source:'deployment_read_only_receipt',
    officialTests:{total:41,executed:0,blocked:0,failed:0,notRun:41,source:'official_individual_results_not_received'}};
}
