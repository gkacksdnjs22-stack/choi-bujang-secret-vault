// Counts come only from an executed receipt, never from displayed success text.
export function summarizeChecks(receipt) {
  if(!receipt || !/^[a-f0-9]{40}$/.test(receipt.commit) || !Number.isFinite(Date.parse(receipt.checkedAt))
    || !Array.isArray(receipt.attackAttempts) || !receipt.attackAttempts.length) throw Error('invalid_check_receipt');
  const attempts=receipt.attackAttempts;
  if(attempts.some(a=>!['blocked','breached','not_run'].includes(a.result)
    || (a.observed==='not_run')!==(a.result==='not_run'))) throw Error('invalid_check_receipt');
  const blocked=attempts.filter(a=>a.result==='blocked').length;
  const notRun=attempts.filter(a=>a.result==='not_run').length;
  return {checkedAt:receipt.checkedAt,commit:receipt.commit,total:attempts.length,blocked,notRun,
    failed:attempts.length-blocked-notRun,source:'deployment_read_only_receipt'};
}
