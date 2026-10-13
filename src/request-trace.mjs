import {randomUUID} from 'node:crypto';
export function traceRequest(res){
  const requestId=randomUUID(),checkedAt=new Date().toISOString();
  res.setHeader('X-Vault-Request-Id',requestId);
  res.setHeader('X-Vault-Checked-At',checkedAt);
  return {requestId,checkedAt};
}
