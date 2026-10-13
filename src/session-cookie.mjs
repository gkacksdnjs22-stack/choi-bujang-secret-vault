// HttpOnly 쿠키는 서버만 읽습니다. 명시적인 Bearer 요청 계약은 유지합니다.
export function requestAuthorization(req,config) {
  if(req.headers?.authorization!==undefined)return req.headers.authorization;
  const cookies=String(req.headers?.cookie??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith('__Host-vault-session='));
  if(cookies.length!==1)return undefined;
  if(!['GET','HEAD'].includes(req.method)&&req.headers?.origin!==new URL(config.publicAppUrl).origin)return undefined;
  const token=cookies[0].slice('__Host-vault-session='.length);
  if(!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token))return undefined;
  return 'Bearer '+token;
}
export function sessionCookie(token,maxAge=3600) {
  return `__Host-vault-session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.max(0,Math.min(3600,maxAge))}`;
}
