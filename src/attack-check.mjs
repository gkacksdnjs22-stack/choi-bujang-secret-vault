// Actual requests only. Never include tokens or note bodies in the bundle.
export async function runAttackChecks(config) {
  const app=new URL(config.publicAppUrl);
  const attempts=[];
  for(const method of ['GET','POST','PUT','DELETE']) {
    const path=['PUT','DELETE'].includes(method)?'/api/notes/00000000-0000-4000-8000-000000000001':'/api/notes';
    const r=await fetch(new URL(path,app),{method,redirect:'error',signal:AbortSignal.timeout(10000)});
    attempts.push({attackId:`anonymous_${method.toLowerCase()}`,expected:'무로그인 자료 요청 거부',observed:`HTTP ${r.status}${r.status===401?' 인증 거부 확인':' 예상과 다름'}`});
  }
  const r=await fetch(new URL('/api/notes',app),{headers:{Authorization:'Bearer invalid'},signal:AbortSignal.timeout(10000)});
  attempts.push({attackId:'invalid_token',expected:'잘못된 토큰 요청 거부',observed:`HTTP ${r.status}`});
  return attempts;
}
