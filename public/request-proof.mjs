// 개인키·인증서는 이 모듈의 메모리에만 있습니다. 저장소·서비스워커에 쓰지 않습니다.
const bytes=value=>new TextEncoder().encode(value);
const base64url=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(value))),x=>x.toString(16).padStart(2,'0')).join('');
function canonicalBody(value){
  if(typeof value==='string')value=JSON.parse(value);
  const normalize=x=>Array.isArray(x)?x.map(normalize):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(key=>[key,normalize(x[key])])):x;
  return JSON.stringify(normalize(value??null));
}
export function createProtectedFetch(authHeaders,dispatch=fetch){
  let connection;
  const connect=async()=>{
    const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
    const publicKey=await crypto.subtle.exportKey('jwk',keys.publicKey);
    const response=await fetch('/api/app-certificate',{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({publicKey})});
    const data=await response.json();
    if(!response.ok||typeof data.certificate!=='string'||data.expiresAt<=Date.now())throw Error(data.error||'요청 서명 연결 실패');
    return {privateKey:keys.privateKey,...data};
  };
  return async function protectedFetch(path,options={}){
    if(!connection)connection=connect();
    let current;try{current=await connection;}catch(error){connection=null;throw error;}
    if(current.expiresAt<Date.now()+5000){connection=connect();current=await connection;}
    const method=options.method||'GET',time=String(Date.now()),nonce=crypto.randomUUID();
    const url=new URL(path,location.origin);if(url.origin!==location.origin)throw Error('다른 서버로 서명을 보내지 않습니다.');
    const message=JSON.stringify(['vault-app-proof-v1',method,url.pathname+url.search,await hash(canonicalBody(options.body)),await hash(current.certificate),time,nonce]);
    const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},current.privateKey,bytes(message));
    return dispatch(path,{...options,headers:{...options.headers,'X-Vault-App-Certificate':current.certificate,
      'X-Vault-App-Signature':base64url(signature),'X-Vault-App-Time':time,'X-Vault-App-Nonce':nonce}});
  };
}
