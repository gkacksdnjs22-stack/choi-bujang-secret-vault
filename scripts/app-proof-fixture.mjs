import {generateKeyPairSync,randomUUID,sign} from 'node:crypto';
import {issueAppCertificate,proofMessage} from '../src/app-proof.mjs';
import {serverDeviceContext} from '../src/server-device.mjs';
const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
export function signedFixture(req,userId,config){
  const res={setHeader(name,value){this[name]=value;}};
  const context=serverDeviceContext(req,res,{userId},config,process.env.SUPABASE_SECRET_KEY);
  if(res['Set-Cookie'])req.headers.cookie=res['Set-Cookie'].split(';')[0];
  const {certificate}=issueAppCertificate({publicKey:keys.publicKey.export({format:'jwk'}),identity:{userId},context,
    secret:process.env.SUPABASE_SECRET_KEY,expiresAt:Date.now()+60000});
  const time=String(Date.now()),nonce=randomUUID();
  const signature=sign('sha256',Buffer.from(proofMessage({...req,certificate,time,nonce})),{key:keys.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  Object.assign(req.headers,{'x-vault-app-certificate':certificate,'x-vault-app-time':time,'x-vault-app-nonce':nonce,'x-vault-app-signature':signature});
  return req;
}
