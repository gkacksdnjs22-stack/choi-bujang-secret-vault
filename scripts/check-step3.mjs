import { readFileSync } from 'node:fs';
import handler from '../api/notes.mjs';
process.env.SUPABASE_URL='https://mhcjrsyvngiokcoljeet.supabase.co';
process.env.SUPABASE_SECRET_KEY='local-test-placeholder';
for(const method of ['GET','POST','PUT','DELETE']) {
  const res={setHeader(){},status(code){this.code=code;return this},json(value){this.value=value;return this}};
  await handler({method,headers:{},query:{}},res);
  if(res.code!==401||res.value.notes)throw Error(`${method} anonymous request not denied`);
}
const res={setHeader(){},status(code){this.code=code;return this},json(value){this.value=value;return this}};
await handler({method:'GET',headers:{authorization:'Bearer invalid'},query:{}},res);
if(res.code!==401)throw Error('Invalid token not denied');
console.log('GET/POST/PUT/DELETE without login and malformed token denied');
