// Local ownership tests use a fake database and identity verifier, not live credentials.
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
const a='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', b='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
let rows=[{public_id:a,owner_id:'A',title:'A',content:'fixture'},{public_id:b,owner_id:'B',title:'B',content:'fixture'}];
class Query {
  constructor(){this.filters=[];this.action='select';}
  select(){return this;} eq(k,v){this.filters.push(r=>r[k]===v);return this;}
  order(){return this;} maybeSingle(){this.single=true;return this;}
  insert(value){this.action='insert';this.value=value;return this;}
  update(value){this.action='update';this.value=value;return this;}
  delete(){this.action='delete';return this;}
  then(resolve){
    let found=rows.filter(r=>this.filters.every(f=>f(r)));
    if(this.action==='insert'){rows.push(this.value);found=[this.value];}
    if(this.action==='update')found.forEach(r=>Object.assign(r,this.value));
    if(this.action==='delete')rows=rows.filter(r=>!found.includes(r));
    return Promise.resolve({data:this.single?(found[0]??null):found,error:null}).then(resolve);
  }
}
globalThis.__ownerTest={createClient:()=>({from:()=>new Query()}),createLoginVerifier:()=>async header=>['A','B'].includes(header)?{userId:header}:null};
registerHooks({resolve(specifier,context,next){
  if(specifier==='@supabase/supabase-js')return {url:'data:text/javascript,export const createClient=globalThis.__ownerTest.createClient',shortCircuit:true};
  if(specifier.endsWith('/verify-login.mjs'))return {url:'data:text/javascript,export const createLoginVerifier=globalThis.__ownerTest.createLoginVerifier',shortCircuit:true};
  return next(specifier,context);
}});
process.env.SUPABASE_URL='https://local-test.invalid';
process.env.SUPABASE_SECRET_KEY='local-test-placeholder';
const {default:handler}=await import('../api/notes.mjs');
async function request(user,method,id,body){
  const res={setHeader(){},status(code){this.code=code;return this;},json(value){this.value=value;return this;}};
  await handler({method,headers:{authorization:user},query:id?{id}:{},body},res);return res;
}
for(const [user,own,other] of [['A',a,b],['B',b,a]]){
  assert.equal((await request(user,'GET')).value.length,1);
  assert.equal((await request(user,'GET',own)).code,200);
  for(const method of ['GET','PUT','DELETE'])assert.equal((await request(user,method,other,{title:'changed',body:'fixture'})).code,404);
  assert.equal((await request(user,'PUT',own,{title:user,body:'fixture'})).code,200);
  assert.equal((await request(user,'PUT',own,{title:user,body:'fixture',owner_id:'other'})).code,400);
}
assert.equal((await request('A','POST',null,{title:'new',body:'fixture',owner_id:'B'})).code,400);
const created=await request('A','POST',null,{title:'new',body:'fixture'});
assert.equal(created.code,201);assert.equal(rows.find(r=>r.public_id===created.value.id).owner_id,'A');
assert.equal((await request('B','DELETE',created.value.id)).code,404);
assert.equal((await request('A','DELETE',created.value.id)).code,200);
assert.equal(rows.length,2);
console.log('Local A/B ownership checks passed: list, read, update, delete, insert, owner spoofing. Live login checks remain separate.');
