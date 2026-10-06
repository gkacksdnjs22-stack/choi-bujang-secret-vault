import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let verify;
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = process.env.SUPABASE_URL;
  if (!key || !url) return res.status(503).json({error:'서버 연결 설정이 필요합니다.'});
  try {
    verify ??= createLoginVerifier({config, supabaseSecretKey:key});
    const identity = await verify(req.headers.authorization);
    if (!identity) return res.status(401).json({error:'로그인이 필요합니다.'});
    const db = createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
    const id = req.query?.id;
    if (id && (typeof id !== 'string' || !uuid.test(id))) return res.status(400).json({error:'올바른 메모 ID가 필요합니다.'});
    const shape = row => ({id:row.public_id,title:row.title,body:row.content});
    if (req.method === 'GET') {
      let query = db.from('notes').select('public_id,title,content');
      if(id) query=query.eq('public_id',id).eq('owner_id',identity.userId).maybeSingle();
      else query=query.eq('owner_id',identity.userId).order('id');
      const {data,error}=await query;
      if(error) return res.status(502).json({error:'자료 조회에 실패했습니다.'});
      if(id && !data) return res.status(404).json({error:'메모가 없습니다.'});
      return res.status(200).json(id?shape(data):data.map(shape));
    }
    if (!['POST','PUT','DELETE'].includes(req.method)) {res.setHeader('Allow','GET, POST, PUT, DELETE');return res.status(405).json({error:'지원하지 않는 요청입니다.'});}
    if (req.method !== 'POST' && !id) return res.status(400).json({error:'메모 ID가 필요합니다.'});
    if (req.method === 'DELETE') {
      const {data,error}=await db.from('notes').delete().eq('public_id',id).eq('owner_id',identity.userId).select('public_id').maybeSingle();
      if(error)return res.status(502).json({error:'삭제에 실패했습니다.'});
      return data?res.status(200).json({id}):res.status(404).json({error:'메모가 없습니다.'});
    }
    const body=typeof req.body==='string'?JSON.parse(req.body):req.body;
    if (body && Object.hasOwn(body,'owner_id')) return res.status(400).json({error:'소유자는 서버에서 결정합니다.'});
    if(typeof body?.title!=='string'||typeof body?.body!=='string'||!body.title.trim()||body.title.length>200||body.body.length>10000)return res.status(400).json({error:'제목과 본문을 확인하세요.'});
    if(req.method==='POST') {
      const newId=body.id??randomUUID();
      if(typeof newId!=='string'||!uuid.test(newId))return res.status(400).json({error:'UUID가 필요합니다.'});
      const {error}=await db.from('notes').insert({public_id:newId,owner_id:identity.userId,title:body.title,content:body.body});
      return error?res.status(409).json({error:'메모 추가에 실패했습니다.'}):res.status(201).json({id:newId});
    }
    // Check ownership in the same query as the write; the owner cannot be changed.
    const {data,error}=await db.from('notes').update({title:body.title,content:body.body}).eq('public_id',id).eq('owner_id',identity.userId).select('public_id,title,content').maybeSingle();
    if(error)return res.status(502).json({error:'수정에 실패했습니다.'});
    return data?res.status(200).json(shape(data)):res.status(404).json({error:'메모가 없습니다.'});
  } catch {return res.status(500).json({error:'요청을 처리할 수 없습니다.'});}
}
