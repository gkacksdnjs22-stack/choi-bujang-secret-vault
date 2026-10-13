import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { apiResourceTarget, UUID_PATTERN } from '../src/resource-routes.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verify;
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const key = process.env.SUPABASE_SECRET_KEY, url = process.env.SUPABASE_URL;
  if (!key || !url) return res.status(503).json({ error: '서버 연결 설정이 필요합니다.' });
  try {
    verify ??= createLoginVerifier({ config, supabaseSecretKey: key });
    const identity = await verify(req.headers.authorization);
    if (!identity) return res.status(401).json({ error: '로그인이 필요합니다.' });
    const target = apiResourceTarget(req, 'announcements');
    if (target.invalid) return res.status(400).json({ error: '허용되지 않은 자료 경로입니다.' });
    const { id } = target;
    const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
    if (!['GET', 'POST', 'PUT', 'DELETE'].includes(req.method)) return res.status(405).json({ error: '지원하지 않는 요청입니다.' });
    if (req.method !== 'GET') {
      const { data: membership, error } = await db.from('instructor_memberships').select('enabled')
        .eq('user_id', identity.userId).eq('enabled', true).maybeSingle();
      if (error) return res.status(503).json({ error: '권한을 확인할 수 없습니다.' });
      if (!membership) return res.status(403).json({ error: '강사 권한이 필요합니다.', reasonCode: 'instructor_required' });
    }
    if (req.method === 'POST' && id) return res.status(405).json({ error: '공지 추가는 목록 경로에서만 허용합니다.' });
    const shape = row => ({ id: row.public_id, resourceId: `announcements:${row.public_id}`, title: row.title, body: row.content });
    if (req.method === 'GET') {
      let query = db.from('announcements').select('public_id,title,content');
      query = id ? query.eq('public_id', id).maybeSingle() : query.order('updated_at');
      const { data, error } = await query;
      if (error) return res.status(502).json({ error: '공지 조회에 실패했습니다.' });
      return id && !data ? res.status(404).json({ error: '공지가 없습니다.' }) : res.status(200).json(id ? shape(data) : data.map(shape));
    }
    if (req.method !== 'POST' && !id) return res.status(400).json({ error: '공지 ID가 필요합니다.' });
    if (req.method === 'DELETE') {
      const { data, error } = await db.from('announcements').delete().eq('public_id', id).select('public_id').maybeSingle();
      if (error) return res.status(502).json({ error: '삭제에 실패했습니다.' });
      return data ? res.status(200).json({ id }) : res.status(404).json({ error: '공지가 없습니다.' });
    }
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!body || ['role', 'owner_id', 'updated_by', 'resourceId'].some(key => Object.hasOwn(body, key))) return res.status(400).json({ error: '권한은 서버에서 결정합니다.' });
    if (typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
        || typeof body.body !== 'string' || body.body.length > 10000) return res.status(400).json({ error: '제목과 본문을 확인하세요.' });
    const values = { title: body.title, content: body.body, updated_by: identity.userId, updated_at: new Date().toISOString() };
    if (req.method === 'POST') {
      const newId = body.id ?? randomUUID();
      if (typeof newId !== 'string' || !UUID_PATTERN.test(newId)) return res.status(400).json({ error: 'UUID가 필요합니다.' });
      const { error } = await db.from('announcements').insert({ ...values, public_id: newId });
      return error ? res.status(409).json({ error: '공지 추가에 실패했습니다.' }) : res.status(201).json({ id: newId });
    }
    const { data, error } = await db.from('announcements').update(values).eq('public_id', id).select('public_id,title,content').maybeSingle();
    if (error) return res.status(502).json({ error: '수정에 실패했습니다.' });
    return data ? res.status(200).json(shape(data)) : res.status(404).json({ error: '공지가 없습니다.' });
  } catch { return res.status(500).json({ error: '요청을 처리할 수 없습니다.' }); }
}
