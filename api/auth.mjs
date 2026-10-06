import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: '지원하지 않는 요청입니다.' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(503).json({ error: '서버 연결 설정이 필요합니다.' });
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (typeof body?.email !== 'string' || typeof body?.password !== 'string'
      || !body.email.trim() || !body.password) {
      return res.status(400).json({ error: '이메일과 비밀번호를 확인하세요.' });
    }
    const auth = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data, error } = await auth.auth.signInWithPassword({ email: body.email.trim(), password: body.password });
    if (error || !data.session?.access_token) return res.status(401).json({ error: '로그인 정보를 확인하세요.' });
    return res.status(200).json({ access_token: data.session.access_token, expires_in: data.session.expires_in, token_type: data.session.token_type });
  } catch {
    return res.status(400).json({ error: '로그인 요청을 처리할 수 없습니다.' });
  }
}
