import { createClient } from '@supabase/supabase-js';

// Step 2 intentionally leaves this endpoint public; authentication is step 3.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'GET 요청만 지원합니다.' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(503).json({ error: '자료 서버 연결 설정이 필요합니다.' });
  try {
    const db = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { data, error } = await db.from('notes').select('title,content').order('id');
    if (error) return res.status(502).json({ error: '자료를 불러올 수 없습니다.' });
    return res.status(200).json({ notes: data });
  } catch {
    return res.status(502).json({ error: '자료를 불러올 수 없습니다.' });
  }
}
