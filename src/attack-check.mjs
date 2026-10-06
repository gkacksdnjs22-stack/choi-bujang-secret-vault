// Self-check results only: these do not represent the operating judge's verdict.
export async function runAttackChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.hostname.endsWith('.example')) throw new Error('실제 배포 주소가 필요합니다.');
  const request = path => fetch(new URL(path, app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
  const json = await request('/data.json');
  let staticEmpty = false;
  if (json.ok) {
    try { const value = await json.json(); staticEmpty = Array.isArray(value.notes) && value.notes.length === 0; } catch {}
  }
  const api = await request('/api/notes');
  let four = false;
  if (api.ok) {
    try { const value = await api.json(); four = Array.isArray(value.notes) && value.notes.length === 4; } catch {}
  }
  return [
    { attackId: 'static_note_seed', expected: '공개 정적 JSON에 메모 본문 없음', observed: staticEmpty ? '공개 JSON의 메모 배열이 비어 있음' : `미확인 (HTTP ${json.status})` },
    { attackId: 'server_note_read', expected: '서버 API에서 가상 자료 네 건 조회', observed: four ? '공개 서버 API에서 자료 네 건 확인; 인증은 아직 없음' : `미확인 (HTTP ${api.status})` },
  ];
}
