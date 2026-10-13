// 내부 서버 전용: identity는 서명 검증 후, binding과 request는 신뢰된 엔진 연결에서 받습니다.
// 브라우저 본문이나 헤더로 binding을 만들지 않습니다.
export async function issueResourceGrant(db, identity, binding, request) {
  const fields = ['classId', 'projectId', 'subjectId', 'deviceId'];
  if (!identity?.userId || binding?.userId !== identity.userId
    || fields.some(key => typeof binding[key] !== 'string' || binding[key] !== request[key])
    || request.deviceRegistered !== true || request.queryLength !== 0
    || !['GET', 'POST', 'PUT', 'DELETE'].includes(request.method)) return null;
  const match = /^\/api\/(notes|announcements)(?:\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?$/i.exec(request.path ?? '');
  if (!match || request.service !== match[1]
    || !(match[2] ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST']).includes(request.method)
    || request.route !== `${request.method} /api/${match[1]}${match[2] ? '/:id' : ''}`) return null;
  const now = Date.now(), at = Date.parse(request.at);
  if (!Number.isFinite(at) || Math.abs(now - at) > 5000) return null;
  if (match[1] === 'notes' && match[2]) {
    const { data, error } = await db.from('notes').select('public_id')
      .eq('public_id', match[2]).eq('owner_id', identity.userId).maybeSingle();
    if (error || !data) return null;
  } else if (match[1] === 'announcements' && request.method !== 'GET') {
    const { data, error } = await db.from('instructor_memberships').select('enabled')
      .eq('user_id', identity.userId).eq('enabled', true).maybeSingle();
    if (error || !data) return null;
  }
  return {
    ...Object.fromEntries([...fields, 'service', 'method', 'path', 'route'].map(key => [key, request[key]])),
    expiresAt: new Date(now + 60000).toISOString(),
  };
}
