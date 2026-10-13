export const RESOURCE_IDS = Object.freeze({ notes: 'notes', announcements: 'announcements' });
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 정확한 경로와 동작만 허용하며 :id 자리에 기능 이름은 허용하지 않습니다.
export function permittedResourceRoute(request) {
  if (request.service !== 'notes' || typeof request.subjectId !== 'string' || !request.subjectId
      || !/^[a-f0-9]{16}$/.test(request.deviceId ?? '')) return false;
  const { method, path, route } = request;
  if (path === '/notes') return ['GET', 'POST'].includes(method) && route === `${method} /notes`;
  if (typeof path === 'string' && path.startsWith('/notes/')) {
    return UUID_PATTERN.test(path.slice('/notes/'.length))
      && ['GET', 'PUT', 'DELETE'].includes(method) && route === `${method} /notes/:id`;
  }
  // 계약에는 강사 역할이 없으므로 판정기에서 공지 쓰기를 허용하지 않습니다.
  if (path === '/announcements') return method === 'GET' && route === 'GET /announcements';
  return typeof path === 'string' && path.startsWith('/announcements/')
    && UUID_PATTERN.test(path.slice('/announcements/'.length))
    && method === 'GET' && route === 'GET /announcements/:id';
}

export function apiResourceTarget(req, resource) {
  if (req.url) {
    const [path, query = ''] = req.url.split('?');
    const prefix = `/api/${resource}`;
    const params = new URLSearchParams(query);
    if ([...params.keys()].some(key => key !== 'id') || params.getAll('id').length > 1) return { invalid: true };
    const pathId = path.startsWith(`${prefix}/`) ? path.slice(prefix.length + 1) : undefined;
    if (path !== prefix && (!pathId || !UUID_PATTERN.test(pathId))) return { invalid: true };
    if (pathId && params.has('id')) return { invalid: true };
    const id = pathId ?? params.get('id') ?? undefined;
    return id && !UUID_PATTERN.test(id) ? { invalid: true } : { id };
  }
  // 로컬 handler 시험은 URL 없이 Vercel의 query.id만 제공합니다.
  if (Object.keys(req.query ?? {}).some(key => key !== 'id')) return { invalid: true };
  const id = req.query?.id;
  return id && (typeof id !== 'string' || !UUID_PATTERN.test(id)) ? { invalid: true } : { id };
}
