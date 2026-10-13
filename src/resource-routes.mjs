export const RESOURCE_IDS = Object.freeze({ notes: 'notes', announcements: 'announcements' });
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 서버 설정의 구역은 접근 범위를 정하고, 실제 소유자·강사 권한 검사는 API가 수행합니다.
export function resourceRouteAllowed(config, resource, method, id) {
  if (!['notes', 'announcements'].includes(resource)) return false;
  const pathPattern = '/api/' + resource + (id ? '/:id' : '');
  const zone = resource === 'notes' ? 'my-notes'
    : method === 'GET' ? 'class-notices' : 'instructor-materials';
  const matches = (config.allowedRoutes ?? []).filter(entry => entry
    && entry.service === resource && entry.method === method && entry.pathPattern === pathPattern);
  return matches.length === 1 && matches[0].zone === zone;
}

export function apiResourceTarget(req, resource) {
  if (req.url) {
    const [path, query = ''] = req.url.split('?');
    const prefix = `/api/${resource}`;
    const params = new URLSearchParams(query);
    if ([...params.keys()].some(key => key !== 'id') || params.getAll('id').length > 1) return { invalid: true };
    const pathId = path.startsWith(`${prefix}/`) ? path.slice(prefix.length + 1) : undefined;
    if (path !== prefix && (!pathId || !UUID_PATTERN.test(pathId))) return { invalid: true };
    // 동적 Vercel 경로는 같은 ID를 쿼리에도 전달할 수 있습니다. 서로 다른 ID는 거부합니다.
    if (pathId && params.has('id') && params.get('id') !== pathId) return { invalid: true };
    const id = pathId ?? params.get('id') ?? undefined;
    return id && !UUID_PATTERN.test(id) ? { invalid: true } : { id };
  }
  // 로컬 handler 시험은 URL 없이 Vercel의 query.id만 제공합니다.
  if (Object.keys(req.query ?? {}).some(key => key !== 'id')) return { invalid: true };
  const id = req.query?.id;
  return id && (typeof id !== 'string' || !UUID_PATTERN.test(id)) ? { invalid: true } : { id };
}
