import { createDecider } from './decider.mjs';
import { issueResourceGrant } from './resource-grants.mjs';
import { apiResourceTarget, resourceRouteAllowed } from './resource-routes.mjs';

// 내부 연결용입니다. identity와 request를 브라우저 본문에서 받아 호출하지 않습니다.
export async function decideOwnedResource({ db, config, identity, request }) {
  const deny = () => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: request.deviceRegistered === true ? 'policy_denied' : 'device_not_registered',
    ruleIds: [request.deviceRegistered === true ? 'resource_zone' : 'device_registered'] });
  if (!identity?.userId || request.deviceRegistered !== true
    || ['classId', 'projectId', 'subjectId', 'deviceId'].some(key => typeof request[key] !== 'string' || !request[key])) return deny();
  const target = apiResourceTarget({ url: request.path }, request.service);
  if (target.invalid || request.queryLength !== 0
    || !resourceRouteAllowed(config, request.service, request.method, target.id)) return deny();
  try {
    const { data, error } = await db.from('principal_bindings')
      .select('user_id,expires_at').eq('class_id', request.classId).eq('project_id', request.projectId)
      .eq('subject_id', request.subjectId).eq('device_id', request.deviceId)
      .eq('user_id', identity.userId).eq('enabled', true).maybeSingle();
    if (error || !data || data.user_id !== identity.userId
      || !(Date.parse(data.expires_at) > Date.now())) return deny();
    const binding = { userId: data.user_id, ...Object.fromEntries(
      ['classId', 'projectId', 'subjectId', 'deviceId'].map(key => [key, request[key]])) };
    const grant = await issueResourceGrant(db, identity, binding, request);
    return grant ? createDecider([grant])(request) : deny();
  } catch { return deny(); }
}
