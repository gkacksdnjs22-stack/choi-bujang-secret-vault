import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

// 자체 실습 서버의 브라우저 쿠키 식별자입니다. ALEPH ID나 하드웨어 인증이 아닙니다.
export function serverDeviceContext(req, res, identity, config, secret) {
  if (!identity?.userId || !secret) throw new TypeError('검증된 로그인과 서버 키가 필요합니다.');
  const digest = (purpose, value) => createHmac('sha256', secret).update(JSON.stringify([purpose, value])).digest('hex');
  const projectId = digest('project-v1', config.repoUrl).slice(0, 32);
  const subjectId = digest('subject-v1', [projectId, identity.userId]);
  const cookies = String(req.headers?.cookie ?? '').split(';').map(value => value.trim()).filter(value => value.startsWith('__Host-vault-device='));
  let deviceId;
  if (cookies.length === 1) {
    try {
      const parts = cookies[0].slice('__Host-vault-device='.length).split('.');
      const expected = digest('device-cookie-v1', parts[0]);
      if (parts.length === 2 && /^[a-f0-9]{64}$/.test(parts[1])
        && timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parts[1], 'hex'))) {
        const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        if (payload.project === projectId && /^[a-f0-9]{16}$/.test(payload.id)
          && Number.isSafeInteger(payload.exp) && payload.exp > Date.now()) deviceId = payload.id;
      }
    } catch { /* 변조되거나 만료된 쿠키는 등록된 기기로 인정하지 않습니다. */ }
  }
  if (!deviceId) {
    deviceId = randomBytes(8).toString('hex');
    const payload = Buffer.from(JSON.stringify({ id: deviceId, project: projectId, exp: Date.now() + 86400000 })).toString('base64url');
    res.setHeader('Set-Cookie', `__Host-vault-device=${payload}.${digest('device-cookie-v1', payload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
  }
  return { classId: 'vault-local-v1', projectId, subjectId, deviceId, requestId: randomUUID() };
}
