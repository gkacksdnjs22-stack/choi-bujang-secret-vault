import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { apiResourceTarget, resourceRouteAllowed } from '../src/resource-routes.mjs';
const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
const id='00000000-0000-4000-8000-000000000001';
assert.equal(resourceRouteAllowed(config,'notes','GET',id),true);
assert.equal(resourceRouteAllowed(config,'notes','PUT',id),true);
assert.equal(resourceRouteAllowed(config,'notes','PATCH',id),false);
assert.equal(resourceRouteAllowed({allowedRoutes:[]},'notes','GET',id),false);
const wrongZone=structuredClone(config);
wrongZone.allowedRoutes.find(r=>r.pathPattern==='/api/notes/:id'&&r.method==='GET').zone='class-notices';
assert.equal(resourceRouteAllowed(wrongZone,'notes','GET',id),false);
const duplicate=structuredClone(config);
duplicate.allowedRoutes.push(duplicate.allowedRoutes.find(r=>r.pathPattern==='/api/notes/:id'&&r.method==='GET'));
assert.equal(resourceRouteAllowed(duplicate,'notes','GET',id),false);
for (const url of ['/api/notes/export',`/api/notes/${id}/export`,'/api/notes?action=export',
  '/api/notes?owner_id=B',`/api/notes/${id}?id=00000000-0000-4000-8000-000000000099`,
  `/api/notes?id=${id}&id=${id}`]) assert.equal(apiResourceTarget({url},'notes').invalid,true);
for (const url of [`/api/notes/${id}`,`/api/notes?id=${id}`,`/api/notes/${id}?id=${id}`]) {
  assert.equal(apiResourceTarget({url},'notes').id,id);
}
// 우회 모드로 API 시험하지 않습니다. 정상 허용·타인 거부를 함께 검증합니다.
for (const script of ['check-policy-entrypoints.mjs','check-engine-policy.mjs','check-server-api.mjs']) {
  process.stdout.write(execFileSync(process.execPath,[fileURLToPath(new URL(script,import.meta.url))],
    {encoding:'utf8',windowsHide:true}));
}
console.log('8단계 기본/격리 구역 판정·서버 소유권·활성 API 검증 통과 (가상 DB).');
