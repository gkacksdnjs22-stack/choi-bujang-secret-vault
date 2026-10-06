import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';
const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (config.step !== 2) throw new Error('현재 빌드는 2단계 서버 자료실 설정입니다.');
await mkdir(resolve(root, 'public'), { recursive: true });
await writeFile(resolve(root, 'public/data.json'), '{"notes":[]}\n', 'utf8');
if (!process.argv.includes('--local')) {
  await writeFile(resolve(root, 'public/aleph.json'), `${JSON.stringify(deploymentIdentity(process.env, config), null, 2)}\n`, 'utf8');
}
console.log('공개 메모 없이 서버 API용 화면을 준비했습니다.');
