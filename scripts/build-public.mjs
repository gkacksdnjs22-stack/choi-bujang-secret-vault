import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';
import {runAttackChecks} from '../src/attack-check.mjs';
import {summarizeChecks} from '../src/check-summary.mjs';
const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (!Number.isInteger(config.step) || config.step < 2 || config.step > 12) throw new Error('현재 빌드는 2~12단계 서버 자료실 설정입니다.');
await mkdir(resolve(root, 'public'), { recursive: true });
await writeFile(resolve(root, 'public/data.json'), '{"notes":[]}\n', 'utf8');
if (!process.argv.includes('--local')) {
  const identity=deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public/aleph.json'), `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  if(config.step>=12){
    const receipt={commit:process.env.VERCEL_GIT_COMMIT_SHA,checkedAt:new Date().toISOString(),attackAttempts:await runAttackChecks(config)};
    summarizeChecks(receipt);
    await mkdir(resolve(root,'artifacts'),{recursive:true});
    await writeFile(resolve(root,'artifacts/checks.json'),JSON.stringify(receipt)+'\n','utf8');
  }
}
console.log('공개 메모 없이 서버 API용 화면을 준비했습니다.');
