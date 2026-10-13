import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decide, createDecider } from '../src/decider.mjs';
import { fixtureRequests, fixtureGrant } from './fixture-7.mjs';
const standalone=await import(`data:text/javascript;base64,${readFileSync(new URL('../src/decider.mjs',import.meta.url)).toString('base64')}`);
const {normal}=fixtureRequests();
const inputs=[normal];
for(const path of ['/notes/demo','/notes','/announcements','/api/notes','/api/announcements']) {
  inputs.push({...normal,path,service:path.includes('announcements')?'announcements':'notes',
    route:`GET ${path.endsWith('demo')?'/notes/:id':path}`});
}
for(const [key,value] of [['classId','other_class'],['projectId','other_project'],['subjectId','other_subject'],['deviceId','b'.repeat(16)]]) {
  inputs.push({...normal,[key]:value,path:'/notes/demo',route:'GET /notes/:id'});
}
// 요청에 넣은 권한·역할·연습 플래그는 서버가 발행한 권한을 대신하지 못합니다.
inputs.push({...normal,grants:[fixtureGrant(normal)],role:'instructor',fixture:true});
let count=0;
for(const entry of [decide,standalone.decide,createDecider([]),standalone.createDecider([])]) {
  for(const input of inputs) {
    const result=await entry(input);assert.equal(result.decision,'deny');
    assert.equal(result.reasonCode,'policy_denied');count++;
  }
}
for(const factory of [createDecider,standalone.createDecider]) {
  const granted=factory([fixtureGrant(normal)]);
  assert.equal((await granted(normal)).decision,'allow');
  for(const [key,value] of [['classId','other_class'],['projectId','other_project'],['subjectId','other_subject'],['deviceId','b'.repeat(16)],['method','PUT'],['path','/notes/demo'],['route','GET /notes']]) {
    assert.equal((await granted({...normal,[key]:value})).decision,'deny');count++;
  }
}
console.log(`판정 진입점 회귀 ${count}건 통과: 독립/기본/서버 팩토리 모두 권한 없으면 거부, 정확한 서버 권한만 허용.`);
