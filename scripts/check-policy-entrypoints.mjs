import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {decide,RULE_IDS} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';
import {checkDecider} from './decider-test.mjs';
const standalone=await import('data:text/javascript;base64,'+readFileSync(new URL('../src/decider.mjs',import.meta.url)).toString('base64'));
let count=0;
for (const entry of [decide,standalone.decide]) {
  const exercise=await checkDecider({decide:entry,ruleIds:RULE_IDS});
  assert.equal(exercise.every(item=>item.passed),true);count+=exercise.length;
  const {normal}=fixtureRequests();
  const cases=[
    [{...normal,method:'PUT',route:'PUT /notes/:id'},'allow'],
    [{...normal,path:'/api/notes/demo',route:'GET /api/notes/:id'},'allow'],
    ...['export','all','admin','search','backup','restore'].map(id=>[{...normal,path:'/notes/'+id},'deny']),
    [{...normal,path:'/notes',route:'GET /notes'},'deny'],
    [{...normal,path:'/notes/demo/export'},'deny'],
    [{...normal,route:'GET /other/:id'},'deny'],
    [{...normal,queryLength:1},'deny'],
    [{...normal,querySha256:'0'.repeat(64)},'deny'],
    [{...normal,deviceId:'bad'},'deny'],
    [{...normal,policyRevision:0},'deny'],
    [{...normal,at:'2020-01-01T00:00:00Z'},'deny'],
    [{...normal,role:'instructor'},'deny'],
    [{...normal,service:'announcements',path:'/announcements/demo',method:'PUT',route:'PUT /announcements/:id'},'deny'],
  ];
  for (const [input,expected] of cases) {
    const result=await entry(input);assert.equal(result.decision,expected);
    assert.equal(result.requestId,input.requestId);count++;
  }
  // 계약에는 소유자 항목이 없습니다. 주체 변경만으로 소유권을 판정했다고 보고하지 않습니다.
  assert.equal((await entry({...normal,subjectId:'other_subject'})).decision,'allow');
}
console.log('기본/격리 구역 판정 '+count+'건 통과. 메모 소유권은 서버/API에서 별도 검증합니다.');
