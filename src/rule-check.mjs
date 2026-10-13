import { createEngineDecision } from './engine-resource-policy.mjs';
import {detect,detectDeviceEvents} from './detect.mjs';

// 공개 점검은 이 고정 가상 DB만 사용합니다. 실제 사용자/메모/등록부를 읽거나 수정하지 않습니다.
const noteId = '00000000-0000-4000-8000-000000000001';
const noticeId = '00000000-0000-4000-8000-000000000002';
export function ruleFixture() {
  const now = Date.now();
  const request = {schema:'aleph.decision.v1',requestId:'00000000-0000-4000-8000-000000000003',
    classId:'check_class',projectId:'check_project',subjectId:'check_A',deviceId:'a'.repeat(16),
    service:'notes',method:'GET',path:`/api/notes/${noteId}`,route:'GET /api/notes/:id',
    queryLength:0,querySha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at:new Date(now).toISOString(),policyRevision:1,deviceRegistered:true,
    stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],
    signals:{source:'judge_fixture',region:'local',network:'usual',hour:14}};
  const rows = {principal_bindings:['A','B','I'].map(user=>({class_id:request.classId,
    project_id:request.projectId,subject_id:'check_'+user,device_id:request.deviceId,user_id:user,
    enabled:true,expires_at:new Date(now+60000).toISOString()})),
    notes:[{public_id:noteId,owner_id:'A'}],instructor_memberships:[{user_id:'I',enabled:true}]};
  const db = {from(table) {const filters=[];return {select(){return this;},
    eq(key,value){filters.push(row=>row[key]===value);return this;},
    async maybeSingle(){const found=rows[table]?.filter(row=>filters.every(test=>test(row)))??[];
      return {data:found.length===1?found[0]:null,error:found.length>1?{message:'ambiguous'}:null};}};}};
  const config = {allowedRoutes:[
    ...['GET','PUT','DELETE'].map(method=>({service:'notes',method,pathPattern:'/api/notes/:id',zone:'my-notes'})),
    ...['GET','POST'].map(method=>({service:'notes',method,pathPattern:'/api/notes',zone:'my-notes'})),
    {service:'announcements',method:'PUT',pathPattern:'/api/announcements/:id',zone:'instructor-materials'},
  ]};
  return {request,rows,db,config};
}

export async function runRuleCheck(caseId) {
  if(caseId==='s09-burst-read'||caseId==='s09-device-compound') {
    const start=Date.UTC(2026,9,1);
    const events=Array.from({length:121},(_,i)=>({at:new Date(start+i*2000).toISOString(),
      method:'GET',identity:{sub:'check_user'}}));
    const result=caseId==='s09-burst-read'?detect(events):detectDeviceEvents(events.map(event=>({
      at:event.at,method:event.method,subjectId:'check_user',deviceId:'a'.repeat(16),
      source:'local_virtual_fixture',decision:'allow',network:'unusual'})));
    return {source:'fixed_virtual_fixture',caseId,ready:result.action==='propose_revocation',
      action:result.action,reasonCode:result.reasonCode};
  }
  const {request,db,config} = ruleFixture();
  const decision = createEngineDecision({db,config});
  const other = {...request,subjectId:'check_B'};
  const notice = {...request,service:'announcements',path:`/api/announcements/${noticeId}`,
    method:'PUT',route:'PUT /api/announcements/:id'};
  const cases = {
    's06-unregistered':[[{...request,deviceRegistered:false},'deny']],
    's07-compound':[[{...request,signals:{source:'judge_fixture',region:'foreign',network:'unusual',hour:3},
      recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]},'step_up']],
    's08-own':[[request,'allow'],[{...request,method:'PUT',route:'PUT /api/notes/:id'},'allow']],
    's08-ownership':[[request,'allow'],[other,'deny'],
      [{...other,method:'PUT',route:'PUT /api/notes/:id'},'deny']],
    's08-unknown-route':[[{...request,path:'/api/notes/export'},'deny']],
    's08-all-notes':[[{...request,path:'/api/notes',route:'GET /api/notes',queryLength:9},'deny']],
    's08-write-notice':[[notice,'deny'],[{...notice,subjectId:'check_I'},'allow']],
  };
  if (!Object.hasOwn(cases,caseId)) return null;
  const checks = [];
  for (const [input,expected] of cases[caseId]) {
    const result = await decision(input);
    checks.push({expected,decision:result.decision,reasonCode:result.reasonCode});
  }
  return {source:'fixed_virtual_fixture',caseId,ready:checks.every(item=>item.decision===item.expected),checks};
}
