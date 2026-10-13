import {createHash} from 'node:crypto';
export const contentHash = content => createHash('sha256').update(content,'utf8').digest('hex');
const policyHash = policy => contentHash(JSON.stringify(policy));
// 신뢰된 사전 사본의 지문은 별도 보관해야 합니다. 사본이 자신의 지문을 정하지 않습니다.
export function previewPolicyRestore({backup,current,trustedHash}) {
  if(!backup||!current||typeof trustedHash!=='string'||policyHash(backup)!==trustedHash
    ||!Number.isSafeInteger(backup.revision)||backup.revision<1
    ||!backup.services||!current.services) throw new Error('invalid_policy_backup');
  const changedServices=Object.keys({...backup.services,...current.services})
    .filter(key=>JSON.stringify(backup.services[key])!==JSON.stringify(current.services[key]));
  return {revision:backup.revision,changedServices};
}
export function restoreTestPolicy({backup,current,trustedHash,confirmedServices}) {
  const preview=previewPolicyRestore({backup,current,trustedHash});
  if(!Array.isArray(confirmedServices)||JSON.stringify([...confirmedServices].sort())!==JSON.stringify([...preview.changedServices].sort()))
    throw new Error('policy_scope_not_confirmed');
  // 실제 운영 설정/감사 기록은 바꾸지 않습니다. 확인된 서비스만 새 시험 사본에 반영합니다.
  const restored=structuredClone(current);
  for(const key of preview.changedServices) {
    if(!Object.hasOwn(backup.services,key)) throw new Error('policy_service_missing');
    restored.services[key]=structuredClone(backup.services[key]);
  }
  restored.revision=backup.revision;
  return restored;
}
export async function restorePrivateNote({db,noteId,identity,context}) {
  if(!identity?.userId||!context) throw new Error('verified_identity_required');
  const {data,error}=await db.rpc('restore_private_note',{p_note_id:noteId,p_actor_id:identity.userId,
    p_class_id:context.classId,p_project_id:context.projectId,p_subject_id:context.subjectId,p_device_id:context.deviceId});
  if(['42883','PGRST202'].includes(error?.code)) throw new Error('restore_unavailable');
  if(error||!data||data.id!==noteId||data.verified!==true) throw new Error('restore_rejected');
  // 본문·소유자·토큰을 반환하지 않습니다. DB 함수에서 한 트랜잭션으로 비교합니다.
  return {id:data.id,verified:true};
}
