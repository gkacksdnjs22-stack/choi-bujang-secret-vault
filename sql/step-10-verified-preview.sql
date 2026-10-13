-- 기존 권한 범위 유지. 사본 읽기/버전 대조를 서버 전용 함수 안에서 실행합니다.
begin;
create or replace function public.preview_private_note_recovery(p_note_id uuid,p_actor_id uuid,
  p_class_id text,p_project_id text,p_subject_id text,p_device_id text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,public,extensions as $$
declare b public.note_recovery_snapshots%rowtype; n public.notes%rowtype;
  changes jsonb:='[]'::jsonb; version text;
begin
  if not exists(select 1 from public.principal_bindings where class_id=p_class_id
    and project_id=p_project_id and subject_id=p_subject_id and device_id=p_device_id
    and user_id=p_actor_id and enabled and expires_at>now()) then raise exception 'restore_rejected'; end if;
  select * into b from public.note_recovery_snapshots where public_id=p_note_id and owner_id=p_actor_id;
  if not found or encode(extensions.digest(b.content,'sha256'),'hex') is distinct from b.content_sha256
    then raise exception 'restore_rejected'; end if;
  version:=encode(extensions.digest(jsonb_build_array(b.public_id,b.owner_id,b.title,b.content,b.created_at)::text,'sha256'),'hex');
  select * into n from public.notes where public_id=p_note_id;
  if not found then changes:='["create"]'::jsonb;
  else
    if n.owner_id is distinct from p_actor_id then raise exception 'restore_rejected'; end if;
    if n.title is distinct from b.title then changes:=changes||'"title"'::jsonb; end if;
    if n.content is distinct from b.content then changes:=changes||'"content"'::jsonb; end if;
  end if;
  return jsonb_build_object('id',p_note_id,'verified',true,'version',version,
    'stateVersion',encode(extensions.digest(jsonb_build_array(n.public_id,n.owner_id,n.title,n.content)::text,'sha256'),'hex'),
    'capturedAt',b.created_at,'changedFields',changes);
end $$;
create or replace function public.restore_verified_private_note(p_note_id uuid,p_actor_id uuid,
  p_class_id text,p_project_id text,p_subject_id text,p_device_id text,p_expected_version text,p_expected_state text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,public,extensions as $$
declare preview jsonb;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_note_id::text,0));
  perform 1 from public.note_recovery_snapshots where public_id=p_note_id for update;
  perform 1 from public.notes where public_id=p_note_id for update;
  preview:=public.preview_private_note_recovery(p_note_id,p_actor_id,p_class_id,p_project_id,p_subject_id,p_device_id);
  if p_expected_version is null or preview->>'version' is distinct from p_expected_version
    or p_expected_state is null or preview->>'stateVersion' is distinct from p_expected_state
    then raise exception 'restore_rejected'; end if;
  return public.restore_private_note(p_note_id,p_actor_id,p_class_id,p_project_id,p_subject_id,p_device_id);
end $$;
revoke all on function public.preview_private_note_recovery(uuid,uuid,text,text,text,text) from public,anon,authenticated;
revoke all on function public.restore_verified_private_note(uuid,uuid,text,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.preview_private_note_recovery(uuid,uuid,text,text,text,text) to service_role;
grant execute on function public.restore_verified_private_note(uuid,uuid,text,text,text,text,text,text) to service_role;
commit;
