-- 적용 전 검토 필요. 실제 메모를 변조/삭제하지 않으며 비공개 사본을 DB 안에 보관합니다.
begin;
create table if not exists public.note_recovery_snapshots (
  public_id uuid primary key, owner_id uuid not null, title text not null, content text not null,
  content_sha256 text not null, created_at timestamptz not null default now()
);
create table if not exists public.note_recovery_audit (
  id bigint generated always as identity primary key, note_id uuid not null,
  actor_id uuid not null, action text not null, at timestamptz not null default now()
);
alter table public.note_recovery_snapshots enable row level security;
alter table public.note_recovery_audit enable row level security;
revoke all on public.note_recovery_snapshots,public.note_recovery_audit from public,anon,authenticated,service_role;
-- 사본은 새 메모 최초 상태만 캡처합니다. UPDATE/DELETE로 원본 사본을 덮지 않습니다.
create or replace function public.capture_note_recovery_snapshot() returns trigger
language plpgsql security definer set search_path=pg_catalog,public,extensions as $$
begin
  if new.owner_id is not null then
    insert into public.note_recovery_snapshots(public_id,owner_id,title,content,content_sha256)
    values(new.public_id,new.owner_id,new.title,new.content,encode(extensions.digest(new.content,'sha256'),'hex'))
    on conflict(public_id) do nothing;
  end if;
  return new;
end $$;
revoke all on function public.capture_note_recovery_snapshot() from public,anon,authenticated,service_role;
drop trigger if exists capture_note_recovery_snapshot on public.notes;
create trigger capture_note_recovery_snapshot after insert on public.notes for each row
execute function public.capture_note_recovery_snapshot();
-- 기존 비공개 자료를 한 번만 백업하며 본문을 출력하지 않습니다.
insert into public.note_recovery_snapshots(public_id,owner_id,title,content,content_sha256)
select public_id,owner_id,title,content,encode(extensions.digest(content,'sha256'),'hex')
from public.notes where owner_id is not null on conflict(public_id) do nothing;
create or replace function public.restore_private_note(p_note_id uuid,p_actor_id uuid,
  p_class_id text,p_project_id text,p_subject_id text,p_device_id text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,public,extensions as $$
declare b public.note_recovery_snapshots%rowtype; n public.notes%rowtype;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_note_id::text,0));
  if not exists(select 1 from public.principal_bindings where class_id=p_class_id
    and project_id=p_project_id and subject_id=p_subject_id and device_id=p_device_id
    and user_id=p_actor_id and enabled and expires_at>now()) then raise exception 'restore_rejected'; end if;
  select * into b from public.note_recovery_snapshots where public_id=p_note_id and owner_id=p_actor_id for update;
  if not found or encode(extensions.digest(b.content,'sha256'),'hex')<>b.content_sha256 then
    raise exception 'restore_rejected'; end if;
  select * into n from public.notes where public_id=p_note_id for update;
  if found and n.owner_id is distinct from p_actor_id then raise exception 'restore_rejected'; end if;
  insert into public.notes(public_id,owner_id,title,content) values(b.public_id,b.owner_id,b.title,b.content)
  on conflict(public_id) do update set title=excluded.title,content=excluded.content
    where notes.owner_id=excluded.owner_id;
  select * into n from public.notes where public_id=p_note_id;
  if n.owner_id is distinct from b.owner_id or n.title is distinct from b.title
    or encode(extensions.digest(n.content,'sha256'),'hex')<>b.content_sha256 then raise exception 'restore_rejected'; end if;
  insert into public.note_recovery_audit(note_id,actor_id,action) values(p_note_id,p_actor_id,'restored_verified');
  return jsonb_build_object('id',p_note_id,'verified',true);
end $$;
revoke all on function public.restore_private_note(uuid,uuid,text,text,text,text) from public,anon,authenticated;
grant execute on function public.restore_private_note(uuid,uuid,text,text,text,text) to service_role;
commit;
