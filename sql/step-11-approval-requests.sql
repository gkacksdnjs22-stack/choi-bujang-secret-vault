-- 신청 기록만 저장합니다. principal_bindings 또는 기기 권한은 변경하지 않습니다.
begin;
create table if not exists public.device_approval_requests (
  class_id text not null,project_id text not null,subject_id text not null,
  device_id text not null,user_id uuid not null,requested_at timestamptz not null default now(),
  primary key(class_id,project_id,subject_id,device_id,user_id)
);
alter table public.device_approval_requests enable row level security;
revoke all on public.device_approval_requests from public,anon,authenticated;
grant select,insert,update on public.device_approval_requests to service_role;
commit;
