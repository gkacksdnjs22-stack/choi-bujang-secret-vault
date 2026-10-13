-- 관리자만 검증된 로그인 계정과 엔진 주체를 연결합니다.
-- 이 연결은 메모 소유권이나 강사 권한을 부여하지 않습니다.
begin;
create table if not exists public.principal_bindings (
  class_id text not null,
  project_id text not null,
  subject_id text not null,
  device_id text not null check (device_id ~ '^[a-f0-9]{16}$'),
  user_id uuid not null references auth.users(id),
  enabled boolean not null default false,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  primary key (class_id, project_id, subject_id, device_id)
);
alter table public.principal_bindings enable row level security;
revoke all on public.principal_bindings from public, anon, authenticated;
revoke all on public.principal_bindings from service_role;
grant select on public.principal_bindings to service_role;
-- 추가·수정·회수는 DB 관리자가 수행합니다. 앱 서버는 조회만 합니다.
-- 확인된 엔진 주체가 없으면 등록하지 않습니다. 실제 계정 데이터는 이 파일에 넣지 않습니다.
commit;
