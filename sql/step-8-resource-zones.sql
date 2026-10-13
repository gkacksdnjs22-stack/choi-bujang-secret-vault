-- 새 구역만 생성합니다. 기존 notes와 자료는 변경하지 않습니다.
begin;
create table if not exists public.instructor_memberships (
  user_id uuid primary key references auth.users(id),
  enabled boolean not null default false
);
create table if not exists public.announcements (
  public_id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);
alter table public.instructor_memberships enable row level security;
alter table public.announcements enable row level security;
revoke all on public.instructor_memberships, public.announcements from public, anon, authenticated;
grant select on public.instructor_memberships to service_role;
grant select, insert, update, delete on public.announcements to service_role;
-- 강사 권한은 DB 관리자가 별도로 등록합니다. 학생·심판을 강사로 승격하지 않습니다.
commit;
