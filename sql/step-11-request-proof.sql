-- 서버 전용 단회 nonce 소비. 메모·기기 승인·권한은 바꾸지 않습니다.
begin;
create table if not exists public.app_request_nonces (
  certificate_id uuid not null,nonce uuid not null,expires_at timestamptz not null,
  primary key(certificate_id,nonce)
);
alter table public.app_request_nonces enable row level security;
revoke all on public.app_request_nonces from public,anon,authenticated,service_role;
create or replace function public.consume_app_request_nonce(p_certificate_id uuid,p_nonce uuid,p_expires_at timestamptz)
returns boolean language plpgsql security definer set search_path=pg_catalog,public as $$
declare inserted integer;
begin
  if p_expires_at<=now() or p_expires_at>now()+interval '10 minutes' then return false; end if;
  insert into public.app_request_nonces values(p_certificate_id,p_nonce,p_expires_at) on conflict do nothing;
  get diagnostics inserted=row_count;
  return inserted=1;
end $$;
revoke all on function public.consume_app_request_nonce(uuid,uuid,timestamptz) from public,anon,authenticated;
grant execute on function public.consume_app_request_nonce(uuid,uuid,timestamptz) to service_role;
commit;
