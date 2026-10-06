-- 먼저 실행해 현재 권한을 기록합니다.
select grantee, privilege_type from information_schema.role_table_grants where table_schema='public' and table_name='notes' order by grantee,privilege_type;
select role_name, p, has_table_privilege(role_name,'public.notes',p) as allowed from (values ('anon'),('authenticated')) as roles(role_name) cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) as permissions(p);

begin;
alter table public.notes enable row level security;
revoke all on table public.notes from PUBLIC, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;
grant usage on sequence public.notes_id_seq to authenticated;
create policy notes_owner_select on public.notes for select to authenticated using ((select auth.uid())=owner_id);
create policy notes_owner_insert on public.notes for insert to authenticated with check ((select auth.uid())=owner_id);
create policy notes_owner_update on public.notes for update to authenticated using ((select auth.uid())=owner_id) with check ((select auth.uid())=owner_id);
create policy notes_owner_delete on public.notes for delete to authenticated using ((select auth.uid())=owner_id);
commit;

-- 적용 후 위와 같은 권한 조회로 대조합니다.
select grantee, privilege_type from information_schema.role_table_grants where table_schema='public' and table_name='notes' order by grantee,privilege_type;
select role_name, p, has_table_privilege(role_name,'public.notes',p) as allowed from (values ('anon'),('authenticated')) as roles(role_name) cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) as permissions(p);
