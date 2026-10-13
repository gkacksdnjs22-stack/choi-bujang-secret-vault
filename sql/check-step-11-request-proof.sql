begin;
do $$
declare c uuid:=gen_random_uuid(); n uuid:=gen_random_uuid();
begin
  if not public.consume_app_request_nonce(c,n,now()+interval '5 minutes') then raise exception 'first nonce rejected'; end if;
  if public.consume_app_request_nonce(c,n,now()+interval '5 minutes') then raise exception 'replay accepted'; end if;
  if public.consume_app_request_nonce(c,gen_random_uuid(),now()-interval '1 second') then raise exception 'expired accepted'; end if;
  if public.consume_app_request_nonce(c,gen_random_uuid(),now()+interval '11 minutes') then raise exception 'future accepted'; end if;
  if has_function_privilege('anon','public.consume_app_request_nonce(uuid,uuid,timestamp with time zone)','EXECUTE') then raise exception 'anon privilege'; end if;
  if has_function_privilege('authenticated','public.consume_app_request_nonce(uuid,uuid,timestamp with time zone)','EXECUTE') then raise exception 'authenticated privilege'; end if;
end $$;
rollback;
select 'nonce first/replay/expiry/privileges passed; test rolled back' as result;
