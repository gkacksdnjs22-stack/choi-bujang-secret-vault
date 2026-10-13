-- 실제 DB 함수 시험. 임시 메모만 사용하고 모든 시험 변경을 롤백합니다.
begin;
create temporary table recovery_check_results(check_name text, passed boolean) on commit drop;
do $$
declare p public.principal_bindings%rowtype; test_id uuid := gen_random_uuid();
  result jsonb; denied boolean; baseline bigint; original_count bigint;
begin
  select * into p from public.principal_bindings where enabled and expires_at>now() limit 1;
  if not found then raise exception '활성 접속 등록이 없어 시험을 중단합니다.'; end if;
  select count(*) into baseline from public.note_recovery_audit;
  select count(*) into original_count from public.notes;
  insert into public.notes(public_id,owner_id,title,content) values(test_id,p.user_id,'recovery transaction fixture','virtual original');
  update public.notes set content='virtual changed' where public_id=test_id;
  result:=public.restore_private_note(test_id,p.user_id,p.class_id,p.project_id,p.subject_id,p.device_id);
  insert into recovery_check_results select 'tampered_note_restored', result->>'verified'='true' and content='virtual original' and owner_id=p.user_id from public.notes where public_id=test_id;
  delete from public.notes where public_id=test_id;
  result:=public.restore_private_note(test_id,p.user_id,p.class_id,p.project_id,p.subject_id,p.device_id);
  insert into recovery_check_results select 'deleted_note_restored', result->>'verified'='true' and content='virtual original' and owner_id=p.user_id from public.notes where public_id=test_id;
  denied:=false;
  begin perform public.restore_private_note(test_id,gen_random_uuid(),p.class_id,p.project_id,p.subject_id,p.device_id);
  exception when others then if sqlerrm='restore_rejected' then denied:=true; else raise; end if; end;
  insert into recovery_check_results values('other_actor_denied',denied);
  denied:=false;
  begin perform public.restore_private_note(test_id,p.user_id,p.class_id,p.project_id,p.subject_id,'unregistered');
  exception when others then if sqlerrm='restore_rejected' then denied:=true; else raise; end if; end;
  insert into recovery_check_results values('unregistered_device_denied',denied);
  update public.note_recovery_snapshots set content_sha256='invalid' where public_id=test_id;
  denied:=false;
  begin perform public.restore_private_note(test_id,p.user_id,p.class_id,p.project_id,p.subject_id,p.device_id);
  exception when others then if sqlerrm='restore_rejected' then denied:=true; else raise; end if; end;
  insert into recovery_check_results values('invalid_snapshot_denied',denied);
  insert into recovery_check_results select 'audit_append_only',count(*)=baseline+2 from public.note_recovery_audit;
  insert into recovery_check_results select 'only_fixture_added',count(*)=original_count+1 from public.notes;
  if exists(select 1 from recovery_check_results where not passed or passed is null) then raise exception '복구 시험 실패'; end if;
end $$;
select * from recovery_check_results order by check_name;
rollback;
