alter table public.notes add column if not exists public_id uuid not null default gen_random_uuid();
create unique index if not exists notes_public_id_key on public.notes(public_id);
