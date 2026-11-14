-- =============================================================================
-- Note Transfer — Supabase schema
--
-- Paste this whole file into Supabase Dashboard → SQL Editor → Run.
-- It is idempotent: running it again upgrades functions in place.
--
-- Design:
--   * Tables live in a private schema (`note_transfer`) that the public API
--     cannot see. The browser can ONLY call the `public.nt_*` functions below.
--   * Every function checks the space name + auth token, so knowing the URL and
--     public API key is not enough to read or list anything.
--   * The browser derives two secrets from the password (PBKDF2): an AES key that
--     never leaves the device, and an auth token. Only SHA-256(auth token) is
--     stored here. Note contents arrive already encrypted (AES-GCM).
--   * Spaces live at most 5 days after creation (enforced by a CHECK
--     constraint), are purged on every request, and also by a pg_cron job.
--   * 10 wrong passwords lock a space for 10 minutes.
-- =============================================================================

create schema if not exists note_transfer;
revoke all on schema note_transfer from public;
do $$ begin
  execute 'revoke all on schema note_transfer from anon, authenticated';
exception when undefined_object then null; end $$;

create table if not exists note_transfer.spaces (
  name            text primary key check (name ~ '^[a-z0-9-]{1,64}$'),
  auth_hash       bytea not null,
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null,
  failed_attempts integer not null default 0,
  locked_until    timestamptz,
  constraint spaces_max_lifespan check (expires_at <= created_at + interval '5 days')
);
create index if not exists spaces_expires_at_idx on note_transfer.spaces (expires_at);

create table if not exists note_transfer.notes (
  id          uuid primary key default gen_random_uuid(),
  space_name  text not null references note_transfer.spaces (name) on delete cascade,
  ciphertext  text not null check (length(ciphertext) <= 400000),
  iv          text not null check (length(iv) <= 64),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists notes_space_idx on note_transfer.notes (space_name, created_at);

alter table note_transfer.spaces enable row level security;
alter table note_transfer.notes  enable row level security;
revoke all on all tables in schema note_transfer from public;

-- -----------------------------------------------------------------------------
-- Internal helpers (not exposed through the API)
-- -----------------------------------------------------------------------------

create or replace function note_transfer.purge_expired()
returns void language sql security definer set search_path = '' as $$
  delete from note_transfer.spaces where expires_at <= now();
$$;

-- Returns 'ok' | 'not_found' | 'bad_password' | 'locked'.
-- Never raises, so failed-attempt counters are actually persisted.
create or replace function note_transfer.check_auth(p_name text, p_auth text)
returns text language plpgsql security definer set search_path = '' as $$
declare
  s note_transfer.spaces%rowtype;
begin
  select * into s from note_transfer.spaces
   where name = p_name and expires_at > now()
   for update;
  if not found then
    return 'not_found';
  end if;
  if s.locked_until is not null and s.locked_until > now() then
    return 'locked';
  end if;
  if p_auth is not null and s.auth_hash = sha256(convert_to(p_auth, 'UTF8')) then
    if s.failed_attempts <> 0 or s.locked_until is not null then
      update note_transfer.spaces set failed_attempts = 0, locked_until = null where name = p_name;
    end if;
    return 'ok';
  end if;
  update note_transfer.spaces
     set failed_attempts = case when failed_attempts + 1 >= 10 then 0 else failed_attempts + 1 end,
         locked_until    = case when failed_attempts + 1 >= 10 then now() + interval '10 minutes' else null end
   where name = p_name;
  return 'bad_password';
end $$;

create or replace function note_transfer.err(p_code text)
returns jsonb language sql immutable as $$ select jsonb_build_object('error', p_code) $$;

create or replace function note_transfer.note_json(n note_transfer.notes)
returns jsonb language sql immutable as $$
  select jsonb_build_object('id', n.id, 'ciphertext', n.ciphertext, 'iv', n.iv,
                            'created_at', n.created_at, 'updated_at', n.updated_at)
$$;

revoke all on all functions in schema note_transfer from public;

-- -----------------------------------------------------------------------------
-- Public API (called from the browser via /rest/v1/rpc/<name>)
-- Every function returns JSON; failures look like {"error": "<code>"}.
-- -----------------------------------------------------------------------------

create or replace function public.nt_create_space(p_name text, p_auth text, p_lifespan_seconds integer)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  s note_transfer.spaces%rowtype;
begin
  perform note_transfer.purge_expired();
  if p_name is null or p_name !~ '^[a-z0-9-]{1,64}$' then
    return note_transfer.err('invalid_name');
  end if;
  if p_auth is null or p_auth !~ '^[0-9a-f]{64}$' then
    return note_transfer.err('invalid_auth');
  end if;
  if p_lifespan_seconds is null or p_lifespan_seconds < 60 or p_lifespan_seconds > 432000 then
    return note_transfer.err('invalid_lifespan');
  end if;

  insert into note_transfer.spaces (name, auth_hash, created_at, expires_at)
  values (p_name, sha256(convert_to(p_auth, 'UTF8')), now(), now() + make_interval(secs => p_lifespan_seconds))
  on conflict (name) do nothing
  returning * into s;

  if not found then
    return note_transfer.err('name_taken');
  end if;
  return jsonb_build_object('name', s.name, 'created_at', s.created_at, 'expires_at', s.expires_at, 'notes', '[]'::jsonb);
end $$;

create or replace function public.nt_open_space(p_name text, p_auth text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
  s  note_transfer.spaces%rowtype;
begin
  perform note_transfer.purge_expired();
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  select * into s from note_transfer.spaces where name = p_name;
  return jsonb_build_object(
    'name', s.name, 'created_at', s.created_at, 'expires_at', s.expires_at,
    'notes', coalesce((select jsonb_agg(note_transfer.note_json(n) order by n.created_at desc)
                         from note_transfer.notes n where n.space_name = p_name), '[]'::jsonb));
end $$;

create or replace function public.nt_add_note(p_name text, p_auth text, p_ciphertext text, p_iv text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
  n  note_transfer.notes%rowtype;
begin
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  if p_ciphertext is null or length(p_ciphertext) > 400000 or p_iv is null or length(p_iv) > 64 then
    return note_transfer.err('too_large');
  end if;
  if (select count(*) from note_transfer.notes where space_name = p_name) >= 500 then
    return note_transfer.err('too_many_notes');
  end if;
  insert into note_transfer.notes (space_name, ciphertext, iv)
  values (p_name, p_ciphertext, p_iv)
  returning * into n;
  return note_transfer.note_json(n);
end $$;

create or replace function public.nt_update_note(p_name text, p_auth text, p_id uuid, p_ciphertext text, p_iv text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
  n  note_transfer.notes%rowtype;
begin
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  if p_ciphertext is null or length(p_ciphertext) > 400000 or p_iv is null or length(p_iv) > 64 then
    return note_transfer.err('too_large');
  end if;
  update note_transfer.notes
     set ciphertext = p_ciphertext, iv = p_iv, updated_at = now()
   where id = p_id and space_name = p_name
  returning * into n;
  if not found then return note_transfer.err('note_not_found'); end if;
  return note_transfer.note_json(n);
end $$;

create or replace function public.nt_delete_note(p_name text, p_auth text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
begin
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  delete from note_transfer.notes where id = p_id and space_name = p_name;
  return jsonb_build_object('ok', true);
end $$;

-- Sets a new expiry. It may be shortened or extended, but never past
-- created_at + 5 days (later values are clamped to that limit).
create or replace function public.nt_set_expiry(p_name text, p_auth text, p_expires_at timestamptz)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
  s  note_transfer.spaces%rowtype;
begin
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  if p_expires_at is null or p_expires_at < now() + interval '30 seconds' then
    return note_transfer.err('invalid_expiry');
  end if;
  update note_transfer.spaces
     set expires_at = least(p_expires_at, created_at + interval '5 days')
   where name = p_name
  returning * into s;
  return jsonb_build_object('name', s.name, 'created_at', s.created_at, 'expires_at', s.expires_at);
end $$;

create or replace function public.nt_delete_space(p_name text, p_auth text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  st text;
begin
  st := note_transfer.check_auth(p_name, p_auth);
  if st <> 'ok' then return note_transfer.err(st); end if;
  delete from note_transfer.spaces where name = p_name;
  return jsonb_build_object('ok', true);
end $$;

-- Only the nt_* functions are callable by API clients.
revoke execute on function public.nt_create_space(text, text, integer)            from public;
revoke execute on function public.nt_open_space(text, text)                       from public;
revoke execute on function public.nt_add_note(text, text, text, text)             from public;
revoke execute on function public.nt_update_note(text, text, uuid, text, text)    from public;
revoke execute on function public.nt_delete_note(text, text, uuid)                from public;
revoke execute on function public.nt_set_expiry(text, text, timestamptz)          from public;
revoke execute on function public.nt_delete_space(text, text)                     from public;
do $$ begin
  grant execute on function public.nt_create_space(text, text, integer)         to anon, authenticated;
  grant execute on function public.nt_open_space(text, text)                    to anon, authenticated;
  grant execute on function public.nt_add_note(text, text, text, text)          to anon, authenticated;
  grant execute on function public.nt_update_note(text, text, uuid, text, text) to anon, authenticated;
  grant execute on function public.nt_delete_note(text, text, uuid)             to anon, authenticated;
  grant execute on function public.nt_set_expiry(text, text, timestamptz)       to anon, authenticated;
  grant execute on function public.nt_delete_space(text, text)                  to anon, authenticated;
exception when undefined_object then
  raise notice 'anon/authenticated roles not found (not running on Supabase?) — skipping grants';
end $$;

-- -----------------------------------------------------------------------------
-- Scheduled cleanup: physically delete expired spaces every 5 minutes.
-- (Every API call also purges expired spaces, so names free up immediately
-- even if pg_cron is unavailable.)
-- -----------------------------------------------------------------------------
do $$
begin
  create extension if not exists pg_cron;
  perform cron.schedule('note-transfer-purge', '*/5 * * * *',
                        'delete from note_transfer.spaces where expires_at <= now()');
exception when others then
  raise notice 'pg_cron not available (%). Expired spaces are still purged on every request.', sqlerrm;
end $$;

-- Ask PostgREST to pick up the new functions right away.
notify pgrst, 'reload schema';
