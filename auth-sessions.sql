-- Persistent, revocable refresh-token sessions. Run with the service-role migration account.
create table if not exists public.admin_sessions (
  id uuid primary key,
  admin_id bigint not null references public.admin_users(id) on delete cascade,
  refresh_token_hash text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint admin_sessions_expiry_valid check (expires_at > created_at)
);

create index if not exists admin_sessions_admin_id_idx
  on public.admin_sessions(admin_id);
create index if not exists admin_sessions_active_expiry_idx
  on public.admin_sessions(expires_at)
  where revoked_at is null;

alter table public.admin_sessions enable row level security;
revoke all on table public.admin_sessions from public, anon, authenticated;
grant all on table public.admin_sessions to service_role;
