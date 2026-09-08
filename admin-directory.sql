-- Rich Discord metadata used by the public Riverra directory.
alter table public.admin_users
  add column if not exists discord_global_name text,
  add column if not exists discord_banner text,
  add column if not exists discord_accent_color integer,
  add column if not exists discord_avatar_decoration text,
  add column if not exists discord_avatar_decoration_sku_id text,
  add column if not exists discord_nameplate text,
  add column if not exists discord_nameplate_sku_id text,
  add column if not exists discord_nameplate_palette text,
  add column if not exists discord_primary_guild_id text,
  add column if not exists discord_primary_guild_tag text,
  add column if not exists discord_primary_guild_badge text,
  add column if not exists discord_primary_guild_enabled boolean,
  add column if not exists discord_profile_updated_at timestamptz;
