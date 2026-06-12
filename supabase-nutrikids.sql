-- NutriKids: schema relacional com RLS
-- Execute no SQL Editor do Supabase (substitui a tabela legada nutrikids_data)

create extension if not exists "pgcrypto";

drop table if exists public.nutrikids_data cascade;

create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  code text not null unique,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  email text not null,
  role text not null check (role in ('kid', 'pro')),
  age int,
  activity text,
  institution text,
  group_id uuid references public.groups(id) on delete set null,
  points int not null default 0,
  badges jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.challenges (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null,
  group_id uuid not null references public.groups(id) on delete cascade,
  due_date date not null,
  materials jsonb not null default '[]'::jsonb,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.completions (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null references public.challenges(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  completed_at timestamptz not null default now(),
  unique (challenge_id, user_id)
);

create table if not exists public.progress (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  completed_modules jsonb not null default '[]'::jsonb,
  completed_trails jsonb not null default '[]'::jsonb,
  recipes_viewed int not null default 0,
  total_correct int not null default 0,
  quizzes_done int not null default 0,
  challenges_done int not null default 0
);

create table if not exists public.library_items (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  type text not null default 'Texto',
  description text not null default '',
  link text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  content text not null,
  group_id uuid references public.groups(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_profiles_group_id on public.profiles(group_id);
create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_groups_owner_id on public.groups(owner_id);
create index if not exists idx_groups_code on public.groups(code);
create index if not exists idx_challenges_group_id on public.challenges(group_id);
create index if not exists idx_completions_user_id on public.completions(user_id);
create index if not exists idx_library_items_owner_id on public.library_items(owner_id);
create index if not exists idx_notes_owner_id on public.notes(owner_id);

-- Busca de turma por código (cadastro sem login)
create or replace function public.lookup_group_by_code(p_code text)
returns table(id uuid, name text, code text)
language sql
security definer
set search_path = public
as $$
  select g.id, g.name, g.code
  from public.groups g
  where upper(g.code) = upper(p_code)
  limit 1;
$$;

grant execute on function public.lookup_group_by_code(text) to anon, authenticated;

create or replace function public.is_group_owner(p_group_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.groups
    where id = p_group_id and owner_id = auth.uid()
  );
$$;

alter table public.profiles enable row level security;
alter table public.groups enable row level security;
alter table public.challenges enable row level security;
alter table public.completions enable row level security;
alter table public.progress enable row level security;
alter table public.library_items enable row level security;
alter table public.notes enable row level security;

-- profiles
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles for select to authenticated
using (
  id = auth.uid()
  or (
    role = 'kid'
    and group_id is not null
    and public.is_group_owner(group_id)
  )
);

drop policy if exists "profiles_insert" on public.profiles;
create policy "profiles_insert" on public.profiles for insert to authenticated
with check (id = auth.uid());

drop policy if exists "profiles_update" on public.profiles;
create policy "profiles_update" on public.profiles for update to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- groups
drop policy if exists "groups_select" on public.groups;
create policy "groups_select" on public.groups for select to authenticated
using (
  owner_id = auth.uid()
  or id = (select group_id from public.profiles where id = auth.uid())
);

drop policy if exists "groups_insert" on public.groups;
create policy "groups_insert" on public.groups for insert to authenticated
with check (owner_id = auth.uid());

drop policy if exists "groups_update" on public.groups;
create policy "groups_update" on public.groups for update to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

drop policy if exists "groups_delete" on public.groups;
create policy "groups_delete" on public.groups for delete to authenticated
using (owner_id = auth.uid());

-- challenges
drop policy if exists "challenges_select" on public.challenges;
create policy "challenges_select" on public.challenges for select to authenticated
using (
  public.is_group_owner(group_id)
  or group_id = (select group_id from public.profiles where id = auth.uid())
);

drop policy if exists "challenges_insert" on public.challenges;
create policy "challenges_insert" on public.challenges for insert to authenticated
with check (owner_id = auth.uid() and public.is_group_owner(group_id));

drop policy if exists "challenges_update" on public.challenges;
create policy "challenges_update" on public.challenges for update to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

drop policy if exists "challenges_delete" on public.challenges;
create policy "challenges_delete" on public.challenges for delete to authenticated
using (owner_id = auth.uid());

-- completions
drop policy if exists "completions_select" on public.completions;
create policy "completions_select" on public.completions for select to authenticated
using (
  user_id = auth.uid()
  or public.is_group_owner(
    (select group_id from public.profiles where id = completions.user_id)
  )
);

drop policy if exists "completions_insert" on public.completions;
create policy "completions_insert" on public.completions for insert to authenticated
with check (user_id = auth.uid());

drop policy if exists "completions_delete" on public.completions;
create policy "completions_delete" on public.completions for delete to authenticated
using (user_id = auth.uid());

-- progress
drop policy if exists "progress_select" on public.progress;
create policy "progress_select" on public.progress for select to authenticated
using (user_id = auth.uid());

drop policy if exists "progress_insert" on public.progress;
create policy "progress_insert" on public.progress for insert to authenticated
with check (user_id = auth.uid());

drop policy if exists "progress_update" on public.progress;
create policy "progress_update" on public.progress for update to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

-- library_items
drop policy if exists "library_select" on public.library_items;
create policy "library_select" on public.library_items for select to authenticated
using (owner_id = auth.uid());

drop policy if exists "library_insert" on public.library_items;
create policy "library_insert" on public.library_items for insert to authenticated
with check (owner_id = auth.uid());

drop policy if exists "library_update" on public.library_items;
create policy "library_update" on public.library_items for update to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

drop policy if exists "library_delete" on public.library_items;
create policy "library_delete" on public.library_items for delete to authenticated
using (owner_id = auth.uid());

-- notes
drop policy if exists "notes_select" on public.notes;
create policy "notes_select" on public.notes for select to authenticated
using (owner_id = auth.uid());

drop policy if exists "notes_insert" on public.notes;
create policy "notes_insert" on public.notes for insert to authenticated
with check (owner_id = auth.uid());

drop policy if exists "notes_update" on public.notes;
create policy "notes_update" on public.notes for update to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

drop policy if exists "notes_delete" on public.notes;
create policy "notes_delete" on public.notes for delete to authenticated
using (owner_id = auth.uid());
