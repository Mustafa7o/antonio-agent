-- Antonio Agent V3: cloud schema + RLS
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_conversations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.agent_conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('system','user','assistant','tool')),
  content text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.agent_memories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null,
  content text not null,
  importance int not null default 5 check (importance between 1 and 10),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  goal text,
  status text not null default 'planned' check (status in ('planned','running','waiting_approval','completed','failed','cancelled')),
  priority int not null default 5 check (priority between 1 and 10),
  result text,
  due_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_task_steps (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.agent_tasks(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  step_no int not null,
  action text not null,
  status text not null default 'pending',
  output text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_approvals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  task_id uuid references public.agent_tasks(id) on delete set null,
  action text not null,
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);

create table if not exists public.agent_schedules (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  task_id uuid references public.agent_tasks(id) on delete set null,
  prompt text not null,
  run_at timestamptz not null,
  repeat_minutes int,
  enabled boolean not null default true,
  last_run_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.agent_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  conversation_id uuid references public.agent_conversations(id) on delete set null,
  task_id uuid references public.agent_tasks(id) on delete set null,
  status text not null default 'running',
  input text,
  output text,
  error text,
  started_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists public.agent_tool_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  run_id uuid references public.agent_runs(id) on delete set null,
  task_id uuid references public.agent_tasks(id) on delete set null,
  tool text not null,
  input jsonb not null default '{}'::jsonb,
  output jsonb,
  status text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.agent_audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  event text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_agent_messages_conversation on public.agent_messages(conversation_id, created_at);
create index if not exists idx_agent_memories_user on public.agent_memories(user_id, importance desc, updated_at desc);
create index if not exists idx_agent_tasks_user on public.agent_tasks(user_id, status, updated_at desc);
create index if not exists idx_agent_schedules_due on public.agent_schedules(enabled, run_at);

alter table public.profiles enable row level security;
alter table public.agent_conversations enable row level security;
alter table public.agent_messages enable row level security;
alter table public.agent_memories enable row level security;
alter table public.agent_tasks enable row level security;
alter table public.agent_task_steps enable row level security;
alter table public.agent_approvals enable row level security;
alter table public.agent_schedules enable row level security;
alter table public.agent_runs enable row level security;
alter table public.agent_tool_runs enable row level security;
alter table public.agent_audit_logs enable row level security;

create policy "own profile" on public.profiles for all to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create policy "own conversations" on public.agent_conversations for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own messages" on public.agent_messages for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own memories" on public.agent_memories for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own tasks" on public.agent_tasks for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own task steps" on public.agent_task_steps for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own approvals" on public.agent_approvals for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own schedules" on public.agent_schedules for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own runs" on public.agent_runs for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own tool runs" on public.agent_tool_runs for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own audit" on public.agent_audit_logs for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
