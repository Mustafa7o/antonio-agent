-- Antonio Agent V4.1 production hardening
alter table if exists public.agent_approvals add column if not exists executed_at timestamptz;

-- Keep exposed tables least-privilege. Server-side service credentials must never be shipped to the browser.
revoke all on public.profiles from anon;
revoke all on public.agent_conversations from anon;
revoke all on public.agent_messages from anon;
revoke all on public.agent_memories from anon;
revoke all on public.agent_tasks from anon;
revoke all on public.agent_task_steps from anon;
revoke all on public.agent_approvals from anon;
revoke all on public.agent_schedules from anon;
revoke all on public.agent_runs from anon;
revoke all on public.agent_tool_runs from anon;
revoke all on public.agent_audit_logs from anon;

-- Authenticated users get only the CRUD path protected by the existing owner policies.
grant select, insert, update, delete on public.profiles, public.agent_conversations, public.agent_messages,
public.agent_memories, public.agent_tasks, public.agent_task_steps, public.agent_approvals,
public.agent_schedules, public.agent_runs, public.agent_tool_runs, public.agent_audit_logs to authenticated;
