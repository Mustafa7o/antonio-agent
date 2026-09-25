# Antonio Agent V4.1

Antonio is an execution-oriented personal digital agent built around the OpenAI Responses API, persistent tasks, durable memory, approvals, scheduling, audit logs, and external integrations.

## V4.1 fixes
- Production Postgres/Supabase database path through `DATABASE_URL` or `SUPABASE_DB_URL`.
- SQLite retained only as a local-development fallback.
- Separate web process and background worker.
- Approval records are bound to the exact action payload and can execute immediately after approval.
- OAuth state is short-lived and single-use.
- Google OAuth tokens are encrypted at rest with AES-256-GCM.
- Health and readiness endpoints are unauthenticated and suitable for hosting health checks.
- Dashboard statistics now match the API.
- Production headers, request limits, graceful shutdown, rate-limit cleanup, and input validation added.
- Default API model updated to `gpt-5.6-luna`.
- Responses API web search uses the current `web_search` tool.

## Local development

```bash
cp .env.example .env
npm install
npm start
```

For the background scheduler in a second terminal:

```bash
npm run worker
```

Open `http://localhost:3000`.

## Production

Use PostgreSQL for production. A Supabase Postgres connection string can be supplied through `DATABASE_URL` (or `SUPABASE_DB_URL`). Keep the database connection string private.

Run the web service and worker as separate processes/containers:

```bash
npm start
npm run worker
```

The included `render.yaml` provides a two-service deployment layout for Render.

## Required production secrets

- `OPENAI_API_KEY`
- `DATABASE_URL`
- `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` if Supabase Auth is enabled
- `TOKEN_ENCRYPTION_KEY`

Never commit secrets to Git. OpenAI recommends keeping API keys in environment variables or a secret manager, not source code or client-side applications. See the official production guidance. 

## Supabase

The `supabase/migrations` directory contains the user-facing Supabase schema and RLS policies. The server's own operational tables live in a private `antonio` Postgres schema when using `DATABASE_URL`, so they are not exposed through the normal Data API.

Apply the migrations in your Supabase project if you want the Auth-facing schema and RLS policies.

## Google

Configure the OAuth client and use:

`https://YOUR-DOMAIN/api/integrations/google/callback`

as the production redirect URI.

## Important

Antonio cannot access an external account until its OAuth/API credentials are configured. The agent only reports an external action as successful after the provider returns success.
