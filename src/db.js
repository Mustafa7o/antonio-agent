import crypto from 'node:crypto';
import pg from 'pg';
const { Pool } = pg;

const rawConnectionString = process.env.DATABASE_URL || process.env.DATABASE_URL_POOLER || process.env.SUPABASE_DB_URL || '';
let connectionString = rawConnectionString;
if (process.env.DB_SUPAVISOR_POOLER === 'true' && rawConnectionString) {
  const url = new URL(rawConnectionString);
  if (url.hostname.endsWith('.supabase.co')) {
    url.hostname = 'aws-ap-northeast-1.pooler.supabase.com';
    url.port = '5432';
    if (url.username === 'postgres') url.username = 'postgres.fxtmxhfoqqbemzbdtdet';
    connectionString = url.toString();
  }
}
export const cloudDb = Boolean(connectionString);

const pgSchema = `
CREATE SCHEMA IF NOT EXISTS antonio;
SET search_path TO antonio, public;
CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,user_id TEXT NOT NULL DEFAULT 'local',role TEXT NOT NULL,content TEXT NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',kind TEXT NOT NULL,content TEXT NOT NULL,importance integer DEFAULT 5,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT NOT NULL,status TEXT NOT NULL,priority integer DEFAULT 5,goal TEXT,result TEXT,due_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);\nALTER TABLE tasks ADD COLUMN IF NOT EXISTS retry_count integer NOT NULL DEFAULT 0;\nALTER TABLE tasks ADD COLUMN IF NOT EXISTS max_retries integer NOT NULL DEFAULT 2;\nALTER TABLE tasks ADD COLUMN IF NOT EXISTS next_retry_at timestamptz;\nALTER TABLE tasks ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;\nALTER TABLE tasks ADD COLUMN IF NOT EXISTS acknowledged_by_user boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS task_steps(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,step_no integer NOT NULL,action TEXT NOT NULL,status TEXT NOT NULL,output TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',task_id TEXT,action TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,created_at timestamptz NOT NULL,decided_at timestamptz,executed_at timestamptz);
CREATE TABLE IF NOT EXISTS tool_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,run_id TEXT,tool TEXT NOT NULL,input TEXT NOT NULL,output TEXT,status TEXT NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,event TEXT NOT NULL,data TEXT,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,prompt TEXT NOT NULL,run_at timestamptz,repeat_minutes integer,enabled boolean DEFAULT true,last_run_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS agent_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,conversation_id TEXT,task_id TEXT,status TEXT,input TEXT,output TEXT,error TEXT,started_at timestamptz NOT NULL,finished_at timestamptz);
CREATE TABLE IF NOT EXISTS integration_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,access_token TEXT,refresh_token TEXT,token_json TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,UNIQUE(user_id,provider));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,description TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'active',created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS goals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,project_id TEXT,title TEXT NOT NULL,description TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'active',priority integer DEFAULT 5,target_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS agent_plans(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,user_id TEXT NOT NULL,goal TEXT NOT NULL,plan_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS agent_steps(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,step_no integer NOT NULL,step_key TEXT NOT NULL,action TEXT NOT NULL,tool_hint TEXT,verification TEXT,status TEXT NOT NULL DEFAULT 'pending',output TEXT DEFAULT '',started_at timestamptz,finished_at timestamptz);
CREATE TABLE IF NOT EXISTS push_subscriptions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,endpoint TEXT NOT NULL,p256dh TEXT NOT NULL,auth TEXT NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,UNIQUE(user_id,endpoint));\nCREATE TABLE IF NOT EXISTS correspondence(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,direction TEXT NOT NULL,contact TEXT,subject TEXT,body TEXT,external_message_id TEXT,external_thread_id TEXT,status TEXT NOT NULL DEFAULT 'sent',last_inbound_message_id TEXT,last_checked_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS whatsapp_messages(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,direction TEXT NOT NULL,contact TEXT NOT NULL,message TEXT NOT NULL,external_message_id TEXT,message_type TEXT,status TEXT NOT NULL DEFAULT 'sent',error TEXT,created_at timestamptz NOT NULL);
ALTER TABLE whatsapp_messages ADD COLUMN IF NOT EXISTS raw_payload TEXT;
CREATE INDEX IF NOT EXISTS idx_whatsapp_messages_user_created ON whatsapp_messages(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_whatsapp_messages_user_direction ON whatsapp_messages(user_id,direction,created_at DESC);\nALTER TABLE correspondence ADD COLUMN IF NOT EXISTS reply_from TEXT;\nALTER TABLE correspondence ADD COLUMN IF NOT EXISTS reply_subject TEXT;\nALTER TABLE correspondence ADD COLUMN IF NOT EXISTS reply_body TEXT;\nALTER TABLE correspondence ADD COLUMN IF NOT EXISTS reply_received_at timestamptz;\nCREATE INDEX IF NOT EXISTS idx_correspondence_user_updated ON correspondence(user_id,updated_at DESC);\nCREATE INDEX IF NOT EXISTS idx_correspondence_thread ON correspondence(user_id,provider,external_thread_id);
CREATE INDEX IF NOT EXISTS idx_tasks_user_status ON tasks(user_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(enabled,run_at);
CREATE INDEX IF NOT EXISTS idx_approvals_user_status ON approvals(user_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id,updated_at DESC);
`;

function convert(sql, params) { let i=0; return {sql:sql.replace(/\?/g,()=>`$${++i}`),params}; }

let impl;
if (!cloudDb) {
  throw new Error('DATABASE_URL is required. Antonio 5 uses Supabase/Postgres only.');
}
const pool = new Pool({connectionString,options:'-c search_path=antonio,public',max:Number(process.env.DB_POOL_MAX||10),idleTimeoutMillis:30000,connectionTimeoutMillis:10000,ssl:process.env.DB_SSL==='false'?false:{rejectUnauthorized:false},family:process.env.DB_IPV4_ONLY==='true'?4:undefined});
await pool.query(pgSchema);
impl = {
  async run(sql,p=[]){const c=convert(sql,p);return pool.query(c.sql,c.params)},
  async get(sql,p=[]){const c=convert(sql,p);const r=await pool.query(c.sql,c.params);return r.rows[0]||undefined},
  async all(sql,p=[]){const c=convert(sql,p);const r=await pool.query(c.sql,c.params);return r.rows},
  async exec(sql){return pool.query(sql)},
  async close(){await pool.end()}
};

export const db = {
  prepare(sql){return {run:(...p)=>impl.run(sql,p),get:(...p)=>impl.get(sql,p),all:(...p)=>impl.all(sql,p)}},
  exec:(sql)=>impl.exec(sql),
  close:()=>impl.close()
};
export const now=()=>new Date().toISOString();
export const id=()=>crypto.randomUUID();
export function stableJson(value){
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value==='object') return `{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${stableJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const audit=(userId,event,data={})=>db.prepare('INSERT INTO audit_logs(id,user_id,event,data,created_at) VALUES(?,?,?,?,?)').run(id(),userId,event,JSON.stringify(data),now());
