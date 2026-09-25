import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import pg from 'pg';
const { Pool } = pg;

const connectionString = process.env.DATABASE_URL || process.env.SUPABASE_DB_URL || '';
export const cloudDb = Boolean(connectionString);

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,user_id TEXT NOT NULL DEFAULT 'local',role TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',kind TEXT NOT NULL,content TEXT NOT NULL,importance INTEGER DEFAULT 5,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT NOT NULL,status TEXT NOT NULL,priority INTEGER DEFAULT 5,goal TEXT,result TEXT,due_at TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_steps(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,step_no INTEGER NOT NULL,action TEXT NOT NULL,status TEXT NOT NULL,output TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',task_id TEXT,action TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,decided_at TEXT,executed_at TEXT);
CREATE TABLE IF NOT EXISTS tool_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,run_id TEXT,tool TEXT NOT NULL,input TEXT NOT NULL,output TEXT,status TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,event TEXT NOT NULL,data TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,prompt TEXT NOT NULL,run_at TEXT,repeat_minutes INTEGER,enabled INTEGER DEFAULT 1,last_run_at TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,conversation_id TEXT,task_id TEXT,status TEXT,input TEXT,output TEXT,error TEXT,started_at TEXT NOT NULL,finished_at TEXT);
CREATE TABLE IF NOT EXISTS integration_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,access_token TEXT,refresh_token TEXT,token_json TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(user_id,provider));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`;

const pgSchema = `
CREATE SCHEMA IF NOT EXISTS antonio;
SET search_path TO antonio, public;
CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,conversation_id TEXT NOT NULL,user_id TEXT NOT NULL DEFAULT 'local',role TEXT NOT NULL,content TEXT NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',kind TEXT NOT NULL,content TEXT NOT NULL,importance integer DEFAULT 5,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',title TEXT NOT NULL,status TEXT NOT NULL,priority integer DEFAULT 5,goal TEXT,result TEXT,due_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS task_steps(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,step_no integer NOT NULL,action TEXT NOT NULL,status TEXT NOT NULL,output TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL DEFAULT 'local',task_id TEXT,action TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,created_at timestamptz NOT NULL,decided_at timestamptz,executed_at timestamptz);
CREATE TABLE IF NOT EXISTS tool_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,run_id TEXT,tool TEXT NOT NULL,input TEXT NOT NULL,output TEXT,status TEXT NOT NULL,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,event TEXT NOT NULL,data TEXT,created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,task_id TEXT,prompt TEXT NOT NULL,run_at timestamptz,repeat_minutes integer,enabled boolean DEFAULT true,last_run_at timestamptz,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS agent_runs(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,conversation_id TEXT,task_id TEXT,status TEXT,input TEXT,output TEXT,error TEXT,started_at timestamptz NOT NULL,finished_at timestamptz);
CREATE TABLE IF NOT EXISTS integration_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,access_token TEXT,refresh_token TEXT,token_json TEXT,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,UNIQUE(user_id,provider));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_tasks_user_status ON tasks(user_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules(enabled,run_at);
CREATE INDEX IF NOT EXISTS idx_approvals_user_status ON approvals(user_id,status,created_at DESC);
`;

function convert(sql, params) { let i=0; return {sql:sql.replace(/\?/g,()=>`$${++i}`),params}; }

let impl;
if (cloudDb) {
  const pool = new Pool({connectionString,options:'-c search_path=antonio,public',max:Number(process.env.DB_POOL_MAX||10),idleTimeoutMillis:30000,connectionTimeoutMillis:10000,ssl:process.env.DB_SSL==='false'?false:{rejectUnauthorized:false}});
  await pool.query(pgSchema);
  impl = { async run(sql,p=[]){const c=convert(sql,p);return pool.query(c.sql,c.params)}, async get(sql,p=[]){const c=convert(sql,p);const r=await pool.query(c.sql,c.params);return r.rows[0]||undefined}, async all(sql,p=[]){const c=convert(sql,p);const r=await pool.query(c.sql,c.params);return r.rows}, async exec(sql){return pool.query(sql)}, async close(){await pool.end()} };
} else {
  const sqlite = new Database(process.env.SQLITE_PATH || 'data/antonio.db');
  sqlite.pragma('journal_mode=WAL'); sqlite.pragma('foreign_keys=ON'); sqlite.exec(sqliteSchema);
  try { sqlite.exec('ALTER TABLE approvals ADD COLUMN executed_at TEXT'); } catch {}
  impl = { async run(sql,p=[]){return sqlite.prepare(sql).run(...p)}, async get(sql,p=[]){return sqlite.prepare(sql).get(...p)}, async all(sql,p=[]){return sqlite.prepare(sql).all(...p)}, async exec(sql){return sqlite.exec(sql)}, async close(){sqlite.close()} };
}

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
