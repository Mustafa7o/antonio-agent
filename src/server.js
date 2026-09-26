import 'dotenv/config';
import express from 'express';
import OpenAI from 'openai';
import crypto from 'node:crypto';
import { db, now, id, audit, cloudDb, stableJson } from './db.js';
import { authEnabled, supabase, verifyAccessToken } from './cloud.js';
import { integrationState, googleAuthUrl, googleExchange, gmailSend, gmailList, calendarCreate, telegramSend, whatsappSend } from './integrations.js';

const TOKEN_KEY = process.env.TOKEN_ENCRYPTION_KEY || '';
if(process.env.NODE_ENV==='production' && !TOKEN_KEY) throw new Error('TOKEN_ENCRYPTION_KEY is required in production');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));
app.use(express.json({ limit: '2mb' }));
app.use((req,res,next)=>{res.set({
  'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin',
  'Permissions-Policy':'camera=(),microphone=(),geolocation=()','Cache-Control':'no-store, no-cache, must-revalidate, proxy-revalidate'
});next()});
app.use(express.static('public'));

const openai = process.env.OPENAI_API_KEY ? new OpenAI({apiKey:process.env.OPENAI_API_KEY}) : null;
const MODEL = process.env.OPENAI_MODEL || 'gpt-5.6-luna';
function protectSecret(value){
  if(!TOKEN_KEY)return process.env.NODE_ENV==='production' ? (()=>{throw new Error('TOKEN_ENCRYPTION_KEY is required in production')})() : value;
  const key=crypto.createHash('sha256').update(TOKEN_KEY).digest(); const iv=crypto.randomBytes(12); const c=crypto.createCipheriv('aes-256-gcm',key,iv); const enc=Buffer.concat([c.update(String(value),'utf8'),c.final()]); return `enc:v1:${iv.toString('base64url')}:${c.getAuthTag().toString('base64url')}:${enc.toString('base64url')}`;
}
function revealSecret(value){
  if(!value?.startsWith('enc:v1:'))return value;
  if(!TOKEN_KEY)throw new Error('TOKEN_ENCRYPTION_KEY is required');
  const [,v,ivS,tagS,dataS]=value.split(':'); const key=crypto.createHash('sha256').update(TOKEN_KEY).digest(); const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(ivS,'base64url')); d.setAuthTag(Buffer.from(tagS,'base64url')); return Buffer.concat([d.update(Buffer.from(dataS,'base64url')),d.final()]).toString('utf8');
}
async function integrationSecret(userId,provider){const row=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,provider);if(!row?.token_json)return null;try{return JSON.parse(revealSecret(row.token_json))}catch{return null}}

const RATE = Math.max(1, Number(process.env.RATE_LIMIT_PER_MINUTE || 60));
const buckets = new Map();
function rate(req,res,next){
  const key=req.ip||'unknown', minute=Math.floor(Date.now()/60000); let b=buckets.get(key);
  if(!b || b.minute!==minute){b={minute,count:0};buckets.set(key,b)}
  b.count++; if(b.count>RATE)return res.status(429).json({error:'rate limit exceeded'}); next();
}
setInterval(()=>{const cutoff=Math.floor(Date.now()/60000)-2;for(const [k,v] of buckets)if(v.minute<cutoff)buckets.delete(k)},120000).unref();

function getToken(req){const h=req.get('authorization');if(h?.startsWith('Bearer '))return h.slice(7);const m=(req.get('cookie')||'').match(/(?:^|; )antonio_session=([^;]+)/);return m?decodeURIComponent(m[1]):null}
async function auth(req,res,next){
  if(!authEnabled){req.user={id:'local',email:null,local:true};return next()}
  try{const u=await verifyAccessToken(getToken(req));if(!u)return res.status(401).json({error:'authentication required'});req.user={id:u.id,email:u.email||null,local:false};next()}catch{res.status(401).json({error:'authentication required'})}
}

const tools=[
 {type:'web_search'},
 {type:'function',name:'create_task',description:'Create a persistent task.',parameters:{type:'object',properties:{title:{type:'string'},goal:{type:'string'},priority:{type:'integer',minimum:1,maximum:10},due_at:{type:'string'}},required:['title','goal']}},
 {type:'function',name:'add_task_step',description:'Add a step to a task.',parameters:{type:'object',properties:{task_id:{type:'string'},action:{type:'string'}},required:['task_id','action']}},
 {type:'function',name:'update_task',description:'Update task status/result.',parameters:{type:'object',properties:{task_id:{type:'string'},status:{type:'string',enum:['planned','running','waiting_approval','completed','failed','cancelled']},result:{type:'string'}},required:['task_id']}},
 {type:'function',name:'list_tasks',description:'List tasks.',parameters:{type:'object',properties:{status:{type:'string'}},required:[]}},
 {type:'function',name:'save_memory',description:'Save durable memory.',parameters:{type:'object',properties:{kind:{type:'string'},content:{type:'string'},importance:{type:'integer',minimum:1,maximum:10}},required:['kind','content']}},
 {type:'function',name:'search_memory',description:'Search durable memory.',parameters:{type:'object',properties:{query:{type:'string'}},required:['query']}},
 {type:'function',name:'schedule_agent',description:'Schedule a future or recurring run.',parameters:{type:'object',properties:{prompt:{type:'string'},run_at:{type:'string'},repeat_minutes:{type:'integer',minimum:1}},required:['prompt','run_at']}},
 {type:'function',name:'request_approval',description:'Request approval before consequential external action.',parameters:{type:'object',properties:{task_id:{type:'string'},action:{type:'string'},payload:{type:'object'}},required:['action','payload']}},
 {type:'function',name:'send_email',description:'Send Gmail message; approval is required.',parameters:{type:'object',properties:{to:{type:'string'},subject:{type:'string'},text:{type:'string'}},required:['to','subject','text']}},
 {type:'function',name:'list_email',description:'List Gmail message IDs matching a search.',parameters:{type:'object',properties:{query:{type:'string'}},required:[]}},
 {type:'function',name:'create_calendar_event',description:'Create Google Calendar event; approval is required.',parameters:{type:'object',properties:{summary:{type:'string'},start:{type:'string'},end:{type:'string'},description:{type:'string'}},required:['summary','start','end']}},
 {type:'function',name:'send_telegram',description:'Send Telegram message; approval is required.',parameters:{type:'object',properties:{chat_id:{type:'string'},text:{type:'string'}},required:['chat_id','text']}},
 {type:'function',name:'send_whatsapp',description:'Send WhatsApp Cloud API message; approval is required.',parameters:{type:'object',properties:{to:{type:'string'},text:{type:'string'}},required:['to','text']}}
];

async function memory(userId){return db.prepare('SELECT kind,content,importance FROM memories WHERE user_id=? ORDER BY importance DESC,updated_at DESC LIMIT 60').all(userId)}
async function history(cid,userId){return db.prepare('SELECT role,content FROM messages WHERE conversation_id=? AND user_id=? ORDER BY created_at ASC LIMIT 160').all(cid,userId)}
async function logTool(userId,runId,taskId,name,args,out,status){await db.prepare('INSERT INTO tool_runs(id,user_id,task_id,run_id,tool,input,output,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)').run(id(),userId,taskId,runId,name,JSON.stringify(args),JSON.stringify(out),status,now())}

const approvalMap={send_email:'gmail.send',create_calendar_event:'calendar.create',send_telegram:'telegram.send',send_whatsapp:'whatsapp.send'};
async function requireApproval(userId,action,payload,taskId=null){
  const p=stableJson(payload);
  const existing=await db.prepare("SELECT id FROM approvals WHERE user_id=? AND action=? AND payload=? AND status='approved' AND executed_at IS NULL ORDER BY decided_at DESC LIMIT 1").get(userId,action,p);
  if(existing)return {approved_id:existing.id};
  const pending=await db.prepare("SELECT id FROM approvals WHERE user_id=? AND action=? AND payload=? AND status='pending' ORDER BY created_at DESC LIMIT 1").get(userId,action,p);
  if(pending)return {approval_required:true,approval_id:pending.id,status:'pending'};
  const x=id(); await db.prepare('INSERT INTO approvals(id,user_id,task_id,action,payload,status,created_at,decided_at,executed_at) VALUES(?,?,?,?,?,?,?,?,?)').run(x,userId,taskId,action,p,'pending',now(),null,null);
  return {approval_required:true,approval_id:x,status:'pending'};
}

async function tool(name,a,userId,runId,{skipApproval=false,taskId=null}={}){
  const t=now();
  if(name==='create_task'){const x=id();await db.prepare('INSERT INTO tasks(id,user_id,title,status,priority,goal,result,due_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,userId,a.title,'planned',a.priority??5,a.goal,'',a.due_at||null,t,t);return{task_id:x,status:'planned'}}
  if(name==='add_task_step'){if(!await db.prepare('SELECT id FROM tasks WHERE id=? AND user_id=?').get(a.task_id,userId))return{error:'task not found'};const r=await db.prepare('SELECT COALESCE(MAX(step_no),0)+1 AS n FROM task_steps WHERE task_id=?').get(a.task_id);const x=id();await db.prepare('INSERT INTO task_steps(id,task_id,step_no,action,status,output,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(x,a.task_id,r.n,a.action,'pending','',t,t);return{step_id:x,step_no:r.n,status:'pending'}}
  if(name==='update_task'){if(!await db.prepare('SELECT id FROM tasks WHERE id=? AND user_id=?').get(a.task_id,userId))return{error:'task not found'};await db.prepare("UPDATE tasks SET status=COALESCE(?,status),result=CASE WHEN ?<>'' THEN ? ELSE result END,updated_at=? WHERE id=? AND user_id=?").run(a.status||null,a.result||'',a.result||'',t,a.task_id,userId);return{updated:true}}
  if(name==='list_tasks')return a.status?db.prepare('SELECT * FROM tasks WHERE user_id=? AND status=? ORDER BY priority DESC,updated_at DESC').all(userId,a.status):db.prepare('SELECT * FROM tasks WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(userId);
  if(name==='save_memory'){const x=id();await db.prepare('INSERT INTO memories(id,user_id,kind,content,importance,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(x,userId,a.kind,a.content,a.importance??5,t,t);return{memory_id:x,saved:true}}
  if(name==='search_memory'){const q=String(a.query||'').toLowerCase();return (await memory(userId)).filter(r=>(r.kind+' '+r.content).toLowerCase().includes(q)).slice(0,25)}
  if(name==='schedule_agent'){const x=id();await db.prepare('INSERT INTO schedules(id,user_id,task_id,prompt,run_at,repeat_minutes,enabled,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,userId,taskId,a.prompt,a.run_at,a.repeat_minutes||null,1,null,t,t);return{schedule_id:x,enabled:true}}
  if(name==='request_approval')return requireApproval(userId,a.action,a.payload,a.task_id||taskId);
  if(approvalMap[name]&&!skipApproval){const gate=await requireApproval(userId,approvalMap[name],a,taskId);if(gate.approval_required)return gate}
  if(name==='send_email'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return gmailSend(JSON.parse(revealSecret(tok.token_json)),a,cfg||{})}
  if(name==='list_email'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return gmailList(JSON.parse(revealSecret(tok.token_json)),a.query||'',cfg||{})}
  if(name==='create_calendar_event'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return calendarCreate(JSON.parse(revealSecret(tok.token_json)),a,cfg||{})}
  if(name==='send_telegram'){const cfg=await integrationSecret(userId,'telegram_config');return telegramSend(a.chat_id,a.text,cfg||{})}
  if(name==='send_whatsapp'){const cfg=await integrationSecret(userId,'whatsapp_config');return whatsappSend(a.to,a.text,cfg||{})}
  throw new Error(`unknown tool: ${name}`);
}

async function runAgent({conversationId,input,userId,taskId=null}){
  const runId=id(),start=now(); await db.prepare('INSERT INTO agent_runs(id,user_id,conversation_id,task_id,status,input,output,error,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(runId,userId,conversationId,taskId,'running',input,'','',start,null);
  if(!openai){const e='OPENAI_API_KEY غير مضبوط.';await db.prepare("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?").run(e,now(),runId);return e}
  const system=`You are Antonio, an autonomous personal digital agent. Plan, execute, verify, and report. Never claim an external action succeeded unless the integration returned success. Consequential external actions require approval. Use web search for current public information. Persist durable facts in memory. Break complex work into tasks and steps. Arabic-first; Iraqi Arabic is welcome. Durable memory: ${JSON.stringify(await memory(userId))}`;
  let items=[{role:'system',content:system},...(await history(conversationId,userId)),{role:'user',content:input}];
  try{
    for(let round=0;round<10;round++){
      const response=await openai.responses.create({model:MODEL,input:items,tools:process.env.ENABLE_WEB_SEARCH==='false'?tools.filter(x=>x.type!=='web_search'):tools,store:false});
      let calls=0;
      for(const item of response.output||[]){if(item.type!=='function_call')continue;calls++;let args={};try{args=JSON.parse(item.arguments||'{}')}catch{args={}}let out,status='completed';try{out=await tool(item.name,args,userId,runId,{taskId})}catch(e){out={error:e.message};status='failed'}await logTool(userId,runId,taskId,item.name,args,out,status);items.push(item,{type:'function_call_output',call_id:item.call_id,output:JSON.stringify(out)})}
      if(!calls){const ans=response.output_text||'تم التنفيذ.';await db.prepare("UPDATE agent_runs SET status='completed',output=?,finished_at=? WHERE id=?").run(ans,now(),runId);return ans}
    }
    const ans='وصلت إلى حد دورات التنفيذ؛ حفظت الحالة ويمكن متابعة المهمة.';await db.prepare("UPDATE agent_runs SET status='completed',output=?,finished_at=? WHERE id=?").run(ans,now(),runId);return ans;
  }catch(e){await db.prepare("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?").run(e.message,now(),runId);await audit(userId,'agent_error',{runId,error:e.message});throw e}
}

app.post('/api/internal/worker-tick',async(req,res)=>{;  if(String(req.get('x-worker-secret')||'')!==String(process.env.WORKER_SECRET||''))return res.status(401).json({error:'unauthorized'});;  const summary={schedules:0,tasks:0,errors:0};;  try{;    const due=await db.prepare("SELECT * FROM schedules WHERE enabled=TRUE AND run_at IS NOT NULL AND run_at<=? ORDER BY run_at LIMIT 20").all(now());;    for(const s of due){try{;      const claimed=await db.prepare("UPDATE schedules SET last_run_at=?, run_at=CASE WHEN repeat_minutes IS NOT NULL THEN ? ELSE run_at END, enabled=CASE WHEN repeat_minutes IS NULL THEN FALSE ELSE enabled END, updated_at=? WHERE id=? AND enabled=TRUE AND run_at<=?").run(now(),s.repeat_minutes?new Date(Date.now()+Number(s.repeat_minutes)*60000).toISOString():s.run_at,now(),s.id,now());;      if(!claimed?.changes && claimed?.rowCount===0)continue;;      const c=id(),t=now(); await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,s.user_id,'Scheduled run',t,t);;      await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'user',s.prompt,t);;      const ans=await runAgent({conversationId:c,input:s.prompt,userId:s.user_id,taskId:s.task_id||null});;      await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'assistant',ans,now()); await audit(s.user_id,'schedule_executed',{scheduleId:s.id}); summary.schedules++;;    }catch(e){summary.errors++;await audit(s.user_id,'schedule_error',{scheduleId:s.id,error:e.message})}};    const taskDue=await db.prepare("SELECT * FROM tasks WHERE status IN ('planned','running') AND due_at IS NOT NULL AND due_at<=? ORDER BY priority DESC,updated_at LIMIT 10").all(now());;    for(const task of taskDue){try{;      const claimed=await db.prepare("UPDATE tasks SET status='running',updated_at=? WHERE id=? AND status IN ('planned','running')").run(now(),task.id); if(claimed?.changes===0&&claimed?.rowCount===0)continue;;      const c=id(),t=now(),prompt='Execute this task autonomously. Verify every step and report the result. Task: '+task.title+'\;Goal: '+task.goal;;      await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,task.user_id,'Autonomous task',t,t); await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'user',prompt,t);;      const ans=await runAgent({conversationId:c,input:prompt,userId:task.user_id,taskId:task.id}); await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'assistant',ans,now()); await db.prepare("UPDATE tasks SET status='completed',result=?,updated_at=? WHERE id=? AND status='running'").run(ans,now(),task.id); await audit(task.user_id,'task_executed',{taskId:task.id}); summary.tasks++;;    }catch(e){summary.errors++;await db.prepare("UPDATE tasks SET status='failed',result=?,updated_at=? WHERE id=?").run(e.message,now(),task.id);await audit(task.user_id,'task_error',{taskId:task.id,error:e.message})}};    res.json({ok:true,...summary});;  }catch(e){res.status(500).json({ok:false,error:e.message,...summary})};});;app.get('/api/health',(req,res)=>res.json({ok:true,version:'5.0.0',build:'55f2e767',model:MODEL,openai:Boolean(openai),auth:authEnabled,cloud_db:cloudDb,integrations:integrationState()}));
app.get('/api/ready',async(req,res)=>{try{await db.prepare('SELECT 1 AS ok').get();if(!openai)return res.status(503).json({ok:false,error:'OpenAI is not configured'});res.json({ok:true})}catch(e){res.status(503).json({ok:false,error:e.message})}});
app.use('/api',rate);
app.post('/api/auth/signup',async(req,res)=>{if(!supabase)return res.status(400).json({error:'Supabase Auth is not configured'});const email=String(req.body?.email||'').trim(),password=String(req.body?.password||'');if(!email||password.length<8)return res.status(400).json({error:'valid email and password (8+ chars) required'});const {data,error}=await supabase.auth.signUp({email,password});if(error)return res.status(400).json({error:error.message});if(data.session)setCookie(res,data.session.access_token);res.json({user:data.user,session:Boolean(data.session),access_token:data.session?.access_token||null})});
app.post('/api/auth/login',async(req,res)=>{if(!supabase)return res.status(400).json({error:'Supabase Auth is not configured'});const {data,error}=await supabase.auth.signInWithPassword({email:String(req.body?.email||'').trim(),password:String(req.body?.password||'')});if(error)return res.status(401).json({error:error.message});setCookie(res,data.session.access_token);res.json({user:data.user,access_token:data.session.access_token})});
app.get('/api/auth/me',async(req,res)=>{try{const u=await verifyAccessToken(getToken(req));if(!u)return res.status(401).json({error:'authentication required'});res.json({user:{id:u.id,email:u.email||null}})}catch{res.status(401).json({error:'authentication required'})}});
app.post('/api/auth/logout',async(req,res)=>{res.setHeader('Set-Cookie','antonio_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');res.json({ok:true})});
function setCookie(res,t){const secure=process.env.COOKIE_SECURE==='false'?'':' Secure;';const maxAge=Math.max(900,Number(process.env.SESSION_MAX_AGE_SECONDS||3600));res.setHeader('Set-Cookie',`antonio_session=${encodeURIComponent(t)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax;${secure}`)}

app.get('/api/integrations/google/start',auth,async(req,res)=>{const cfg=await integrationSecret(req.user.id,'google_oauth');const ready=(cfg?.client_id&&cfg?.client_secret)||(process.env.GOOGLE_CLIENT_ID&&process.env.GOOGLE_CLIENT_SECRET);if(!ready)return res.status(400).json({error:'Google OAuth credentials are not configured in Antonio'});const state=crypto.randomUUID();await db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(`oauth:${state}`,JSON.stringify({userId:req.user.id,expires:Date.now()+600000}));res.redirect(googleAuthUrl(state,cfg||{}))});
app.get('/api/integrations/google/callback',async(req,res)=>{try{const state=String(req.query.state||'');const row=await db.prepare('SELECT value FROM settings WHERE key=?').get(`oauth:${state}`);if(!row)return res.status(400).send('Invalid OAuth state');const meta=JSON.parse(row.value);if(meta.expires<Date.now())return res.status(400).send('OAuth state expired');await db.prepare('DELETE FROM settings WHERE key=?').run(`oauth:${state}`);const cfg=await integrationSecret(meta.userId,'google_oauth');const tokens=await googleExchange(String(req.query.code||''),cfg||{});await db.prepare('INSERT INTO integration_tokens(id,user_id,provider,access_token,refresh_token,token_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET access_token=excluded.access_token,refresh_token=integration_tokens.refresh_token,token_json=excluded.token_json,updated_at=excluded.updated_at').run(id(),meta.userId,'google','','',protectSecret(JSON.stringify(tokens)),now(),now());res.redirect('/?google=connected')}catch(e){res.status(400).send('Google OAuth failed')}});

app.use('/api',auth);
app.get('/api/integrations',(req,res)=>res.json(integrationState()));
app.get('/api/me',(req,res)=>res.json(req.user));
app.get('/api/tasks',async(req,res)=>res.json(await db.prepare('SELECT * FROM tasks WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(req.user.id)));
app.get('/api/tasks/:id/steps',async(req,res)=>res.json(await db.prepare('SELECT * FROM task_steps WHERE task_id=? AND EXISTS(SELECT 1 FROM tasks WHERE tasks.id=task_steps.task_id AND tasks.user_id=?)').all(req.params.id,req.user.id)));
app.get('/api/memories',async(req,res)=>res.json(await db.prepare('SELECT * FROM memories WHERE user_id=? ORDER BY importance DESC,updated_at DESC').all(req.user.id)));
app.get('/api/approvals',async(req,res)=>res.json(await db.prepare('SELECT * FROM approvals WHERE user_id=? ORDER BY created_at DESC').all(req.user.id)));
app.get('/api/schedules',async(req,res)=>res.json(await db.prepare('SELECT * FROM schedules WHERE user_id=? ORDER BY enabled DESC,run_at').all(req.user.id)));
app.get('/api/runs',async(req,res)=>res.json(await db.prepare('SELECT * FROM agent_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 100').all(req.user.id)));
app.get('/api/audit',async(req,res)=>res.json(await db.prepare('SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id)));
app.get('/api/stats',async(req,res)=>{const u=req.user.id;const [tasks,mem,pending,schedules,runs]=await Promise.all([db.prepare('SELECT COUNT(*) AS n FROM tasks WHERE user_id=?').get(u),db.prepare('SELECT COUNT(*) AS n FROM memories WHERE user_id=?').get(u),db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id=? AND status='pending'").get(u),db.prepare('SELECT COUNT(*) AS n FROM schedules WHERE user_id=? AND enabled=TRUE').get(u),db.prepare('SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=?').get(u)]);res.json({tasks:Number(tasks.n),memories:Number(mem.n),pending_approvals:Number(pending.n),schedules:Number(schedules.n),runs:Number(runs.n)})});

app.post('/api/approvals/:id/decide',async(req,res)=>{const a=await db.prepare('SELECT * FROM approvals WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!a)return res.status(404).json({error:'approval not found'});if(a.status!=='pending')return res.status(409).json({error:`approval already ${a.status}`});const approved=Boolean(req.body?.approved);if(!approved){await db.prepare("UPDATE approvals SET status='rejected',decided_at=? WHERE id=? AND user_id=?").run(now(),a.id,req.user.id);await audit(req.user.id,'approval_decided',{approvalId:a.id,status:'rejected'});return res.json({ok:true,status:'rejected'})}
  let actionName=Object.entries(approvalMap).find(([,v])=>v===a.action)?.[0]; if(!actionName)return res.status(400).json({error:'unsupported approval action'});
  let payload;try{payload=JSON.parse(a.payload)}catch{return res.status(400).json({error:'invalid approval payload'})}
  await db.prepare("UPDATE approvals SET status='approved',decided_at=? WHERE id=? AND user_id=?").run(now(),a.id,req.user.id);
  try{const out=await tool(actionName,payload,req.user.id,null,{skipApproval:true,taskId:a.task_id});await db.prepare('UPDATE approvals SET executed_at=? WHERE id=? AND user_id=?').run(now(),a.id,req.user.id);await audit(req.user.id,'approval_executed',{approvalId:a.id,action:a.action});return res.json({ok:true,status:'executed',result:out})}catch(e){await audit(req.user.id,'approval_execution_failed',{approvalId:a.id,error:e.message});return res.status(502).json({error:e.message,approval_id:a.id,status:'approved'})}
});
app.post('/api/schedules/:id/toggle',async(req,res)=>{const s=await db.prepare('SELECT enabled FROM schedules WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!s)return res.status(404).json({error:'schedule not found'});await db.prepare('UPDATE schedules SET enabled=?,updated_at=? WHERE id=? AND user_id=?').run(s.enabled?0:1,now(),req.params.id,req.user.id);res.json({ok:true,enabled:!Boolean(s.enabled)})});
app.post('/api/chat',async(req,res)=>{const text=String(req.body?.message||'').trim();if(!text)return res.status(400).json({error:'message required'});if(text.length>20000)return res.status(413).json({error:'message too long'});let cid=req.body?.conversation_id;if(!cid){cid=id();const t=now();await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(cid,req.user.id,'محادثة جديدة',t,t)}else if(!await db.prepare('SELECT id FROM conversations WHERE id=? AND user_id=?').get(cid,req.user.id))return res.status(404).json({error:'conversation not found'});await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),cid,req.user.id,'user',text,now());try{const ans=await runAgent({conversationId:cid,input:text,userId:req.user.id});await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),cid,req.user.id,'assistant',ans,now());await db.prepare('UPDATE conversations SET updated_at=? WHERE id=? AND user_id=?').run(now(),cid,req.user.id);res.json({conversation_id:cid,answer:ans})}catch(e){res.status(500).json({error:'agent execution failed'})}});
app.get('/api/conversations/:id/messages',async(req,res)=>res.json(await db.prepare('SELECT role,content,created_at FROM messages WHERE conversation_id=? AND user_id=? ORDER BY created_at').all(req.params.id,req.user.id)));

export { runAgent, app, auth };
await import('./v5.js').then(m=>m.registerV5({app,auth,db,now,id,protectSecret}));

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const port=Number(process.env.PORT||3000);
  const server=app.listen(port,()=>console.log(`Antonio Agent 5.0 running on ${port}`));
  server.requestTimeout=Number(process.env.REQUEST_TIMEOUT_MS||120000);
  server.headersTimeout=Number(process.env.HEADERS_TIMEOUT_MS||30000);
  server.keepAliveTimeout=5000;
  process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
  process.on('SIGINT',()=>server.close(()=>process.exit(0)));
}
