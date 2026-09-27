import 'dotenv/config';
import express from 'express';
import OpenAI from 'openai';
import crypto from 'node:crypto';
import webpush from 'web-push';
import { db, now, id, audit, cloudDb, stableJson } from './db.js';
import { authEnabled, supabase, verifyAccessToken } from './cloud.js';
import { integrationState, googleAuthUrl, googleExchange, gmailSend, gmailList, gmailRead, gmailThreadRead, calendarCreate, telegramSend, whatsappSend } from './integrations.js';
import { createPlan, verifyRun } from './agent-core.js';

const TOKEN_KEY = process.env.TOKEN_ENCRYPTION_KEY || '';
if(process.env.NODE_ENV==='production' && !TOKEN_KEY) throw new Error('TOKEN_ENCRYPTION_KEY is required in production');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));
app.use(express.json({ limit: '18mb' }));
app.use((req,res,next)=>{res.set({
  'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin',
  'Permissions-Policy':'camera=(),microphone=(self),geolocation=()','Cache-Control':'no-store, no-cache, must-revalidate, proxy-revalidate'
});next()});
app.use(express.static('public',{setHeaders:(res,filePath)=>{if(filePath.endsWith('.html'))res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate')}}));

const openai = process.env.OPENAI_API_KEY ? new OpenAI({apiKey:process.env.OPENAI_API_KEY}) : null;
const MODEL = process.env.OPENAI_MODEL || 'gpt-5.6-luna';
const VAPID_PUBLIC_KEY=String(process.env.VAPID_PUBLIC_KEY||'');
const VAPID_PRIVATE_KEY=String(process.env.VAPID_PRIVATE_KEY||'');
const VAPID_SUBJECT=String(process.env.VAPID_SUBJECT||'mailto:antonio@localhost');
if(VAPID_PUBLIC_KEY&&VAPID_PRIVATE_KEY)webpush.setVapidDetails(VAPID_SUBJECT,VAPID_PUBLIC_KEY,VAPID_PRIVATE_KEY);
async function pushToUser(userId,title,body,data={}){
  if(!VAPID_PUBLIC_KEY||!VAPID_PRIVATE_KEY)return;
  const rows=await db.prepare('SELECT id,endpoint,p256dh,auth FROM push_subscriptions WHERE user_id=?').all(userId);
  for(const row of rows){
    try{await webpush.sendNotification({endpoint:row.endpoint,keys:{p256dh:row.p256dh,auth:row.auth}},JSON.stringify({title,body,data}));}
    catch(e){if(e.statusCode===404||e.statusCode===410)await db.prepare('DELETE FROM push_subscriptions WHERE id=? AND user_id=?').run(row.id,userId);}
  }
}
async function notifyUser(userId,event,data={}){
  const title=event==='task_executed'?'اكتملت المهمة':event==='schedule_executed'?'اكتمل التذكير':event==='reminder_due'?'حان وقت التذكير':event==='message_reply'?'فلان رد عليك':event==='task_error'?'خطأ بالمهمة':event==='schedule_error'?'خطأ بالتذكير':'تحديث من Antonio';
  const body=data.result||data.error||'عندك تحديث جديد من Antonio.';
  await pushToUser(userId,title,String(body).slice(0,500),{event,...data});
}
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

const READ_RATE = Math.max(30, Number(process.env.RATE_LIMIT_READS_PER_MINUTE || 300));
const WRITE_RATE = Math.max(10, Number(process.env.RATE_LIMIT_WRITES_PER_MINUTE || 60));
const buckets = new Map();
function rate(req,res,next){
  const key=(req.ip||'unknown')+':'+req.method, minute=Math.floor(Date.now()/60000); let b=buckets.get(key);
  if(!b || b.minute!==minute){b={minute,count:0};buckets.set(key,b)}
  const limit=(req.method==='GET'||req.method==='HEAD')?READ_RATE:WRITE_RATE;
  b.count++;
  if(b.count>limit)return res.status(429).json({error:'rate limit exceeded',retry_after_seconds:Math.max(1,60-(Date.now()%60000)/1000)});
  next();
}
setInterval(()=>{const cutoff=Math.floor(Date.now()/60000)-2;for(const [k,v] of buckets)if(v.minute<cutoff)buckets.delete(k)},120000).unref();

function cookieValue(req,name){const item=(req.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));return item?decodeURIComponent(item.slice(name.length+1)):null}
function getToken(req){const h=req.get('authorization');if(h?.startsWith('Bearer '))return h.slice(7);return cookieValue(req,'antonio_session')}
function getRefreshToken(req){return cookieValue(req,'antonio_refresh')}
function setCookie(res,name,value,maxAge){const secure=process.env.COOKIE_SECURE==='false'?'':' Secure;';const cookie=value?name+'='+encodeURIComponent(value)+'; Max-Age='+maxAge+'; Path=/; HttpOnly; SameSite=Lax;'+secure:name+'=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax;'+secure;res.append('Set-Cookie',cookie)}
function setSessionCookies(res,session){if(!session)return;setCookie(res,'antonio_session',session.access_token,Math.max(900,Number(process.env.SESSION_MAX_AGE_SECONDS||3600)));if(session.refresh_token)setCookie(res,'antonio_refresh',session.refresh_token,Math.max(3600,Number(process.env.REFRESH_MAX_AGE_SECONDS||2592000)))}
async function refreshUser(req,res){if(!supabase)return null;const refresh=getRefreshToken(req);if(!refresh)return null;const {data,error}=await supabase.auth.refreshSession({refresh_token:refresh});if(error||!data?.user||!data?.session)return null;setSessionCookies(res,data.session);return data.user}
async function auth(req,res,next){
  if(!authEnabled){req.user={id:'local',email:null,local:true};return next()}
  try{let u=await verifyAccessToken(getToken(req));if(!u)u=await refreshUser(req,res);if(!u)return res.status(401).json({error:'authentication required'});req.user={id:u.id,email:u.email||null,local:false};next()}catch{res.status(401).json({error:'authentication required'})}
}

const tools=[
 {type:'web_search'},
 {type:'function',name:'create_task',description:'Create a persistent task.',parameters:{type:'object',properties:{title:{type:'string'},goal:{type:'string'},priority:{type:'integer',minimum:1,maximum:10},due_at:{type:'string'}},required:['title','goal']}},
 {type:'function',name:'add_task_step',description:'Add a step to a task.',parameters:{type:'object',properties:{task_id:{type:'string'},action:{type:'string'}},required:['task_id','action']}},
 {type:'function',name:'update_task',description:'Update task status/result. waiting_confirmation means a reminder was delivered and is waiting for the user to confirm they saw it.',parameters:{type:'object',properties:{task_id:{type:'string'},status:{type:'string',enum:['planned','running','waiting_approval','waiting_confirmation','completed','failed','cancelled']},result:{type:'string'}},required:['task_id']}},
 {type:'function',name:'list_tasks',description:'List tasks.',parameters:{type:'object',properties:{status:{type:'string'}},required:[]}},
 {type:'function',name:'save_memory',description:'Save durable memory.',parameters:{type:'object',properties:{kind:{type:'string'},content:{type:'string'},importance:{type:'integer',minimum:1,maximum:10}},required:['kind','content']}},
 {type:'function',name:'search_memory',description:'Search durable memory.',parameters:{type:'object',properties:{query:{type:'string'}},required:['query']}},
 {type:'function',name:'schedule_agent',description:'Schedule a future or recurring run.',parameters:{type:'object',properties:{prompt:{type:'string'},run_at:{type:'string'},repeat_minutes:{type:'integer',minimum:1}},required:['prompt','run_at']}},
 {type:'function',name:'create_project',description:'Create a project for organizing long-running work.',parameters:{type:'object',properties:{name:{type:'string'},description:{type:'string'}},required:['name']}},
 {type:'function',name:'list_projects',description:'List the user projects.',parameters:{type:'object',properties:{status:{type:'string'}},required:[]}},
 {type:'function',name:'create_goal',description:'Create a goal, optionally attached to a project.',parameters:{type:'object',properties:{project_id:{type:'string'},title:{type:'string'},description:{type:'string'},priority:{type:'integer',minimum:1,maximum:10},target_at:{type:'string'}},required:['title']}},
 {type:'function',name:'list_goals',description:'List goals, optionally by project or status.',parameters:{type:'object',properties:{project_id:{type:'string'},status:{type:'string'}},required:[]}},
 {type:'function',name:'get_agent_health',description:'Inspect Antonio health: recent failed runs, pending approvals, due tasks, active schedules.',parameters:{type:'object',properties:{},required:[]}},
 {type:'function',name:'request_approval',description:'Request approval before consequential external action.',parameters:{type:'object',properties:{task_id:{type:'string'},action:{type:'string'},payload:{type:'object'}},required:['action','payload']}},
 {type:'function',name:'send_email',description:'Send Gmail message; approval is required.',parameters:{type:'object',properties:{to:{type:'string'},subject:{type:'string'},text:{type:'string'}},required:['to','subject','text']}},
 {type:'function',name:'list_email',description:'List Gmail message IDs matching a search. Use read_email to read the actual message contents.',parameters:{type:'object',properties:{query:{type:'string'}},required:[]}},
 {type:'function',name:'read_email',description:'Read the full text and metadata of a Gmail message by message ID.',parameters:{type:'object',properties:{message_id:{type:'string'}},required:['message_id']}},
 {type:'function',name:'create_calendar_event',description:'Create Google Calendar event; approval is required.',parameters:{type:'object',properties:{summary:{type:'string'},start:{type:'string'},end:{type:'string'},description:{type:'string'}},required:['summary','start','end']}},
 {type:'function',name:'send_telegram',description:'Send Telegram message; approval is required.',parameters:{type:'object',properties:{chat_id:{type:'string'},text:{type:'string'}},required:['chat_id','text']}},
 {type:'function',name:'send_whatsapp',description:'Send WhatsApp Cloud API message; approval is required.',parameters:{type:'object',properties:{to:{type:'string'},text:{type:'string'}},required:['to','text']}}
];

async function memory(userId){return db.prepare('SELECT kind,content,importance FROM memories WHERE user_id=? ORDER BY importance DESC,updated_at DESC LIMIT 60').all(userId)}
async function history(cid,userId){
  const rows=await db.prepare('SELECT role,content FROM messages WHERE conversation_id=? AND user_id=? ORDER BY created_at ASC LIMIT 160').all(cid,userId);
  return rows.map(r=>{try{const x=JSON.parse(r.content);if(x&&x.__antonio_message)return {role:r.role,content:x.content||x.text||''}}catch{}return r});
}
async function logTool(userId,runId,taskId,name,args,out,status){await db.prepare('INSERT INTO tool_runs(id,user_id,task_id,run_id,tool,input,output,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)').run(id(),userId,taskId,runId,name,JSON.stringify(args),JSON.stringify(out),status,now())}

const approvalMap={send_email:'gmail.send',create_calendar_event:'calendar.create',send_telegram:'telegram.send',send_whatsapp:'whatsapp.send'};
async function requireApproval(userId,action,payload,taskId=null){
  const setting=await db.prepare("SELECT value FROM settings WHERE key=?").get(`user:${userId}:setting:require_approval_external`);
  let requireApprovalExternal=false;
  if(setting?.value!==undefined){try{requireApprovalExternal=Boolean(JSON.parse(setting.value))}catch{requireApprovalExternal=String(setting.value).toLowerCase()==='true'}}
  if(!requireApprovalExternal)return {approval_required:false,auto_approved:true,status:'auto'};
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
  if(name==='create_task'){const due=a.due_at||null;const existing=await db.prepare("SELECT id,status FROM tasks WHERE user_id=? AND title=? AND COALESCE(goal,'')=? AND due_at IS NOT DISTINCT FROM ? AND status NOT IN ('cancelled','failed') ORDER BY created_at DESC LIMIT 1").get(userId,a.title||'',a.goal||'',due);if(existing)return{task_id:existing.id,status:existing.status,duplicate:true};const x=id();await db.prepare('INSERT INTO tasks(id,user_id,title,status,priority,goal,result,due_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,userId,a.title,'planned',a.priority??5,a.goal,'',due,t,t);return{task_id:x,status:'planned',duplicate:false}}
  if(name==='add_task_step'){if(!await db.prepare('SELECT id FROM tasks WHERE id=? AND user_id=?').get(a.task_id,userId))return{error:'task not found'};const r=await db.prepare('SELECT COALESCE(MAX(step_no),0)+1 AS n FROM task_steps WHERE task_id=?').get(a.task_id);const x=id();await db.prepare('INSERT INTO task_steps(id,task_id,step_no,action,status,output,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(x,a.task_id,r.n,a.action,'pending','',t,t);return{step_id:x,step_no:r.n,status:'pending'}}
  if(name==='update_task'){if(!await db.prepare('SELECT id FROM tasks WHERE id=? AND user_id=?').get(a.task_id,userId))return{error:'task not found'};await db.prepare("UPDATE tasks SET status=COALESCE(?,status),result=CASE WHEN ?<>'' THEN ? ELSE result END,updated_at=? WHERE id=? AND user_id=?").run(a.status||null,a.result||'',a.result||'',t,a.task_id,userId);return{updated:true}}
  if(name==='list_tasks')return a.status?db.prepare('SELECT * FROM tasks WHERE user_id=? AND status=? ORDER BY priority DESC,updated_at DESC').all(userId,a.status):db.prepare('SELECT * FROM tasks WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(userId);
  if(name==='save_memory'){const x=id();await db.prepare('INSERT INTO memories(id,user_id,kind,content,importance,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(x,userId,a.kind,a.content,a.importance??5,t,t);return{memory_id:x,saved:true}}
  if(name==='search_memory'){const q=String(a.query||'').toLowerCase();return (await memory(userId)).filter(r=>(r.kind+' '+r.content).toLowerCase().includes(q)).slice(0,25)}
  if(name==='schedule_agent'){const prompt=String(a.prompt||'').trim();const oneShot=/(مرة\\s*(واحدة|وحدة|فقط)|مرة\\s*وحدة|مرة\\s*فقط|مرة\\s*واحد|one[- ]?time|once)/i.test(prompt);const explicitlyRecurring=/(كل\\s*(دقيقة|دقائق|ساعة|ساعات|يوم|أيام|أسبوع|أسابيع)|every\\s+|recurr|repeats?)/i.test(prompt);const repeat=(!oneShot&&explicitlyRecurring&&Number.isFinite(Number(a.repeat_minutes))&&Number(a.repeat_minutes)>0)?Number(a.repeat_minutes):null;const existing=await db.prepare('SELECT id,enabled,task_id FROM schedules WHERE user_id=? AND prompt=? AND run_at=? AND repeat_minutes IS NOT DISTINCT FROM ? AND enabled=TRUE ORDER BY created_at DESC LIMIT 1').get(userId,prompt,a.run_at,repeat);if(existing)return{schedule_id:existing.id,task_id:existing.task_id||null,enabled:true,duplicate:true,repeat_minutes:repeat};let linkedTask=taskId||null;if(!linkedTask){const tx=id();await db.prepare('INSERT INTO tasks(id,user_id,title,status,priority,goal,result,due_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(tx,userId,prompt,'planned',5,'Reminder: '+prompt,'',a.run_at,t,t);linkedTask=tx}const x=id();await db.prepare('INSERT INTO schedules(id,user_id,task_id,prompt,run_at,repeat_minutes,enabled,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,userId,linkedTask,prompt,a.run_at,repeat,1,null,t,t);return{schedule_id:x,task_id:linkedTask,enabled:true,duplicate:false,repeat_minutes:repeat}}
  if(name==='create_project'){const name=String(a.name||'').trim();if(!name)return{error:'project name required'};const existing=await db.prepare("SELECT id,status FROM projects WHERE user_id=? AND name=? AND status<>'archived' ORDER BY created_at DESC LIMIT 1").get(userId,name);if(existing)return{project_id:existing.id,status:existing.status,duplicate:true};const x=id();const t=now();await db.prepare('INSERT INTO projects(id,user_id,name,description,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(x,userId,name,String(a.description||''),'active',t,t);return{project_id:x,status:'active',duplicate:false}}
  if(name==='list_projects')return a.status?db.prepare('SELECT * FROM projects WHERE user_id=? AND status=? ORDER BY updated_at DESC').all(userId,a.status):db.prepare('SELECT * FROM projects WHERE user_id=? ORDER BY updated_at DESC').all(userId);
  if(name==='create_goal'){const title=String(a.title||'').trim();if(!title)return{error:'goal title required'};if(a.project_id&&!await db.prepare('SELECT id FROM projects WHERE id=? AND user_id=?').get(a.project_id,userId))return{error:'project not found'};const x=id();const t=now();await db.prepare('INSERT INTO goals(id,user_id,project_id,title,description,status,priority,target_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,userId,a.project_id||null,title,String(a.description||''),'active',a.priority??5,a.target_at||null,t,t);return{goal_id:x,status:'active'}}
  if(name==='list_goals'){if(a.project_id)return db.prepare('SELECT * FROM goals WHERE user_id=? AND project_id=? ORDER BY priority DESC,updated_at DESC').all(userId,a.project_id);if(a.status)return db.prepare('SELECT * FROM goals WHERE user_id=? AND status=? ORDER BY priority DESC,updated_at DESC').all(userId,a.status);return db.prepare('SELECT * FROM goals WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(userId);}
  if(name==='get_agent_health'){const failed=await db.prepare("SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=? AND status IN ('failed','needs_review') AND started_at>NOW()-INTERVAL '24 hours'").get(userId);const pending=await db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id=? AND status='pending'").get(userId);const due=await db.prepare("SELECT COUNT(*) AS n FROM tasks WHERE user_id=? AND status='planned' AND due_at IS NOT NULL AND due_at<=?").get(userId,now());const active=await db.prepare("SELECT COUNT(*) AS n FROM schedules WHERE user_id=? AND enabled=TRUE").get(userId);return{healthy:Number(failed.n)===0,failed_runs_24h:Number(failed.n),pending_approvals:Number(pending.n),due_tasks:Number(due.n),active_schedules:Number(active.n)}}
  if(name==='request_approval'){const gate=await requireApproval(userId,a.action,a.payload,a.task_id||taskId);return gate.approval_required?gate:{approval_required:false,auto_approved:true,status:'auto'};}
  if(approvalMap[name]&&!skipApproval){const gate=await requireApproval(userId,approvalMap[name],a,taskId);if(gate.approval_required)return gate}
  if(name==='send_email'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');const out=await gmailSend(JSON.parse(revealSecret(tok.token_json)),a,cfg||{});const t=now();await db.prepare('INSERT INTO correspondence(id,user_id,provider,direction,contact,subject,body,external_message_id,external_thread_id,status,last_inbound_message_id,last_checked_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id(),userId,'gmail','outbound',a.to,a.subject,a.text,out.id||null,out.threadId||null,'awaiting_reply',null,t,t,t);return out}
  if(name==='list_email'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return gmailList(JSON.parse(revealSecret(tok.token_json)),a.query||'',cfg||{})}
  if(name==='read_email'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return gmailRead(JSON.parse(revealSecret(tok.token_json)),a.message_id,cfg||{})}
  if(name==='create_calendar_event'){const tok=await db.prepare('SELECT token_json FROM integration_tokens WHERE user_id=? AND provider=?').get(userId,'google');if(!tok)return{error:'Google account not connected'};const cfg=await integrationSecret(userId,'google_oauth');return calendarCreate(JSON.parse(revealSecret(tok.token_json)),a,cfg||{})}
  if(name==='send_telegram'){const cfg=await integrationSecret(userId,'telegram_config');return telegramSend(a.chat_id,a.text,cfg||{})}
  if(name==='send_whatsapp'){const cfg=await integrationSecret(userId,'whatsapp_config');return whatsappSend(a.to,a.text,cfg||{})}
  throw new Error(`unknown tool: ${name}`);
}

async function runAgent({conversationId,input,userId,taskId=null,inputContent=null}){
  const runId=id(),start=now(); await db.prepare('INSERT INTO agent_runs(id,user_id,conversation_id,task_id,status,input,output,error,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(runId,userId,conversationId,taskId,'running',input,'','',start,null);
  if(!openai){const e='OPENAI_API_KEY غير مضبوط.';await db.prepare("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?").run(e,now(),runId);return e}
  const recentHistory=await history(conversationId,userId);
  const plan=await createPlan({openai,model:MODEL,input,memory:await memory(userId),history:recentHistory});
  const planId=id();
  await db.prepare('INSERT INTO agent_plans(id,run_id,user_id,goal,plan_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(planId,runId,userId,String(plan.goal||input),JSON.stringify(plan),'active',start,start);
  for(let i=0;i<(plan.steps||[]).length;i++){const s=plan.steps[i];await db.prepare('INSERT INTO agent_steps(id,plan_id,step_no,step_key,action,tool_hint,verification,status,output) VALUES(?,?,?,?,?,?,?,?,?)').run(id(),planId,i+1,String(s.id||('step-'+(i+1))),String(s.action||''),s.tool_hint?String(s.tool_hint):null,s.verification?String(s.verification):null,'pending','')}
  const system=`You are Antonio, an autonomous personal digital agent. Plan, execute, verify, and report. Never claim an external action succeeded unless the integration returned success. Consequential external actions require approval. Use web search for current public information. Persist durable facts in memory. Break complex work into tasks and steps. Always reply in authentic natural Iraqi Arabic (Baghdadi/عراقي) by default. Speak like a young Iraqi from Baghdad: use natural Iraqi words such as شنو، شلون، هسه، أكو، ماكو، أريد، راح، وياك when appropriate. Avoid Modern Standard Arabic and avoid Gulf/Levantine phrasing unless the user explicitly asks for another dialect or language. Keep normal conversational replies short and direct; answer immediately without unnecessary introductions or repetition. Durable memory: ${JSON.stringify(await memory(userId))}`;
  let items=[{role:'system',content:system+'\nExecution plan: '+JSON.stringify(plan)},...recentHistory];if(inputContent&&items.length>1&&items[items.length-1].role==='user')items[items.length-1]={role:'user',content:inputContent};
  try{
    const toolResults=[];
    for(let round=0;round<10;round++){
      const response=await openai.responses.create({model:MODEL,input:items,tools:process.env.ENABLE_WEB_SEARCH==='false'?tools.filter(x=>x.type!=='web_search'):tools,store:false});
      let calls=0;
      for(const item of response.output||[]){if(item.type!=='function_call')continue;calls++;let args={};try{args=JSON.parse(item.arguments||'{}')}catch{args={}}let out,status='completed';try{out=await tool(item.name,args,userId,runId,{taskId})}catch(e){out={error:e.message};status='failed'}await logTool(userId,runId,taskId,item.name,args,out,status);toolResults.push({tool:item.name,args,out,status});items.push(item,{type:'function_call_output',call_id:item.call_id,output:JSON.stringify(out)})}
      if(!calls){let ans=response.output_text||'تم التنفيذ.';const verification=await verifyRun({openai,model:MODEL,input,plan,toolResults,answer:ans});await db.prepare("UPDATE agent_plans SET status=?,updated_at=? WHERE id=?").run(verification.verified?'verified':'needs_review',now(),planId);if(!verification.verified){ans+='\n\nملاحظة تحقق: ما كدرت أتحقق بالكامل من النتيجة. '+(verification.issues||[]).slice(0,2).join(' | ')}await db.prepare("UPDATE agent_runs SET status=?,output=?,finished_at=? WHERE id=?").run(verification.verified?'completed':'needs_review',ans,now(),runId);return ans}
    }
    const ans='وصلت إلى حد دورات التنفيذ؛ حفظت الحالة ويمكن متابعة المهمة.';await db.prepare("UPDATE agent_runs SET status='completed',output=?,finished_at=? WHERE id=?").run(ans,now(),runId);return ans;
  }catch(e){await db.prepare("UPDATE agent_runs SET status='failed',error=?,finished_at=? WHERE id=?").run(e.message,now(),runId);await audit(userId,'agent_error',{runId,error:e.message});throw e}
}

async function syncGmailRepliesForUser(userId){
  const rows=await db.prepare("SELECT * FROM correspondence WHERE user_id=? AND provider='gmail' AND direction='outbound' AND external_thread_id IS NOT NULL AND status IN ('awaiting_reply','replied') ORDER BY updated_at DESC LIMIT 30").all(userId);
  if(!rows.length)return 0;
  const tok=await db.prepare("SELECT token_json FROM integration_tokens WHERE user_id=? AND provider='google'").get(userId);
  if(!tok)return 0;
  const cfg=await integrationSecret(userId,'google_oauth');
  let found=0;
  const tokens=JSON.parse(revealSecret(tok.token_json));
  for(const row of rows){
    let stage='start';
    try{
      stage='read_thread';
      const fullMessages=await gmailThreadRead(tokens,row.external_thread_id,cfg||{});
      stage='read_outbound';
      const outboundDate=Number((await gmailRead(tokens,row.external_message_id,cfg||{}))?.internalDate||0);
      const inbound=fullMessages.filter(m=>{
        const labels=Array.isArray(m.labelIds)?m.labelIds:[];
        const ts=Number(m.internalDate||0);
        return m.id!==row.external_message_id && labels.includes('INBOX') && ts>=outboundDate;
      });
      if(!inbound.length){await db.prepare('UPDATE correspondence SET last_checked_at=?,updated_at=? WHERE id=? AND user_id=?').run(now(),now(),row.id,userId);continue;}
      stage='persist_reply';
      const latest=inbound.sort((a,b)=>Number(a.internalDate||0)-Number(b.internalDate||0)).at(-1);
      if(!latest||latest.id===row.last_inbound_message_id)continue;
      await db.prepare("UPDATE correspondence SET status='replied',last_inbound_message_id=?,reply_from=?,reply_subject=?,reply_body=?,reply_received_at=?,last_checked_at=?,updated_at=? WHERE id=? AND user_id=?").run(latest.id,latest.from||row.contact,latest.subject||row.subject,String(latest.body||latest.snippet||''),latest.date||now(),now(),now(),row.id,userId);
      await audit(userId,'message_reply',{correspondenceId:row.id,provider:'gmail',contact:latest.from||row.contact,subject:latest.subject||row.subject,result:String(latest.body||latest.snippet||'').slice(0,700)});
      await notifyUser(userId,'message_reply',{correspondenceId:row.id,contact:latest.from||row.contact,subject:latest.subject||row.subject,result:String(latest.body||latest.snippet||'').slice(0,700)});
      found++;
    }catch(e){await audit(userId,'message_sync_error',{correspondenceId:row.id,stage,error:e.message,stack:String(e.stack||'').slice(0,1200)})}
  }
  return found;
}

app.post('/api/internal/worker-tick',async(req,res)=>{;  if(String(req.get('x-worker-secret')||'')!==String(process.env.WORKER_SECRET||''))return res.status(401).json({error:'unauthorized'});;  const summary={schedules:0,tasks:0,replies:0,errors:0};;  try{;    const users=await db.prepare("SELECT DISTINCT user_id FROM correspondence WHERE provider='gmail' AND direction='outbound' AND status IN ('awaiting_reply','replied')").all(); for(const u of users){try{summary.replies+=await syncGmailRepliesForUser(u.user_id)}catch(e){summary.errors++;await audit(u.user_id,'message_sync_error',{error:e.message})}}; const due=await db.prepare("SELECT * FROM schedules WHERE enabled=TRUE AND run_at IS NOT NULL AND run_at<=? ORDER BY run_at LIMIT 20").all(now());;    for(const s of due){try{;      const claimed=await db.prepare("UPDATE schedules SET last_run_at=?, run_at=CASE WHEN repeat_minutes IS NOT NULL THEN ? ELSE run_at END, enabled=CASE WHEN repeat_minutes IS NULL THEN FALSE ELSE enabled END, updated_at=? WHERE id=? AND enabled=TRUE AND run_at<=?").run(now(),s.repeat_minutes?new Date(Date.now()+Number(s.repeat_minutes)*60000).toISOString():s.run_at,now(),s.id,now());;      if(!claimed?.changes && claimed?.rowCount===0)continue;;      const c=id(),t=now(); await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,s.user_id,'Scheduled run',t,t);;      await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'user',s.prompt,t);;      const ans=await runAgent({conversationId:c,input:s.prompt,userId:s.user_id,taskId:s.task_id||null});;      await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'assistant',ans,now()); if(s.task_id){await db.prepare("UPDATE tasks SET status='waiting_confirmation',result=?,updated_at=? WHERE id=? AND user_id=? AND status NOT IN ('cancelled','failed')").run(ans,now(),s.task_id,s.user_id)} await audit(s.user_id,'reminder_due',{scheduleId:s.id,taskId:s.task_id||null,result:String(ans||'').slice(0,700)}); await notifyUser(s.user_id,'reminder_due',{scheduleId:s.id,taskId:s.task_id||null,result:String(ans||'').slice(0,700)}); summary.schedules++;;    }catch(e){summary.errors++;await audit(s.user_id,'schedule_error',{scheduleId:s.id,error:e.message});await notifyUser(s.user_id,'schedule_error',{scheduleId:s.id,error:e.message})}};    const taskDue=await db.prepare("SELECT * FROM tasks WHERE status='planned' AND due_at IS NOT NULL AND due_at<=? AND (next_retry_at IS NULL OR next_retry_at<=?) ORDER BY priority DESC,updated_at LIMIT 10").all(now(),now());;    for(const task of taskDue){try{;      const claimed=await db.prepare("UPDATE tasks SET status='running',updated_at=? WHERE id=? AND status='planned'").run(now(),task.id); if(claimed?.changes===0&&claimed?.rowCount===0)continue;;      const c=id(),t=now(),prompt='Execute this task autonomously. Verify every step and report the result. Task: '+task.title+'\;Goal: '+task.goal;;      await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,task.user_id,'Autonomous task',t,t); await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'user',prompt,t);;      const ans=await runAgent({conversationId:c,input:prompt,userId:task.user_id,taskId:task.id}); await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'assistant',ans,now()); await db.prepare("UPDATE tasks SET status='completed',result=?,updated_at=? WHERE id=? AND status='running'").run(ans,now(),task.id); await audit(task.user_id,'task_executed',{taskId:task.id,result:String(ans||'').slice(0,700)}); await notifyUser(task.user_id,'task_executed',{taskId:task.id,result:String(ans||'').slice(0,700)}); summary.tasks++;;    }catch(e){summary.errors++;const retries=Number(task.retry_count||0);const maxRetries=Number(task.max_retries??2);if(retries<maxRetries){const next=new Date(Date.now()+Math.min(60,2**retries)*60000).toISOString();await db.prepare("UPDATE tasks SET status='planned',retry_count=?,next_retry_at=?,result=?,updated_at=? WHERE id=?").run(retries+1,next,'Retry '+(retries+1)+'/'+maxRetries+': '+e.message,now(),task.id)}else{await db.prepare("UPDATE tasks SET status='failed',result=?,updated_at=? WHERE id=?").run(e.message,now(),task.id)}await audit(task.user_id,'task_error',{taskId:task.id,error:e.message,retry_count:retries+1});await notifyUser(task.user_id,'task_error',{taskId:task.id,error:e.message,retry_count:retries+1})}};    res.json({ok:true,...summary});;  }catch(e){res.status(500).json({ok:false,error:e.message,...summary})};});;app.get('/api/health',(req,res)=>res.json({ok:true,version:'6.0.0',build:'6.0.0',model:MODEL,openai:Boolean(openai),auth:authEnabled,cloud_db:cloudDb,integrations:integrationState()}));
app.post('/api/speak',auth,async(req,res)=>{try{const text=String(req.body?.text||'').trim();if(!text)return res.status(400).json({error:'text required'});if(text.length>8000)return res.status(413).json({error:'text too long'});if(!openai)return res.status(503).json({error:'OpenAI is not configured'});const speech=await openai.audio.speech.create({model:process.env.OPENAI_TTS_MODEL||'gpt-4o-mini-tts',voice:process.env.OPENAI_TTS_VOICE||'cedar',input:text,instructions:'Speak in authentic Baghdad Iraqi Arabic (عراقي بغدادي), like a young Iraqi male personal assistant named Antonio. Use natural Iraqi pronunciation, rhythm, and conversational phrasing. Do not use Modern Standard Arabic, Gulf Arabic, or Levantine Arabic. Be warm, clear, energetic, and slightly fast. Do not translate or change the meaning.',speed:Number(process.env.OPENAI_TTS_SPEED||1.15)});const buf=Buffer.from(await speech.arrayBuffer());res.set('Content-Type','audio/mpeg');res.set('Cache-Control','no-store');res.send(buf)}catch(e){console.error('TTS error',e.message);res.status(502).json({error:'voice generation failed'})}});
app.post('/api/realtime/session',auth,express.raw({type:['application/sdp','text/plain'],limit:'2mb'}),async(req,res)=>{
  try{
    if(!openai)return res.status(503).json({error:'OpenAI is not configured'});
    const sdp=Buffer.isBuffer(req.body)?req.body.toString('utf8').trim():String(req.body||'').trim();
    if(!sdp)return res.status(400).json({error:'SDP offer required'});
    const sessionConfig=JSON.stringify({
      type:'realtime',
      model:process.env.OPENAI_REALTIME_MODEL||'gpt-realtime-2.1',
      output_modalities:['audio'],
      audio:{
        input:{turn_detection:{type:'semantic_vad'}},
        output:{voice:process.env.OPENAI_REALTIME_VOICE||'cedar'}
      },
      instructions:'أنت Antonio، الوكيل الرقمي الشخصي للمستخدم. احچي باللهجة العراقية البغدادية بشكل طبيعي، مختصر وواضح. لا تستخدم JSON ولا Markdown ولا رموز تنسيق ولا إيموجي في كلامك. إذا الطلب يحتاج تنفيذ مهمة أو استخدام خدمة أو معلومات خاصة بالمستخدم، استخدم أداة antonio_agent حتى ينفذها الوكيل الأساسي ويرجع لك النتيجة. لا تدّعي تنفيذ أي إجراء خارجي بدون نتيجة مؤكدة.',
      tools:[{
        type:'function',
        name:'antonio_agent',
        description:'مرر طلب المستخدم إلى وكيل Antonio الأساسي لتنفيذ المهام، استخدام الأدوات، الوصول للمراسلات والذاكرة والمهام، أو أي إجراء يحتاج صلاحيات الوكيل. استخدمها للطلبات العملية بدل أن تجيب من عندك.',
        parameters:{type:'object',properties:{message:{type:'string',description:'طلب المستخدم كما فهمته، بصياغة واضحة باللهجة العراقية أو اللغة التي استخدمها المستخدم.'}},required:['message']}
      }],
      tool_choice:'auto'
    });
    const fd=new FormData();
    fd.set('sdp',sdp);
    fd.set('session',sessionConfig);
    const safety=crypto.createHash('sha256').update(String(req.user.id)).digest('hex');
    const upstream=await fetch('https://api.openai.com/v1/realtime/calls',{method:'POST',headers:{Authorization:'Bearer '+process.env.OPENAI_API_KEY,'OpenAI-Safety-Identifier':safety},body:fd});
    const body=await upstream.text();
    if(!upstream.ok){console.error('Realtime session error',upstream.status,body.slice(0,1000));return res.status(upstream.status).type('text/plain').send(body)}
    res.type('text/plain').send(body);
  }catch(e){console.error('Realtime session exception',e.message);res.status(502).json({error:'تعذر تشغيل المحادثة الصوتية المباشرة'})}
});
// WhatsApp Cloud API webhook: Meta verification + incoming events\napp.get('/webhook',(req,res)=>{\n  const mode=String(req.query['hub.mode']||'');\n  const token=String(req.query['hub.verify_token']||'');\n  const challenge=String(req.query['hub.challenge']||'');\n  const expected=String(process.env.WEBHOOK_VERIFY_TOKEN||'');\n  if(mode==='subscribe' && expected && token===expected && challenge){\n    return res.status(200).type('text/plain').send(challenge);\n  }\n  return res.sendStatus(403);\n});\napp.post('/webhook',(req,res)=>{\n  console.log('WhatsApp webhook event received');\n  return res.sendStatus(200);\n});\napp.get('/healthz',(req,res)=>res.status(200).json({ok:true}));
app.get('/api/ready',(req,res)=>res.status(200).json({ok:true}));
app.use('/api',rate);
app.post('/api/auth/signup',async(req,res)=>{if(!supabase)return res.status(400).json({error:'Supabase Auth is not configured'});const email=String(req.body?.email||'').trim(),password=String(req.body?.password||'');if(!email||password.length<8)return res.status(400).json({error:'valid email and password (8+ chars) required'});const {data,error}=await supabase.auth.signUp({email,password});if(error)return res.status(400).json({error:error.message});if(data.session)setSessionCookies(res,data.session);res.json({user:data.user,session:Boolean(data.session),access_token:data.session?.access_token||null})});
app.post('/api/auth/login',async(req,res)=>{if(!supabase)return res.status(400).json({error:'Supabase Auth is not configured'});const email=String(req.body?.email||'').trim(),password=String(req.body?.password||'');if(!email||!password)return res.status(400).json({error:'email and password are required'});try{const {data,error}=await supabase.auth.signInWithPassword({email,password});if(error)return res.status(401).json({error:error.message});if(!data?.session?.access_token||!data?.user)return res.status(502).json({error:'Supabase returned an incomplete session'});setSessionCookies(res,data.session);res.json({user:data.user,access_token:data.session.access_token})}catch(e){console.error('auth login error:',e.message);res.status(500).json({error:e.message||'authentication failed'})}});
app.post('/api/auth/refresh',async(req,res)=>{const u=await refreshUser(req,res);if(!u)return res.status(401).json({error:'session expired'});res.json({user:{id:u.id,email:u.email||null}})});
app.get('/api/auth/me',async(req,res)=>{try{let u=await verifyAccessToken(getToken(req));if(!u)u=await refreshUser(req,res);if(!u)return res.status(401).json({error:'authentication required'});res.json({user:{id:u.id,email:u.email||null}})}catch{res.status(401).json({error:'authentication required'})}});
app.post('/api/auth/logout',async(req,res)=>{setCookie(res,'antonio_session','',0);setCookie(res,'antonio_refresh','',0);res.json({ok:true})});

app.get('/api/integrations/google/start',auth,async(req,res)=>{const cfg=await integrationSecret(req.user.id,'google_oauth');const ready=(cfg?.client_id&&cfg?.client_secret)||(process.env.GOOGLE_CLIENT_ID&&process.env.GOOGLE_CLIENT_SECRET);if(!ready)return res.status(400).json({error:'Google OAuth credentials are not configured in Antonio'});const state=crypto.randomUUID();await db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(`oauth:${state}`,JSON.stringify({userId:req.user.id,expires:Date.now()+600000}));res.redirect(googleAuthUrl(state,cfg||{}))});
app.get('/api/integrations/google/callback',async(req,res)=>{try{const state=String(req.query.state||'');const row=await db.prepare('SELECT value FROM settings WHERE key=?').get(`oauth:${state}`);if(!row)return res.status(400).send('Invalid OAuth state');const meta=JSON.parse(row.value);if(meta.expires<Date.now())return res.status(400).send('OAuth state expired');await db.prepare('DELETE FROM settings WHERE key=?').run(`oauth:${state}`);const cfg=await integrationSecret(meta.userId,'google_oauth');const tokens=await googleExchange(String(req.query.code||''),cfg||{});await db.prepare('INSERT INTO integration_tokens(id,user_id,provider,access_token,refresh_token,token_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET access_token=excluded.access_token,refresh_token=integration_tokens.refresh_token,token_json=excluded.token_json,updated_at=excluded.updated_at').run(id(),meta.userId,'google','','',protectSecret(JSON.stringify(tokens)),now(),now());res.redirect('/?google=connected')}catch(e){res.status(400).send('Google OAuth failed')}});

app.use('/api',auth);
app.get('/api/integrations',(req,res)=>res.json(integrationState()));
app.get('/api/me',(req,res)=>res.json(req.user));
app.get('/api/tasks',async(req,res)=>res.json(await db.prepare('SELECT * FROM tasks WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(req.user.id)));
app.get('/api/projects',async(req,res)=>res.json(await db.prepare('SELECT * FROM projects WHERE user_id=? ORDER BY updated_at DESC').all(req.user.id)));
app.get('/api/goals',async(req,res)=>res.json(await db.prepare('SELECT * FROM goals WHERE user_id=? ORDER BY priority DESC,updated_at DESC').all(req.user.id)));
app.post('/api/projects',async(req,res)=>{const name=String(req.body?.name||'').trim();if(!name)return res.status(400).json({error:'name required'});const x=id(),t=now();await db.prepare('INSERT INTO projects(id,user_id,name,description,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(x,req.user.id,name,String(req.body?.description||''),'active',t,t);res.json({id:x,status:'active'})});
app.post('/api/goals',async(req,res)=>{const title=String(req.body?.title||'').trim();if(!title)return res.status(400).json({error:'title required'});if(req.body?.project_id&&!await db.prepare('SELECT id FROM projects WHERE id=? AND user_id=?').get(req.body.project_id,req.user.id))return res.status(404).json({error:'project not found'});const x=id(),t=now();await db.prepare('INSERT INTO goals(id,user_id,project_id,title,description,status,priority,target_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(x,req.user.id,req.body.project_id||null,title,String(req.body?.description||''),'active',Number(req.body?.priority||5),req.body?.target_at||null,t,t);res.json({id:x,status:'active'})});
app.post('/api/tasks/:id/ack',async(req,res)=>{const task=await db.prepare('SELECT id,status,acknowledged_at FROM tasks WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!task)return res.status(404).json({error:'task not found'});if(task.acknowledged_at)return res.json({ok:true,already:true,acknowledged_at:task.acknowledged_at});const t=now();await db.prepare("UPDATE tasks SET acknowledged_at=?,acknowledged_by_user=TRUE,status=CASE WHEN status='waiting_confirmation' THEN 'completed' ELSE status END,updated_at=? WHERE id=? AND user_id=?").run(t,t,req.params.id,req.user.id);await audit(req.user.id,'task_acknowledged',{taskId:req.params.id});res.json({ok:true,acknowledged_at:t,status:'completed'})});
app.get('/api/correspondence',async(req,res)=>res.json(await db.prepare('SELECT * FROM correspondence WHERE user_id=? ORDER BY updated_at DESC LIMIT 100').all(req.user.id)));
app.delete('/api/tasks/:id',async(req,res)=>{const task=await db.prepare('SELECT id,title FROM tasks WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!task)return res.status(404).json({error:'task not found'});await db.prepare('DELETE FROM schedules WHERE task_id=? AND user_id=?').run(task.id,req.user.id);await db.prepare('DELETE FROM task_steps WHERE task_id=?').run(task.id);await db.prepare('DELETE FROM approvals WHERE task_id=? AND user_id=?').run(task.id,req.user.id);await db.prepare('DELETE FROM tool_runs WHERE task_id=? AND user_id=?').run(task.id,req.user.id);await db.prepare('DELETE FROM agent_runs WHERE task_id=? AND user_id=?').run(task.id,req.user.id);await db.prepare('DELETE FROM tasks WHERE id=? AND user_id=?').run(task.id,req.user.id);await audit(req.user.id,'task_deleted',{taskId:task.id,title:task.title});res.json({ok:true,id:task.id})});
app.get('/api/tasks/:id/steps',async(req,res)=>res.json(await db.prepare('SELECT * FROM task_steps WHERE task_id=? AND EXISTS(SELECT 1 FROM tasks WHERE tasks.id=task_steps.task_id AND tasks.user_id=?)').all(req.params.id,req.user.id)));
app.get('/api/memories',async(req,res)=>res.json(await db.prepare('SELECT * FROM memories WHERE user_id=? ORDER BY importance DESC,updated_at DESC').all(req.user.id)));
app.get('/api/approvals',async(req,res)=>res.json(await db.prepare('SELECT * FROM approvals WHERE user_id=? ORDER BY created_at DESC').all(req.user.id)));
app.get('/api/schedules',async(req,res)=>res.json(await db.prepare('SELECT * FROM schedules WHERE user_id=? ORDER BY enabled DESC,run_at').all(req.user.id)));
app.get('/api/runs',async(req,res)=>res.json(await db.prepare('SELECT * FROM agent_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 100').all(req.user.id)));
app.get('/api/audit',async(req,res)=>res.json(await db.prepare('SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id)));
app.get('/api/notifications',async(req,res)=>{const rows=await db.prepare("SELECT id,event,data,created_at FROM audit_logs WHERE user_id=? AND event IN ('task_executed','schedule_executed','reminder_due','message_reply','approval_executed','approval_execution_failed','task_error','schedule_error') ORDER BY created_at DESC LIMIT 40").all(req.user.id);res.json(rows)});
app.get('/api/push/vapid-public-key',auth,(req,res)=>{if(!VAPID_PUBLIC_KEY)return res.status(503).json({error:'push notifications are not configured'});res.json({publicKey:VAPID_PUBLIC_KEY})});
app.post('/api/push/subscribe',auth,async(req,res)=>{if(!VAPID_PUBLIC_KEY||!VAPID_PRIVATE_KEY)return res.status(503).json({error:'push notifications are not configured'});const s=req.body?.subscription;if(!s?.endpoint||!s?.keys?.p256dh||!s?.keys?.auth)return res.status(400).json({error:'invalid push subscription'});await db.prepare('INSERT INTO push_subscriptions(id,user_id,endpoint,p256dh,auth,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,endpoint) DO UPDATE SET p256dh=excluded.p256dh,auth=excluded.auth,updated_at=excluded.updated_at').run(id(),req.user.id,s.endpoint,s.keys.p256dh,s.keys.auth,now(),now());res.json({ok:true})});
app.delete('/api/push/subscribe',auth,async(req,res)=>{const endpoint=String(req.body?.endpoint||'');if(endpoint)await db.prepare('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?').run(req.user.id,endpoint);else await db.prepare('DELETE FROM push_subscriptions WHERE user_id=?').run(req.user.id);res.json({ok:true})});
app.get('/api/agent/health',async(req,res)=>{const failed=await db.prepare("SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=? AND status IN ('failed','needs_review') AND started_at>NOW()-INTERVAL '24 hours'").get(req.user.id);const pending=await db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id=? AND status='pending'").get(req.user.id);const due=await db.prepare("SELECT COUNT(*) AS n FROM tasks WHERE user_id=? AND status='planned' AND due_at IS NOT NULL AND due_at<=?").get(req.user.id,now());const active=await db.prepare("SELECT COUNT(*) AS n FROM schedules WHERE user_id=? AND enabled=TRUE").get(req.user.id);res.json({healthy:Number(failed.n)===0,failed_runs_24h:Number(failed.n),pending_approvals:Number(pending.n),due_tasks:Number(due.n),active_schedules:Number(active.n),checked_at:now()})});
app.get('/api/stats',async(req,res)=>{const u=req.user.id;const [tasks,mem,pending,schedules,runs]=await Promise.all([db.prepare('SELECT COUNT(*) AS n FROM tasks WHERE user_id=?').get(u),db.prepare('SELECT COUNT(*) AS n FROM memories WHERE user_id=?').get(u),db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id=? AND status='pending'").get(u),db.prepare('SELECT COUNT(*) AS n FROM schedules WHERE user_id=? AND enabled=TRUE').get(u),db.prepare('SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=?').get(u)]);res.json({tasks:Number(tasks.n),memories:Number(mem.n),pending_approvals:Number(pending.n),schedules:Number(schedules.n),runs:Number(runs.n)})});

app.post('/api/approvals/:id/decide',async(req,res)=>{const a=await db.prepare('SELECT * FROM approvals WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!a)return res.status(404).json({error:'approval not found'});if(a.status!=='pending')return res.status(409).json({error:`approval already ${a.status}`});const approved=Boolean(req.body?.approved);if(!approved){await db.prepare("UPDATE approvals SET status='rejected',decided_at=? WHERE id=? AND user_id=?").run(now(),a.id,req.user.id);await audit(req.user.id,'approval_decided',{approvalId:a.id,status:'rejected'});return res.json({ok:true,status:'rejected'})}
  let actionName=Object.entries(approvalMap).find(([,v])=>v===a.action)?.[0]; if(!actionName)return res.status(400).json({error:'unsupported approval action'});
  let payload;try{payload=JSON.parse(a.payload)}catch{return res.status(400).json({error:'invalid approval payload'})}
  await db.prepare("UPDATE approvals SET status='approved',decided_at=? WHERE id=? AND user_id=?").run(now(),a.id,req.user.id);
  try{const out=await tool(actionName,payload,req.user.id,null,{skipApproval:true,taskId:a.task_id});await db.prepare('UPDATE approvals SET executed_at=? WHERE id=? AND user_id=?').run(now(),a.id,req.user.id);await audit(req.user.id,'approval_executed',{approvalId:a.id,action:a.action,result:String(out?.message||out?.result||out||'').slice(0,700)});return res.json({ok:true,status:'executed',result:out})}catch(e){await audit(req.user.id,'approval_execution_failed',{approvalId:a.id,error:e.message});return res.status(502).json({error:e.message,approval_id:a.id,status:'approved'})}
});
app.post('/api/schedules/:id/toggle',async(req,res)=>{const s=await db.prepare('SELECT enabled FROM schedules WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!s)return res.status(404).json({error:'schedule not found'});await db.prepare('UPDATE schedules SET enabled=?,updated_at=? WHERE id=? AND user_id=?').run(s.enabled?0:1,now(),req.params.id,req.user.id);res.json({ok:true,enabled:!Boolean(s.enabled)})});
app.post('/api/chat',async(req,res)=>{
  const text=String(req.body?.message||'').trim();
  const attachments=Array.isArray(req.body?.attachments)?req.body.attachments.slice(0,5):[];
  if(!text&&!attachments.length)return res.status(400).json({error:'message or attachment required'});
  if(text.length>20000)return res.status(413).json({error:'message too long'});
  let cid=req.body?.conversation_id;
  if(!cid){cid=id();const t=now();await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(cid,req.user.id,'محادثة جديدة',t,t)}
  else if(!await db.prepare('SELECT id FROM conversations WHERE id=? AND user_id=?').get(cid,req.user.id))return res.status(404).json({error:'conversation not found'});
  const content=[];
  if(text)content.push({type:'input_text',text});
  for(const a of attachments){
    const data=String(a.data||'');
    if(!/^data:[^;]+;base64,/.test(data))continue;
    const type=String(a.type||'application/octet-stream');
    if(type.startsWith('image/'))content.push({type:'input_image',image_url:data});
    else content.push({type:'input_file',filename:String(a.name||'attachment'),file_data:data});
  }
  const saved=JSON.stringify({__antonio_message:true,text,content:content.map(x=>x.type==='input_image'?{type:'input_text',text:'[صورة مرفقة]'}:x.type==='input_file'?{type:'input_text',text:'[ملف مرفق: '+String(aName(x.filename||'ملف'))+']'}:x)});
  function aName(x){return String(x).replace(/[<>]/g,'').slice(0,160)}
  await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),cid,req.user.id,'user',saved,now());
  try{const ans=await runAgent({conversationId:cid,input:text||'مرفقات مضافة إلى المحادثة',userId:req.user.id,inputContent:content});await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),cid,req.user.id,'assistant',ans,now());await db.prepare('UPDATE conversations SET updated_at=? WHERE id=? AND user_id=?').run(now(),cid,req.user.id);res.json({conversation_id:cid,answer:ans})}catch(e){console.error('chat error',e);res.status(500).json({error:'agent execution failed'})}
});
app.get('/api/conversations',async(req,res)=>{
  const limit=Math.min(50,Math.max(1,Number(req.query.limit||20)));
  const rows=await db.prepare('SELECT id,title,created_at,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC LIMIT ?').all(req.user.id,limit);
  res.json(rows);
});
app.delete('/api/conversations/:id',async(req,res)=>{
  const cid=req.params.id;
  const exists=await db.prepare('SELECT id FROM conversations WHERE id=? AND user_id=?').get(cid,req.user.id);
  if(!exists)return res.status(404).json({error:'conversation not found'});
  await db.prepare('DELETE FROM messages WHERE conversation_id=? AND user_id=?').run(cid,req.user.id);
  await db.prepare('DELETE FROM conversations WHERE id=? AND user_id=?').run(cid,req.user.id);
  res.json({ok:true});
});
app.get('/api/conversations/:id/messages',async(req,res)=>{const rows=await db.prepare('SELECT role,content,created_at FROM messages WHERE conversation_id=? AND user_id=? ORDER BY created_at').all(req.params.id,req.user.id);res.json(rows.map(r=>{if(r.role==='user'){try{const x=JSON.parse(r.content);if(x&&x.__antonio_message)return {...r,content:String(x.text||'')+(Array.isArray(x.content)&&x.content.some(v=>v?.type==='input_image'||v?.type==='input_file')?'\nمرفق مضاف':'')}}catch{} }return r}))});

export { runAgent, app, auth };
await import('./v5.js').then(m=>m.registerV5({app,auth,db,now,id,protectSecret}));

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const port=Number(process.env.PORT||3000);
  const server=app.listen(port,()=>console.log(`Antonio Agent 6.0 running on ${port}`));
  server.requestTimeout=Number(process.env.REQUEST_TIMEOUT_MS||120000);
  server.headersTimeout=Number(process.env.HEADERS_TIMEOUT_MS||30000);
  server.keepAliveTimeout=5000;
  const shutdown=async()=>{try{await db.close()}finally{server.close(()=>process.exit(0))}};
  process.on('SIGTERM',shutdown);
  process.on('SIGINT',shutdown);
}