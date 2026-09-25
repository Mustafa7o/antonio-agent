import 'dotenv/config';
import { db, now, id, audit } from './db.js';
import { runAgent } from './server.js';

const intervalMs = Math.max(5000, Number(process.env.WORKER_INTERVAL_MS || 15000));
let busy = false;

async function worker(){
  if(busy)return;
  busy=true;
  try{
    const due = await db.prepare("SELECT * FROM schedules WHERE enabled=TRUE AND run_at IS NOT NULL AND run_at<=? ORDER BY run_at LIMIT 20").all(now());
    for(const s of due){
      try{
        const claimed = await db.prepare("UPDATE schedules SET last_run_at=?, run_at=CASE WHEN repeat_minutes IS NOT NULL THEN ? ELSE run_at END, enabled=CASE WHEN repeat_minutes IS NULL THEN FALSE ELSE enabled END, updated_at=? WHERE id=? AND enabled=TRUE AND run_at<=?").run(now(),new Date(Date.now()+Number(s.repeat_minutes)*60000).toISOString(),now(),s.id,now());
        if(!claimed?.changes && claimed?.rowCount===0)continue;
        const c=id(),t=now();
        await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,s.user_id,'Scheduled run',t,t);
        await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'user',s.prompt,t);
        const ans=await runAgent({conversationId:c,input:s.prompt,userId:s.user_id,taskId:s.task_id||null});
        await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,s.user_id,'assistant',ans,now());
        await audit(s.user_id,'schedule_executed',{scheduleId:s.id});
      }catch(e){await audit(s.user_id,'schedule_error',{scheduleId:s.id,error:e.message})}
    }

    const taskDue = await db.prepare("SELECT * FROM tasks WHERE status IN ('planned','running') AND due_at IS NOT NULL AND due_at<=? ORDER BY priority DESC,updated_at LIMIT 10").all(now());
    for(const task of taskDue){
      try{
        const claimed=await db.prepare("UPDATE tasks SET status='running',updated_at=? WHERE id=? AND status IN ('planned','running')").run(now(),task.id);
        if(claimed?.changes===0 && claimed?.rowCount===0) continue;
        const c=id(),t=now();
        await db.prepare('INSERT INTO conversations(id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(c,task.user_id,'Autonomous task',t,t);
        const prompt='Execute this task autonomously. Verify every step and report the result. Task: '+task.title+'\nGoal: '+task.goal;
        await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'user',prompt,t);
        const ans=await runAgent({conversationId:c,input:prompt,userId:task.user_id,taskId:task.id});
        await db.prepare('INSERT INTO messages(id,conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?,?)').run(id(),c,task.user_id,'assistant',ans,now());
        await db.prepare("UPDATE tasks SET status='completed',result=?,updated_at=? WHERE id=? AND status='running'").run(ans,now(),task.id);
        await audit(task.user_id,'task_executed',{taskId:task.id});
      }catch(e){
        await db.prepare("UPDATE tasks SET status='failed',result=?,updated_at=? WHERE id=?").run(e.message,now(),task.id);
        await audit(task.user_id,'task_error',{taskId:task.id,error:e.message});
      }
    }
  } finally {busy=false}
}

await worker();
const timer=setInterval(()=>worker().catch(()=>{}),intervalMs);timer.unref();
console.log(`Antonio worker running every ${intervalMs}ms`);
process.on('SIGTERM',async()=>{clearInterval(timer);await db.close();process.exit(0)});
process.on('SIGINT',async()=>{clearInterval(timer);await db.close();process.exit(0)});
