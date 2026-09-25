import 'dotenv/config';

const intervalMs=Math.max(5000,Number(process.env.WORKER_INTERVAL_MS||15000));
const target=String(process.env.WORKER_TARGET_URL||'').replace(/\/$/,'');
const secret=String(process.env.WORKER_SECRET||'');
if(!target)throw new Error('WORKER_TARGET_URL is required');
if(!secret)throw new Error('WORKER_SECRET is required');
let busy=false;
async function worker(){
  if(busy)return; busy=true;
  try{
    const r=await fetch(target+'/api/internal/worker-tick',{method:'POST',headers:{'x-worker-secret':secret,'content-type':'application/json'},body:'{}'});
    const body=await r.text();
    if(!r.ok)throw new Error('worker tick '+r.status+': '+body.slice(0,500));
    console.log('Antonio worker tick',body);
  }catch(e){console.error('Antonio worker tick failed',e.message)}
  finally{busy=false}
}
await worker();
const timer=setInterval(worker,intervalMs);
console.log('Antonio worker running every '+intervalMs+'ms -> '+target);
process.on('SIGTERM',()=>{clearInterval(timer);process.exit(0)});
process.on('SIGINT',()=>{clearInterval(timer);process.exit(0)});
