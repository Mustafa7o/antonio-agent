export function registerV5({app,auth,db,now,id}) {
  const defaults = {
    display_name:'Antonio',
    language:'ar-IQ',
    personality:'friendly',
    autonomy:'high',
    require_approval_external:true,
    notifications:true,
    memory_enabled:true,
    theme:'dark-glass'
  };

  async function readSettings(userId){
    const rows=await db.prepare('SELECT key,value FROM settings ORDER BY key').all();
    const out={...defaults};
    for(const r of rows){try{out[r.key]=JSON.parse(r.value)}catch{out[r.key]=r.value}}
    return out;
  }

  app.get('/api/v5/settings',auth,async(req,res)=>res.json(await readSettings(req.user.id)));

  app.put('/api/v5/settings',auth,async(req,res)=>{
    const body=req.body||{};
    const allowed=Object.keys(defaults);
    for(const key of allowed){
      if(body[key]===undefined) continue;
      await db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,JSON.stringify(body[key]));
    }
    res.json(await readSettings(req.user.id));
  });

  app.get('/api/v5/accounts',auth,async(req,res)=>{
    const rows=await db.prepare('SELECT provider,updated_at FROM integration_tokens WHERE user_id=? ORDER BY provider').all(req.user.id);
    const connected=new Map(rows.map(r=>[r.provider,r]));
    const providers=['google','telegram','whatsapp','tiktok','phone'];
    res.json(providers.map(provider=>({
      provider,
      connected:connected.has(provider),
      updated_at:connected.get(provider)?.updated_at||null
    })));
  });

  app.post('/api/v5/accounts/:provider/disconnect',auth,async(req,res)=>{
    const provider=String(req.params.provider||'').toLowerCase();
    const allowed=['google','telegram','whatsapp','tiktok','phone'];
    if(!allowed.includes(provider)) return res.status(400).json({error:'unsupported provider'});
    await db.prepare('DELETE FROM integration_tokens WHERE user_id=? AND provider=?').run(req.user.id,provider);
    res.json({ok:true,provider,connected:false});
  });

  app.get('/api/v5/overview',auth,async(req,res)=>{
    const u=req.user.id;
    const [tasks,running,memories,pending,runs]=await Promise.all([
      db.prepare('SELECT COUNT(*) AS n FROM tasks WHERE user_id=?').get(u),
      db.prepare("SELECT COUNT(*) AS n FROM tasks WHERE user_id=? AND status='running'").get(u),
      db.prepare('SELECT COUNT(*) AS n FROM memories WHERE user_id=?').get(u),
      db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE user_id=? AND status='pending'").get(u),
      db.prepare('SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=?').get(u)
    ]);
    res.json({version:'5.0.0',tasks:Number(tasks.n),running:Number(running.n),memories:Number(memories.n),pending_approvals:Number(pending.n),runs:Number(runs.n)});
  });
}
