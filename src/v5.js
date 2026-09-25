export function registerV5({app,auth,db,now,id,protectSecret}) {
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

  app.get('/api/v5/secrets',auth,async(req,res)=>{
    const rows=await db.prepare("SELECT provider,updated_at FROM integration_tokens WHERE user_id=? AND provider IN ('google_oauth','telegram_config','whatsapp_config') ORDER BY provider").all(req.user.id);
    const m=new Map(rows.map(r=>[r.provider,r]));
    res.json(['google','telegram','whatsapp'].map(p=>({provider:p,configured:m.has(p==='google'?'google_oauth':p+'_config'),updated_at:m.get(p==='google'?'google_oauth':p+'_config')?.updated_at||null})));
  });
  app.put('/api/v5/secrets/:provider',auth,async(req,res)=>{
    const p=String(req.params.provider||'').toLowerCase(),map={google:'google_oauth',telegram:'telegram_config',whatsapp:'whatsapp_config'},dbProvider=map[p];
    if(!dbProvider)return res.status(400).json({error:'unsupported provider'});
    const b=req.body||{};let value;
    if(p==='google'){const client_id=String(b.client_id||'').trim(),client_secret=String(b.client_secret||'').trim(),redirect_uri=String(b.redirect_uri||'https://antonio-production-4e8f.up.railway.app/api/integrations/google/callback').trim();if(!client_id||!client_secret)return res.status(400).json({error:'Google Client ID and Client Secret are required'});value={client_id,client_secret,redirect_uri}}
    if(p==='telegram'){const bot_token=String(b.bot_token||'').trim();if(!bot_token)return res.status(400).json({error:'Telegram bot token is required'});value={bot_token}}
    if(p==='whatsapp'){const access_token=String(b.access_token||'').trim(),phone_number_id=String(b.phone_number_id||'').trim(),api_version=String(b.api_version||'v23.0').trim();if(!access_token||!phone_number_id)return res.status(400).json({error:'WhatsApp access token and phone number ID are required'});value={access_token,phone_number_id,api_version}}
    await db.prepare('INSERT INTO integration_tokens(id,user_id,provider,access_token,refresh_token,token_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET token_json=excluded.token_json,updated_at=excluded.updated_at').run(id(),req.user.id,dbProvider,'','',protectSecret(JSON.stringify(value)),now(),now());
    res.json({ok:true,provider:p,configured:true});
  });
  app.delete('/api/v5/secrets/:provider',auth,async(req,res)=>{const map={google:'google_oauth',telegram:'telegram_config',whatsapp:'whatsapp_config'},dbProvider=map[String(req.params.provider||'').toLowerCase()];if(!dbProvider)return res.status(400).json({error:'unsupported provider'});await db.prepare('DELETE FROM integration_tokens WHERE user_id=? AND provider=?').run(req.user.id,dbProvider);res.json({ok:true,configured:false})});
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
