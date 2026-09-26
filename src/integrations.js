import crypto from 'node:crypto';
import { google } from 'googleapis';

const googleScopes = (process.env.GOOGLE_SCOPES || [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/calendar.events'
].join(' ')).split(/\s+/).filter(Boolean);
export const integrationState = () => ({
  google: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
  telegram: Boolean(process.env.TELEGRAM_BOT_TOKEN),
  whatsapp: Boolean(process.env.WHATSAPP_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID),
  web_search: process.env.ENABLE_WEB_SEARCH !== 'false',
  file_search: Boolean(process.env.ENABLE_FILE_SEARCH === 'true' && process.env.OPENAI_VECTOR_STORE_ID)
});

export function googleClient(config={}) {
  const clientId=config.client_id||process.env.GOOGLE_CLIENT_ID, clientSecret=config.client_secret||process.env.GOOGLE_CLIENT_SECRET, redirectUri=config.redirect_uri||process.env.GOOGLE_REDIRECT_URI;
  if (!clientId || !clientSecret) throw new Error('Google OAuth is not configured');
  return new google.auth.OAuth2(clientId,clientSecret,redirectUri);
}
export function googleAuthUrl(state,config={}) {
  const c = googleClient(config);
  return c.generateAuthUrl({ access_type:'offline', prompt:'consent', scope:googleScopes, state });
}
export async function googleExchange(code,config={}) {
  const c = googleClient(config);
  const {tokens} = await c.getToken(code); return tokens;
}
export function googleAuthorizedClient(tokens,config={}) {
  const c=googleClient(config); c.setCredentials(tokens); return c;
}
export async function gmailSend(tokens,{to,subject,text},config={}) {
  if(!to||!subject||!text) throw new Error('to, subject and text are required');
  const auth=googleAuthorizedClient(tokens,config), gmail=google.gmail({version:'v1',auth});
  const raw=[`To: ${to}`,`Subject: ${subject}`,'Content-Type: text/plain; charset=utf-8','',text].join('\r\n');
  const encoded=Buffer.from(raw).toString('base64url');
  return gmail.users.messages.send({userId:'me',requestBody:{raw:encoded}}).then(r=>({id:r.data.id,threadId:r.data.threadId}));
}
export async function gmailList(tokens,q='',config={}) {
  const auth=googleAuthorizedClient(tokens,config), gmail=google.gmail({version:'v1',auth});
  const r=await gmail.users.messages.list({userId:'me',q,maxResults:20}); return r.data.messages||[];
}

function decodeGmailData(data='') {
  return Buffer.from(String(data).replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8');
}
function stripHtml(html='') {
  return String(html)
    .replace(/<style[\\s\\S]*?<\\/style>/gi,' ')
    .replace(/<script[\\s\\S]*?<\\/script>/gi,' ')
    .replace(/<br\\s*\\/?>/gi,'\n')
    .replace(/<\\/p>/gi,'\n')
    .replace(/<[^>]+>/g,' ')
    .replace(/&nbsp;/gi,' ')
    .replace(/&amp;/gi,'&')
    .replace(/&lt;/gi,'<')
    .replace(/&gt;/gi,'>')
    .replace(/\\r\\n/g,'\n')
    .replace(/[ \\t]+/g,' ')
    .replace(/\\n{3,}/g,'\n\n')
    .trim();
}
function collectGmailBodies(part, out={plain:[],html:[]}) {
  if(!part)return out;
  const mime=String(part.mimeType||'').toLowerCase();
  if(part.body?.data){
    const text=decodeGmailData(part.body.data);
    if(mime==='text/plain')out.plain.push(text);
    else if(mime==='text/html')out.html.push(text);
  }
  for(const child of part.parts||[])collectGmailBodies(child,out);
  return out;
}
function headerValue(headers=[],name='') {
  return headers.find(h=>String(h.name||'').toLowerCase()===name.toLowerCase())?.value||'';
}
export async function gmailRead(tokens,messageId,config={}) {
  if(!messageId) throw new Error('message_id is required');
  const auth=googleAuthorizedClient(tokens,config), gmail=google.gmail({version:'v1',auth});
  const r=await gmail.users.messages.get({userId:'me',id:String(messageId),format:'full'});
  const msg=r.data||{}, payload=msg.payload||{}, headers=payload.headers||[];
  const bodies=collectGmailBodies(payload);
  const body=(bodies.plain.join('\n\n').trim()||stripHtml(bodies.html.join('\n\n'))||msg.snippet||'').trim();
  return {
    id:msg.id,
    threadId:msg.threadId,
    labelIds:msg.labelIds||[],
    internalDate:msg.internalDate||null,
    from:headerValue(headers,'From'),
    to:headerValue(headers,'To'),
    cc:headerValue(headers,'Cc'),
    subject:headerValue(headers,'Subject'),
    date:headerValue(headers,'Date'),
    snippet:msg.snippet||'',
    body,
    html:bodies.html.join('\n\n').trim()||null
  };
}
export async function calendarCreate(tokens,{summary,start,end,description},config={}) {
  const auth=googleAuthorizedClient(tokens,config), calendar=google.calendar({version:'v3',auth});
  const r=await calendar.events.insert({calendarId:'primary',requestBody:{summary,description,start:{dateTime:start},end:{dateTime:end}}});
  return {id:r.data.id,htmlLink:r.data.htmlLink};
}
export async function telegramSend(chatId,text,config={}) {
  const token=config.bot_token||process.env.TELEGRAM_BOT_TOKEN;
  if(!token) throw new Error('Telegram bot token is not configured');
  const r=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chatId,text})});
  const data=await r.json(); if(!r.ok||!data.ok) throw new Error(data.description||'Telegram send failed'); return data.result;
}
export async function whatsappSend(to,text,config={}) {
  const token=config.access_token||process.env.WHATSAPP_ACCESS_TOKEN, phone=config.phone_number_id||process.env.WHATSAPP_PHONE_NUMBER_ID, version=config.api_version||process.env.WHATSAPP_API_VERSION||'v23.0';
  if(!token||!phone) throw new Error('WhatsApp Cloud API is not configured');
  const r=await fetch(`https://graph.facebook.com/${version}/${phone}/messages`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({messaging_product:'whatsapp',to,type:'text',text:{body:text}})});
  const data=await r.json(); if(!r.ok) throw new Error(data.error?.message||'WhatsApp send failed'); return data;
}
export function newState(){return crypto.randomUUID();}
