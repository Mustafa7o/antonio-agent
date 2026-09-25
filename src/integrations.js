import crypto from 'node:crypto';
import { google } from 'googleapis';

const googleScopes = (process.env.GOOGLE_SCOPES || '').split(/\s+/).filter(Boolean);
export const integrationState = () => ({
  google: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
  telegram: Boolean(process.env.TELEGRAM_BOT_TOKEN),
  whatsapp: Boolean(process.env.WHATSAPP_ACCESS_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID),
  web_search: process.env.ENABLE_WEB_SEARCH !== 'false',
  file_search: Boolean(process.env.ENABLE_FILE_SEARCH === 'true' && process.env.OPENAI_VECTOR_STORE_ID)
});

export function googleClient() {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) throw new Error('Google OAuth is not configured');
  return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
}
export function googleAuthUrl(state) {
  const c = googleClient();
  return c.generateAuthUrl({ access_type:'offline', prompt:'consent', scope:googleScopes, state });
}
export async function googleExchange(code) {
  const c = googleClient();
  const {tokens} = await c.getToken(code); return tokens;
}
export function googleAuthorizedClient(tokens) {
  const c=googleClient(); c.setCredentials(tokens); return c;
}
export async function gmailSend(tokens,{to,subject,text}) {
  if(!to||!subject||!text) throw new Error('to, subject and text are required');
  const auth=googleAuthorizedClient(tokens), gmail=google.gmail({version:'v1',auth});
  const raw=[`To: ${to}`,`Subject: ${subject}`,'Content-Type: text/plain; charset=utf-8','',text].join('\r\n');
  const encoded=Buffer.from(raw).toString('base64url');
  return gmail.users.messages.send({userId:'me',requestBody:{raw:encoded}}).then(r=>({id:r.data.id,threadId:r.data.threadId}));
}
export async function gmailList(tokens,q='') {
  const auth=googleAuthorizedClient(tokens), gmail=google.gmail({version:'v1',auth});
  const r=await gmail.users.messages.list({userId:'me',q,maxResults:20}); return r.data.messages||[];
}
export async function calendarCreate(tokens,{summary,start,end,description}) {
  const auth=googleAuthorizedClient(tokens), calendar=google.calendar({version:'v3',auth});
  const r=await calendar.events.insert({calendarId:'primary',requestBody:{summary,description,start:{dateTime:start},end:{dateTime:end}}});
  return {id:r.data.id,htmlLink:r.data.htmlLink};
}
export async function telegramSend(chatId,text) {
  if(!process.env.TELEGRAM_BOT_TOKEN) throw new Error('Telegram bot token is not configured');
  const r=await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chatId,text})});
  const data=await r.json(); if(!r.ok||!data.ok) throw new Error(data.description||'Telegram send failed'); return data.result;
}
export async function whatsappSend(to,text) {
  const token=process.env.WHATSAPP_ACCESS_TOKEN, phone=process.env.WHATSAPP_PHONE_NUMBER_ID, version=process.env.WHATSAPP_API_VERSION||'v23.0';
  if(!token||!phone) throw new Error('WhatsApp Cloud API is not configured');
  const r=await fetch(`https://graph.facebook.com/${version}/${phone}/messages`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({messaging_product:'whatsapp',to,type:'text',text:{body:text}})});
  const data=await r.json(); if(!r.ok) throw new Error(data.error?.message||'WhatsApp send failed'); return data;
}
export function newState(){return crypto.randomUUID();}
