import OpenAI from 'openai';

function parseJson(text, fallback){
  try{return JSON.parse(String(text||'').replace(/^\s*\`\`\`json\s*/,'').replace(/\s*\`\`\`\s*$/,''));}
  catch{return fallback}
}

export async function createPlan({openai,model,input,memory,history}){
  if(!openai)return {goal:input,success_criteria:['Provide a useful answer or complete the requested action'],steps:[{id:'step-1',action:'Understand the request and respond',tool_hint:null,verification:'Check that the response directly addresses the request'}]};
  const prompt = [
    'Create a concise execution plan for Antonio, an autonomous personal digital agent.',
    'Return JSON only with: goal (string), success_criteria (string[]), steps (array of objects with id, action, tool_hint, verification).',
    'Do not execute anything. Keep 1-6 steps. Prefer the smallest plan that can accomplish the goal.',
    'User request:', String(input),
    'Relevant memory:', JSON.stringify(memory||[]),
    'Recent conversation:', JSON.stringify((history||[]).slice(-20))
  ].join('\n');
  try{
    const r=await openai.responses.create({model,input:[{role:'system',content:'You are Antonio Planner. Output valid JSON only.'},{role:'user',content:prompt}],store:false});
    const fallback={goal:input,success_criteria:['Complete the user request accurately','Do not claim unverified actions'],steps:[{id:'step-1',action:'Execute the request using available tools when needed',tool_hint:null,verification:'Check tool results before reporting success'}]};
    const p=parseJson(r.output_text,fallback);
    if(!p||typeof p.goal!=='string'||!Array.isArray(p.steps))return fallback;
    return {...fallback,...p,steps:p.steps.slice(0,6)};
  }catch{return {goal:input,success_criteria:['Complete the user request accurately','Do not claim unverified actions'],steps:[{id:'step-1',action:'Execute the request using available tools when needed',tool_hint:null,verification:'Check tool results before reporting success'}]}}
}

export async function verifyRun({openai,model,input,plan,toolResults,answer}){
  if(!openai)return {verified:true,issues:[],next_action:null};
  const prompt=[
    'Verify whether Antonio actually completed the user request.',
    'Return JSON only: verified (boolean), issues (string[]), next_action (string|null).',
    'Do not invent success. A tool error, missing integration, or missing evidence means the relevant part is not verified.',
    'User request:',String(input),
    'Plan:',JSON.stringify(plan||{}),
    'Tool results:',JSON.stringify((toolResults||[]).slice(-30)),
    'Proposed answer:',String(answer||'')
  ].join('\n');
  try{
    const r=await openai.responses.create({model,input:[{role:'system',content:'You are Antonio Verifier. Be strict, factual, and output valid JSON only.'},{role:'user',content:prompt}],store:false});
    return parseJson(r.output_text,{verified:false,issues:['Verification failed to parse'],next_action:'Report uncertainty rather than claiming success'});
  }catch{return {verified:false,issues:['Verification service unavailable'],next_action:'Report uncertainty rather than claiming success'}}
}
