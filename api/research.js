const {put,get,list}=require('@vercel/blob');
const crypto=require('node:crypto');
const prefix='research/';
const sign=v=>crypto.createHmac('sha256',process.env.QZENT_SESSION_SECRET).update(v).digest('hex');
function authorized(req){
 const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('qzent_session='))?.slice(14);
 if(!token)return false;
 const [expires,signature]=token.split('.');
 if(!expires||!signature||!Number.isFinite(Number(expires))||Number(expires)<Date.now())return false;
 const expected=sign(expires);
 return signature.length===expected.length&&crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected));
}
async function read(path){
 const result=await get(path,{access:'private',useCache:false});
 return result?.statusCode===200?JSON.parse(await new Response(result.stream).text()):null;
}
function validate(body, legacy=false){
 const r=body.record,q=body.questionnaire;
 if(!r||!q||typeof q.id!=='string'||typeof q.title!=='string'||q.title.length>300||typeof r.id!=='string'||! /^[a-zA-Z0-9_-]{1,100}$/.test(r.id)||!Array.isArray(q.questions)||q.questions.length>100||!q.questions.length||r.questionnaireId!==q.id||!r.answers||typeof r.answers!=='object'||Array.isArray(r.answers))throw Error('Dados inválidos.');
 for(const k of ['personName','room','interviewer','obs','questionnaireTitle','date','time'])if(typeof r[k]!=='string'||r[k].length>2000)throw Error('Dados inválidos.');
 for(const item of q.questions){
  if(typeof item.id!=='string'||typeof item.text!=='string'||item.text.length>1000||!['short','long','single','multi','list','yesno','scale5','note10'].includes(item.type)||!Array.isArray(item.options)||item.options.length>100||item.options.some(o=>typeof o!=='string'||o.length>500))throw Error('Pergunta inválida.');
  const value=r.answers[item.id];
  if(!legacy&&item.required&&(value===undefined||value===null||value===''||(Array.isArray(value)&&!value.length)))throw Error('Responda todas as perguntas obrigatórias.');
  if(value!==undefined&&!(typeof value==='string'||typeof value==='number'||(Array.isArray(value)&&value.every(v=>typeof v==='string'))))throw Error('Resposta inválida.');
  if(Array.isArray(item.options)&&item.options.length&&value!==undefined){
   if((Array.isArray(value)?value:[value]).some(v=>!item.options.includes(v)))throw Error('Alternativa inválida.');
  }
 }
 if(r.anonymous){r.personName='Anônimo';r.room='Não informado';}
 return {record:{...r,demo:false,questionnaireSnapshot:q},questionnaire:q};
}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 const origin=req.headers.origin;
 if(origin&&origin!== 'https://'+req.headers.host)return res.status(403).json({error:'Origem inválida.'});
 try{
  if(req.method==='POST'&&req.query.action==='login'){
   if(!process.env.QZENT_PASSWORD||!process.env.QZENT_SESSION_SECRET)throw Error('Configuração de acesso indisponível.');
   const input=String(req.body?.password||''),expected=process.env.QZENT_PASSWORD;
   if(input.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(input),Buffer.from(expected)))return res.status(401).json({error:'Senha incorreta.'});
   const expires=String(Date.now()+8*60*60*1000);
   res.setHeader('Set-Cookie','qzent_session='+expires+'.'+sign(expires)+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800');
   return res.json({ok:true});
  }
  if(req.method==='POST'&&req.query.action==='logout'){
   res.setHeader('Set-Cookie','qzent_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
   return res.json({ok:true});
  }
  if(req.method==='GET'){
   if(!authorized(req))return res.status(401).json({error:'Entre com a senha do entrevistador.'});
   const rows=[];let cursor;
   do{
    const page=await list({prefix,limit:1000,cursor});
    for(let i=0;i<page.blobs.length;i+=10)rows.push(...await Promise.all(page.blobs.slice(i,i+10).map(b=>read(b.pathname))));
    cursor=page.hasMore?page.cursor:undefined;
   }while(cursor);
   return res.json({rows:rows.filter(row=>row&&!row.deleted)});
  }
  if(req.method==='DELETE'){
   if(!authorized(req))return res.status(401).json({error:'Acesso necessário.'});
   const id=String(req.query.id||'');
   if(!/^[a-zA-Z0-9_-]{1,100}$/.test(id))return res.status(400).json({error:'Registro inválido.'});
   await put(prefix+id+'.json',JSON.stringify({deleted:true}),{access:'private',addRandomSuffix:false,allowOverwrite:true,contentType:'application/json'});return res.json({ok:true});
  }
  if(req.method==='POST'){
   if(JSON.stringify(req.body).length>150000)return res.status(413).json({error:'Formulário muito grande.'});
   let data;try {data=validate(req.body,req.body.legacy===true&&authorized(req));}catch(err){return res.status(400).json({error:err.message});}
   const path=prefix+data.record.id+'.json';
   const existing=await read(path);
   if(existing)return res.json({ok:true,id:data.record.id,deleted:!!existing.deleted});
   await put(path,JSON.stringify({...data,receivedAt:Date.now()}),{access:'private',addRandomSuffix:false,contentType:'application/json'});
   return res.status(201).json({ok:true,id:data.record.id});
  }
  res.setHeader('Allow','GET, POST, DELETE');return res.status(405).json({error:'Método não permitido.'});
 }catch(error){console.error('Research API:',error.message);return res.status(500).json({error:'Não foi possível acessar as pesquisas. Tente novamente.'});}
};
