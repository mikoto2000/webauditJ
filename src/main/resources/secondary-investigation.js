/* Offline generation only. No directory access, LLM calls, fetch or log execution. */
(function(root){
 'use strict';
 function validatePaths(p){
  const norm=value=>{
   if(typeof value!=='string'||!value.trim()||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value))throw Error('Invalid directory / ディレクトリを確認してください');
   const v=value.trim().replace(/\\/g,'/'),prefix=/^[a-z]:/i.test(v)?v.slice(0,2).toLowerCase():v.startsWith('/')?'/':'';
   const parts=[];for(const s of v.replace(/^[a-z]:/i,'').split('/')){if(!s||s==='.')continue;if(s==='..'&&parts.length&&parts.at(-1)!=='..')parts.pop();else if(s==='..'&&!prefix)parts.push(s);else if(s!=='..')parts.push(s);}
   const result=(prefix?prefix.replace(/\/$/,'')+'/':'')+parts.join('/');return result==='/'?'/':(result||'.').replace(/\/$/,'').toLowerCase();
  };
  const a=norm(p.primary),b=norm(p.additional),o=norm(p.output);
  const inside=(x,y)=>x===y||x.startsWith(y+'/')||y==='/'&&x.startsWith('/')||y==='.'&&!x.startsWith('../')&&!x.startsWith('/')&&!/^[a-z]:\//i.test(x);
  if(o==='/'||/^[a-z]:$/i.test(o)||inside(o,a)||inside(a,o)||inside(o,b)||inside(b,o))throw Error('Separate output from inputs / 出力先を入力と重ならない場所にしてください');
 }
 function render(plan,ids,paths){
  validatePaths(paths);const wanted=new Set(ids);
  if(!wanted.size)throw Error('Select at least one target / 対象を選択してください');
  const parts=[];for(const c of plan.cases){if(wanted.has(c.id)){parts.push(c.prompt_section);wanted.delete(c.id);}}
  if(wanted.size)throw Error('Unknown case / 不明な事案です');
  const escaped=JSON.stringify(paths,null,2).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
  return plan.prompt_prefix+'```json\n'+escaped+'\n```\n\n'+parts.join('')+plan.prompt_suffix+'\n'+plan.template_version+' / '+plan.version+' / '+plan.risk_rules_version+'\n';
 }
 const api={render,validatePaths};if(typeof module!=='undefined'&&module.exports){module.exports=api;return;}root.WebAuditPrompt=api;
 const plan=root.WebAuditSecondaryPlan,$=id=>document.getElementById(id);
 const boxes=[...document.querySelectorAll('input[name="secondary-case"]')];
 const l=(ja,en)=>plan.language==='en'?en:ja;
 function update(){
  const ids=boxes.filter(b=>b.checked).map(b=>b.value);$('secondary-materials').replaceChildren();
  for(const c of plan.cases.filter(c=>ids.includes(c.id))){const p=document.createElement('p');p.textContent=c.id+': '+c.required_materials.join(' / ');$('secondary-materials').appendChild(p);}
  try{$('secondary-prompt').value=render(plan,ids,{primary:$('secondary-primary').value,additional:$('secondary-additional').value,output:$('secondary-output').value});$('secondary-copy').disabled=$('secondary-save').disabled=false;$('secondary-status').textContent=l('依頼文を生成しました。調査・送信は行っていません。','Request generated. No investigation or transmission performed.');}
  catch(e){$('secondary-prompt').value='';$('secondary-copy').disabled=$('secondary-save').disabled=true;$('secondary-status').textContent=e.message;}
 }
 for(const b of boxes)b.addEventListener('change',update);
 for(const id of ['secondary-primary','secondary-additional','secondary-output'])$(id).addEventListener('input',update);
 for(const [id,mode] of [['secondary-all','all'],['secondary-priority','priority'],['secondary-none','none']])$(id).onclick=()=>{boxes.forEach(b=>b.checked=mode==='all'||mode==='priority'&&plan.cases.some(c=>c.id===b.value&&c.priority==='high'));update();};
 document.addEventListener('click',e=>{const b=e.target.closest('button[data-secondary-case]');if(!b)return;boxes.forEach(x=>x.checked=x.value===b.dataset.secondaryCase);update();location.hash='secondary-investigation';$('secondary-investigation').scrollIntoView();});
 $('secondary-copy').onclick=async()=>{try{if(!navigator.clipboard?.writeText)throw Error();await navigator.clipboard.writeText($('secondary-prompt').value);$('secondary-status').textContent=l('コピーしました。','Copied.');}catch{$('secondary-prompt').focus();$('secondary-prompt').select();$('secondary-status').textContent=l('本文を選択しました。Ctrl+C / Command+Cでコピーしてください。','Text selected. Copy with Ctrl+C / Command+C.');}};
 $('secondary-save').onclick=()=>{const u=URL.createObjectURL(new Blob([$('secondary-prompt').value],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=u;a.download='secondary-investigation-selected.md';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000);};
 update();
})(typeof globalThis!=='undefined'?globalThis:this);
