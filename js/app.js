/* UI layer: renders the steps produced by buildSteps() from aes.js. */


const $=s=>document.querySelector(s);
const H=b=>b.toString(16).toUpperCase().padStart(2,'0');
const bin=b=>b.toString(2).padStart(8,'0');
const OPNAME={input:'Load state',sub:'SubBytes',shift:'ShiftRows',mix:'MixColumns',ark:'AddRoundKey'};
const DESC={
  input:'The 16 plaintext bytes fill a 4×4 grid called the state, one column at a time, top to bottom.',
  ark0:'Round 0 only does one thing: XOR every state byte with the matching byte of the cipher key.',
  sub:'Every byte is swapped for its value in the S-box lookup table. This is the only non-linear step, and it is what makes AES hard to attack with algebra.',
  shift:'Row 0 stays put. Row 1 rotates left by 1 byte, row 2 by 2, row 3 by 3. Colours show which column each byte started in.',
  mix:'Each column is multiplied by a fixed matrix in GF(2⁸). Every output byte depends on all four bytes of its column. The last round skips this step.',
  ark:'The round key from the key schedule is XORed into the state.'
};

const S={mode:'text',steps:[],w:[],idx:0,sel:0,timer:null,pt:[],key:[],animate:false};

function parseField(val,mode,label){
  if(mode==='hex'){
    const h=val.replace(/0x|[\s:,-]/gi,'');
    if(!/^[0-9a-f]{32}$/i.test(h)) throw new Error(label+' needs exactly 32 hex digits (16 bytes). You have '+h.length+'.');
    return {bytes:h.match(/../g).map(x=>parseInt(x,16)),note:''};
  }
  const enc=new TextEncoder().encode(val);
  let note='';
  if(enc.length>16) note=label+' was cut to its first 16 bytes.';
  else if(enc.length<16) note=label+' was padded with zero bytes up to 16.';
  const b=new Array(16).fill(0);
  enc.slice(0,16).forEach((x,i)=>b[i]=x);
  return {bytes:b,note};
}

function recompute(keepStep){
  const msg=$('#msg');
  try{
    const a=parseField($('#pt').value,S.mode,'Plaintext');
    const k=parseField($('#key').value,S.mode,'Key');
    S.pt=a.bytes;S.key=k.bytes;
    const res=buildSteps(a.bytes,k.bytes);
    S.steps=res.steps;S.w=res.w;
    if(!keepStep) S.idx=0;
    S.idx=Math.min(S.idx,S.steps.length-1);
    msg.className='';msg.textContent=[a.note,k.note].filter(Boolean).join(' ');
    $('#scrub').max=S.steps.length-1;
    render();
  }catch(e){
    msg.className='err';msg.textContent=e.message;
  }
}

function setMode(m){
  const cur={pt:S.pt,key:S.key};
  S.mode=m;
  document.querySelectorAll('.seg button').forEach(b=>b.classList.toggle('on',b.dataset.mode===m));
  if(m==='hex'){
    $('#pt').value=cur.pt.map(H).join(' ');
    $('#key').value=cur.key.map(H).join(' ');
  }else{
    const ok=a=>a.every(b=>b>=32&&b<127);
    if(ok(cur.pt)&&ok(cur.key)){
      $('#pt').value=String.fromCharCode(...cur.pt);
      $('#key').value=String.fromCharCode(...cur.key);
    }else{
      $('#pt').value='Two One Nine Two';$('#key').value='Thats my Kung Fu';
    }
  }
  recompute(true);
}

function stepTitle(st){
  return st.op==='input'?'Load the state':'Round '+st.round+': '+OPNAME[st.op];
}

function matrixHTML(bytes,o={}){
  const {from=null,tint=null,keym=false,sel=true}=o;
  let h='<div class="mx'+(tint?' tint':'')+(keym?' keym':'')+'">';
  for(let r=0;r<4;r++)for(let c=0;c<4;c++){
    const i=c*4+r;
    const ch=from&&from[i]!==bytes[i];
    const st=tint?' style="--o:var(--c'+tint(i)+')"':'';
    h+='<button type="button" class="cell'+(ch?' changed':'')+(sel&&S.sel===i?' sel':'')+'" data-i="'+i+'"'+st+' aria-label="Row '+r+', column '+c+': '+H(bytes[i])+'">'+H(bytes[i])+'</button>';
  }
  return h+'</div>';
}

function renderStage(st){
  const op=st.op;
  let h='<h2>'+stepTitle(st)+'</h2><p class="desc">'+(op==='ark'&&st.round===0?DESC.ark0:DESC[op])+'</p>';
  h+='<div class="stage'+(S.animate?' pop':'')+'">';
  if(op==='input'){
    h+='<div class="blk"><div class="strip">'+st.before.map((b,i)=>'<span>'+H(b)+'<small>'+i+'</small></span>').join('')+'</div><div class="cap">Plaintext bytes</div></div>';
    h+='<div class="opmark"><i>→</i><span>fill columns</span></div>';
    h+='<div class="blk">'+matrixHTML(st.after,{tint:i=>i>>2})+'<div class="cap">State</div></div>';
  }else if(op==='ark'){
    h+='<div class="blk">'+matrixHTML(st.before)+'<div class="cap">State</div></div>';
    h+='<div class="sym">⊕</div>';
    h+='<div class="blk">'+matrixHTML(st.key,{keym:true})+'<div class="cap">Round key '+st.round+'</div></div>';
    h+='<div class="sym">=</div>';
    h+='<div class="blk">'+matrixHTML(st.after,{from:st.before})+'<div class="cap">New state</div></div>';
  }else{
    const tb=op==='shift'?{tint:i=>i>>2}:{};
    const ta=op==='shift'?{tint:i=>(((i>>2)+(i&3))%4)}:{};
    h+='<div class="blk">'+matrixHTML(st.before,tb)+'<div class="cap">Before</div></div>';
    h+='<div class="opmark"><i>→</i><span>'+OPNAME[op]+'</span></div>';
    h+='<div class="blk">'+matrixHTML(st.after,Object.assign({from:st.before},ta))+'<div class="cap">After</div></div>';
  }
  h+='</div>';
  if(op!=='input') h+='<p class="hint">Click a byte to inspect it below.</p>';
  $('#stage').innerHTML=h;
}

function renderDetail(st){
  const el=$('#detail');
  const op=st.op;
  if(op==='input'){el.style.display='none';return}
  el.style.display='';
  let h='';
  const i=S.sel,c=i>>2,r=i&3;
  if(op==='sub'){
    const used=new Set(st.before),sb=st.before[i];
    h+='<h3>The S-box lookup table</h3><div class="sboxwrap"><div class="sbox"><div></div>';
    for(let k=0;k<16;k++) h+='<div class="hd">'+k.toString(16).toUpperCase()+'</div>';
    for(let a=0;a<16;a++){
      h+='<div class="hd">'+a.toString(16).toUpperCase()+'</div>';
      for(let b=0;b<16;b++){
        const idx=a*16+b;
        h+='<div class="sb'+(idx===sb?' sel':used.has(idx)?' used':'')+'">'+H(SBOX[idx])+'</div>';
      }
    }
    h+='</div></div>';
    h+='<p class="read">Byte (row '+r+', col '+c+') = <b>'+H(sb)+'</b> → S-box row <b>'+(sb>>4).toString(16).toUpperCase()+'</b>, column <b>'+(sb&15).toString(16).toUpperCase()+'</b> → <b>'+H(SBOX[sb])+'</b></p>';
    h+='<p class="hint" style="text-align:left">Blue cells are the table entries this step looked up. The S-box is built from the multiplicative inverse in GF(2⁸) followed by an affine transform.</p>';
  }else if(op==='shift'){
    h+='<h3>Row by row</h3><div class="rowmap">';
    for(let a=0;a<4;a++){
      const bf=[0,1,2,3].map(cc=>H(st.before[cc*4+a])).join(' ');
      const af=[0,1,2,3].map(cc=>H(st.after[cc*4+a])).join(' ');
      h+='<div>Row '+a+': '+bf+' → '+af+'  <span style="color:var(--muted)">('+(a?'left by '+a:'no shift')+')</span></div>';
    }
    h+='</div>';
  }else if(op==='mix'){
    const a=st.before.slice(4*c,4*c+4);
    h+='<h3>Column '+c+' times the fixed matrix</h3><div class="eqs">';
    for(let row=0;row<4;row++){
      h+='<div class="eq">'+MIX[row].map((m,j)=>'<span class="term">'+H(m)+'·'+H(a[j])+' <small>= '+H(gmul(a[j],m))+'</small></span>').join('<span>⊕</span>')+'<span>=</span><span class="res">'+H(st.after[4*c+row])+'</span></div>';
    }
    h+='</div><p class="hint" style="text-align:left">Multiplying by 01 keeps the byte, by 02 shifts left and conditionally XORs 1B, and by 03 is 02 XOR the byte. Click a byte in another column to see that column.</p>';
  }else if(op==='ark'){
    const b=st.before[i],k=st.key[i],o=st.after[i];
    h+='<h3>XOR on one byte (row '+r+', col '+c+')</h3><pre class="bits">'+bin(b)+'   state  '+H(b)+'\n'+bin(k)+'   key    '+H(k)+'\n--------   XOR\n'+bin(o)+'   result '+H(o)+'</pre>';
    h+='<p class="hint" style="text-align:left">A bit in the result is 1 only where exactly one of the two inputs has a 1.</p>';
  }
  el.innerHTML=h;
}

function renderSched(st){
  const w=S.w,rd=st.round;
  let h='<div class="ksplit"><div><h3>Round keys</h3>';
  for(let r=0;r<=10;r++){
    h+='<div class="krow'+(r===rd?' cur':'')+'"><span class="kr">'+(r===0?'key':r)+'</span>';
    for(let k=0;k<4;k++) h+='<span>'+w[4*r+k].map(H).join(' ')+'</span>';
    h+='</div>';
  }
  h+='</div><div><h3>'+(rd===0?'Round 0 key':'How round key '+rd+' is made')+'</h3>';
  if(rd===0){
    h+='<p class="desc" style="margin:0">Round 0 uses the cipher key as it is. Every later round key grows from the one before it.</p>';
  }else{
    const i=4*rd,prev=w[i-1],rot=[prev[1],prev[2],prev[3],prev[0]],sub=rot.map(b=>SBOX[b]);
    const rc=[RCON[rd],0,0,0],x=sub.map((b,j)=>b^rc[j]);
    h+='<dl class="g">'
      +'<dt>Last word</dt><dd>'+prev.map(H).join(' ')+'</dd>'
      +'<dt>RotWord</dt><dd>'+rot.map(H).join(' ')+'</dd>'
      +'<dt>SubWord</dt><dd>'+sub.map(H).join(' ')+'</dd>'
      +'<dt>⊕ Rcon</dt><dd>'+rc.map(H).join(' ')+'</dd>'
      +'<dt>= g</dt><dd>'+x.map(H).join(' ')+'</dd>'
      +'<dt>⊕ word 4 back</dt><dd>'+w[i-4].map(H).join(' ')+'</dd>'
      +'<dt>First word</dt><dd class="out">'+w[i].map(H).join(' ')+'</dd></dl>';
    h+='<p class="desc" style="margin:10px 0 0">The other three words are each the previous word XOR the word four places back.</p>';
  }
  h+='</div></div>';
  $('#sched').innerHTML=h;
}

function renderNav(st){
  const last=S.steps.length-1;
  // round buttons
  let h='<b>Round</b>';
  for(let r=0;r<=10;r++) h+='<button type="button" class="rnd'+(r===st.round?' cur':r<st.round?' done':'')+'" data-round="'+r+'" aria-label="Round '+r+'">'+r+'</button>';
  $('#rounds').innerHTML=h;
  // ops for current round
  let o='';
  S.steps.forEach((s,i)=>{if(s.round===st.round) o+='<button type="button" class="op'+(i===S.idx?' cur':'')+'" data-step="'+i+'">'+OPNAME[s.op]+'</button>'});
  $('#ops').innerHTML=o;
  $('#scrub').value=S.idx;
  $('#count').textContent='Step '+S.idx+' / '+last;
  $('#bBack').disabled=S.idx===0;$('#bStart').disabled=S.idx===0;
  $('#bNext').disabled=S.idx===last;$('#bEnd').disabled=S.idx===last;
  $('#bPlay').textContent=S.timer?'Pause':'Play';
}

function renderHex(){
  $('#hPt').textContent=S.pt.map(H).join(' ');
  $('#hKey').textContent=S.key.map(H).join(' ');
  const ct=S.steps[S.steps.length-1].after;
  $('#hCt').textContent=ct.map(H).join(' ');
}

function render(){
  const st=S.steps[S.idx];
  renderHex();renderNav(st);renderStage(st);renderDetail(st);renderSched(st);
  S.animate=false;
}

function go(i,anim=true){
  S.idx=Math.max(0,Math.min(S.steps.length-1,i));
  S.animate=anim;
  if(S.idx===S.steps.length-1) stop();
  render();
}
function stop(){if(S.timer){clearInterval(S.timer);S.timer=null}}
function togglePlay(){
  if(S.timer){stop();render();return}
  if(S.idx>=S.steps.length-1) S.idx=0;
  S.timer=setInterval(()=>go(S.idx+1),900);
  go(S.idx+1);
}

// events
document.querySelectorAll('.seg button').forEach(b=>b.addEventListener('click',()=>{if(S.mode!==b.dataset.mode)setMode(b.dataset.mode)}));
$('#pt').addEventListener('input',()=>{stop();recompute(true)});
$('#key').addEventListener('input',()=>{stop();recompute(true)});
$('#exText').addEventListener('click',()=>{stop();S.mode='text';document.querySelectorAll('.seg button').forEach(b=>b.classList.toggle('on',b.dataset.mode==='text'));$('#pt').value='Two One Nine Two';$('#key').value='Thats my Kung Fu';recompute(false)});
$('#exFips').addEventListener('click',()=>{stop();S.mode='hex';document.querySelectorAll('.seg button').forEach(b=>b.classList.toggle('on',b.dataset.mode==='hex'));$('#pt').value='32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34';$('#key').value='2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c';recompute(false)});
$('#bStart').addEventListener('click',()=>{stop();go(0)});
$('#bBack').addEventListener('click',()=>{stop();go(S.idx-1)});
$('#bNext').addEventListener('click',()=>{stop();go(S.idx+1)});
$('#bEnd').addEventListener('click',()=>{stop();go(S.steps.length-1)});
$('#bPlay').addEventListener('click',togglePlay);
$('#scrub').addEventListener('input',e=>{stop();go(+e.target.value)});
$('#rounds').addEventListener('click',e=>{
  const b=e.target.closest('[data-round]');if(!b)return;
  stop();go(S.steps.findIndex(s=>s.round===+b.dataset.round));
});
$('#ops').addEventListener('click',e=>{const b=e.target.closest('[data-step]');if(b){stop();go(+b.dataset.step)}});
$('#stage').addEventListener('click',e=>{
  const c=e.target.closest('.cell');if(!c)return;
  S.sel=+c.dataset.i;S.animate=false;render();
});
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT'&&e.target.type==='text')return;
  if(e.key==='ArrowRight'){stop();go(S.idx+1)}
  else if(e.key==='ArrowLeft'){stop();go(S.idx-1)}
});

// start
$('#pt').value='Two One Nine Two';
$('#key').value='Thats my Kung Fu';
recompute(false);
