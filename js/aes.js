/* AES-128 core: pure functions, no DOM access.
 * State layout: index = column * 4 + row (column-major, as in FIPS-197).
 * Works as a classic <script> in the browser and as a CommonJS module in Node. */

const RCON=[0,1,2,4,8,0x10,0x20,0x40,0x80,0x1b,0x36];
const MIX=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]];
function xtime(a){return ((a<<1)^((a&0x80)?0x1b:0))&0xff}
function gmul(a,b){let p=0;while(b){if(b&1)p^=a;a=xtime(a);b>>=1}return p}
const SBOX=(()=>{
  const s=new Array(256);
  for(let x=0;x<256;x++){
    let inv=0;
    if(x){for(let y=1;y<256;y++){if(gmul(x,y)===1){inv=y;break}}}
    let r=inv;
    for(let k=1;k<=4;k++) r^=((inv<<k)|(inv>>(8-k)))&0xff;
    s[x]=r^0x63;
  }
  return s;
})();
// State layout: index = column*4 + row (column-major, as in FIPS-197)
function expandKey(key){
  const w=[];
  for(let i=0;i<4;i++) w.push(key.slice(4*i,4*i+4));
  for(let i=4;i<44;i++){
    let t=w[i-1].slice();
    if(i%4===0){
      t=[t[1],t[2],t[3],t[0]].map(b=>SBOX[b]);
      t[0]^=RCON[i/4];
    }
    w.push(w[i-4].map((b,j)=>b^t[j]));
  }
  return w;
}
function shiftRows(s){
  const o=new Array(16);
  for(let c=0;c<4;c++)for(let r=0;r<4;r++) o[c*4+r]=s[((c+r)%4)*4+r];
  return o;
}
function mixColumns(s){
  const o=new Array(16);
  for(let c=0;c<4;c++)for(let r=0;r<4;r++){
    let v=0;
    for(let j=0;j<4;j++) v^=gmul(s[c*4+j],MIX[r][j]);
    o[c*4+r]=v;
  }
  return o;
}
function buildSteps(pt,key){
  const w=expandKey(key);
  const rk=r=>[].concat(...w.slice(4*r,4*r+4));
  const steps=[];
  let s=pt.slice();
  steps.push({round:0,op:'input',before:s,after:s});
  const push=(round,op,after,extra)=>{steps.push(Object.assign({round,op,before:s,after},extra||{}));s=after};
  push(0,'ark',s.map((b,i)=>b^rk(0)[i]),{key:rk(0)});
  for(let r=1;r<=10;r++){
    push(r,'sub',s.map(b=>SBOX[b]));
    push(r,'shift',shiftRows(s));
    if(r<10) push(r,'mix',mixColumns(s));
    push(r,'ark',s.map((b,i)=>b^rk(r)[i]),{key:rk(r)});
  }
  return {steps,w};
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { RCON, MIX, SBOX, xtime, gmul, expandKey, shiftRows, mixColumns, buildSteps };
}
