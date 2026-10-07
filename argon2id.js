/*
 * SFE 2.0 - Argon2id RFC 9106 implementation.
 * Pure JavaScript fallback designed for a fully offline, double-clickable build.
 * Uses BigInt for exact 64-bit arithmetic. Slower than WASM, but self-contained.
 */
(function () {
'use strict';
const MASK64 = 0xffffffffffffffffn;
const MASK32 = 0xffffffffn;
const BLOCK_WORDS = 128;
const BLOCK_U32 = 256;
const SYNC = 4;
const TYPE_ID = 2;
const enc = new TextEncoder();
function le32(n){const a=new Uint8Array(4);new DataView(a.buffer).setUint32(0,n>>>0,true);return a;}
function le64(n){const a=new Uint8Array(8);let x=BigInt.asUintN(64,n);for(let i=0;i<8;i++){a[i]=Number(x&255n);x>>=8n;}return a;}
function read64(a,o){let x=0n;for(let i=7;i>=0;i--)x=(x<<8n)|BigInt(a[o+i]);return x;}
function rotr(x,n){x&=MASK64;return ((x>>BigInt(n))|(x<<BigInt(64-n)))&MASK64;}
function add(x,y){return (x+y)&MASK64;}
function xor(a,b){return (a^b)&MASK64;}
const IV=[0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];
const SIGMA=[
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
];
function b2G(v,a,b,c,d,x,y,m){v[a]=add(v[a],add(v[b],m[x]));v[d]=rotr(xor(v[d],v[a]),32);v[c]=add(v[c],v[d]);v[b]=rotr(xor(v[b],v[c]),24);v[a]=add(v[a],add(v[b],m[y]));v[d]=rotr(xor(v[d],v[a]),16);v[c]=add(v[c],v[d]);v[b]=rotr(xor(v[b],v[c]),63);}
function b2Compress(h,block,off,final,dlen){let v=new Array(16);for(let i=0;i<8;i++)v[i]=h[i];for(let i=0;i<8;i++)v[i+8]=IV[i];v[12]^=BigInt(dlen);if(final)v[14]^=MASK64;let m=new Array(16);for(let i=0;i<16;i++)m[i]=read64(block,off+i*8);for(let r=0;r<12;r++){let s=SIGMA[r];b2G(v,0,4,8,12,s[0],s[1],m);b2G(v,1,5,9,13,s[2],s[3],m);b2G(v,2,6,10,14,s[4],s[5],m);b2G(v,3,7,11,15,s[6],s[7],m);b2G(v,0,5,10,15,s[8],s[9],m);b2G(v,1,6,11,12,s[10],s[11],m);b2G(v,2,7,8,13,s[12],s[13],m);b2G(v,3,4,9,14,s[14],s[15],m);}for(let i=0;i<8;i++)h[i]=(h[i]^v[i]^v[i+8])&MASK64;}
function blake2b(input,outLen=64){let h=IV.slice();h[0]^=0x01010000n^BigInt(outLen);let data=input instanceof Uint8Array?input:new Uint8Array(input);let full=Math.floor(data.length/128),pos=0;for(let i=0;i<full;i++){b2Compress(h,data,pos,false,128*(i+1));pos+=128;}let last=new Uint8Array(128);last.set(data.subarray(pos));b2Compress(h,last,0,true,data.length);let out=new Uint8Array(64);for(let i=0;i<8;i++)out.set(le64(h[i]),i*8);return out.subarray(0,outLen);}
function concat(...xs){let n=xs.reduce((s,x)=>s+x.length,0),o=new Uint8Array(n),p=0;for(const x of xs){o.set(x,p);p+=x.length;}return o;}
function Hprime(input,outLen){const prefix=le32(outLen);if(outLen<=64)return blake2b(concat(prefix,input),outLen);let out=new Uint8Array(outLen);let v=blake2b(concat(prefix,input),64);let pos=0;out.set(v.subarray(0,32),pos);pos+=32;while(outLen-pos>64){v=blake2b(v,64);out.set(v.subarray(0,32),pos);pos+=32;}v=blake2b(v,outLen-pos);out.set(v,pos);return out;}
function bytesToU32(bytes){const a=new Uint32Array(bytes.length>>>2);const dv=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);for(let i=0;i<a.length;i++)a[i]=dv.getUint32(i*4,true);return a;}
const A2_BUF=new Uint32Array(256);
function AG(a,b,c,d){let Al=A2_BUF[2*a],Ah=A2_BUF[2*a+1],Bl=A2_BUF[2*b],Bh=A2_BUF[2*b+1],Cl=A2_BUF[2*c],Ch=A2_BUF[2*c+1],Dl=A2_BUF[2*d],Dh=A2_BUF[2*d+1];let ml,mh,rl,xh,xl;
ml=Math.imul(Al,Bl);mh=(((Al>>>0)*(Bl>>>0)-(ml>>>0))/0x100000000+0.5)|0;rl=(Al>>>0)+(Bl>>>0)+((ml<<1)>>>0);Ah=(Ah+Bh+((mh<<1)|(ml>>>31))+((rl/0x100000000)|0))|0;Al=rl|0;xh=Dh^Ah;xl=Dl^Al;Dh=xl;Dl=xh;
ml=Math.imul(Cl,Dl);mh=(((Cl>>>0)*(Dl>>>0)-(ml>>>0))/0x100000000+0.5)|0;rl=(Cl>>>0)+(Dl>>>0)+((ml<<1)>>>0);Ch=(Ch+Dh+((mh<<1)|(ml>>>31))+((rl/0x100000000)|0))|0;Cl=rl|0;xh=Bh^Ch;xl=Bl^Cl;Bh=(xh>>>24)|(xl<<8);Bl=(xh<<8)|(xl>>>24);
ml=Math.imul(Al,Bl);mh=(((Al>>>0)*(Bl>>>0)-(ml>>>0))/0x100000000+0.5)|0;rl=(Al>>>0)+(Bl>>>0)+((ml<<1)>>>0);Ah=(Ah+Bh+((mh<<1)|(ml>>>31))+((rl/0x100000000)|0))|0;Al=rl|0;xh=Dh^Ah;xl=Dl^Al;Dh=(xh>>>16)|(xl<<16);Dl=(xh<<16)|(xl>>>16);
ml=Math.imul(Cl,Dl);mh=(((Cl>>>0)*(Dl>>>0)-(ml>>>0))/0x100000000+0.5)|0;rl=(Cl>>>0)+(Dl>>>0)+((ml<<1)>>>0);Ch=(Ch+Dh+((mh<<1)|(ml>>>31))+((rl/0x100000000)|0))|0;Cl=rl|0;xh=Bh^Ch;xl=Bl^Cl;Bh=(xh<<1)|(xl>>>31);Bl=(xh>>>31)|(xl<<1);
A2_BUF[2*a]=Al;A2_BUF[2*a+1]=Ah;A2_BUF[2*b]=Bl;A2_BUF[2*b+1]=Bh;A2_BUF[2*c]=Cl;A2_BUF[2*c+1]=Ch;A2_BUF[2*d]=Dl;A2_BUF[2*d+1]=Dh;}
function AP(...v){AG(v[0],v[4],v[8],v[12]);AG(v[1],v[5],v[9],v[13]);AG(v[2],v[6],v[10],v[14]);AG(v[3],v[7],v[11],v[15]);AG(v[0],v[5],v[10],v[15]);AG(v[1],v[6],v[11],v[12]);AG(v[2],v[7],v[8],v[13]);AG(v[3],v[4],v[9],v[14]);}
function ablock(x,xp,yp,op,xorOld){for(let i=0;i<256;i++){const r=x[xp+i]^x[yp+i];A2_BUF[i]=r;if(xorOld)x[op+i]^=r;else x[op+i]=r;}for(let i=0;i<128;i+=16)AP(i,i+1,i+2,i+3,i+4,i+5,i+6,i+7,i+8,i+9,i+10,i+11,i+12,i+13,i+14,i+15);for(let i=0;i<16;i+=2)AP(i,i+1,i+16,i+17,i+32,i+33,i+48,i+49,i+64,i+65,i+80,i+81,i+96,i+97,i+112,i+113);for(let i=0;i<256;i++)x[op+i]^=A2_BUF[i];}
function indexAlpha2(r,s,laneLen,segmentLen,index,randL,sameLane){let area;if(r===0){if(s===0)area=index-1;else if(sameLane)area=s*segmentLen+index-1;else area=s*segmentLen+(index===0?-1:0);}else if(sameLane)area=laneLen-segmentLen+index-1;else area=laneLen-segmentLen+(index===0?-1:0);const start=r!==0&&s!==3?(s+1)*segmentLen:0;const low=Math.imul(randL,randL);const high=(((randL>>>0)*(randL>>>0)-(low>>>0))/0x100000000+0.5)|0;const alow=Math.imul(area,high);const ahigh=(((area>>>0)*(high>>>0)-(alow>>>0))/0x100000000+0.5)|0;return (start+area-1-ahigh)%laneLen;}
function initialHash2(password,salt,p,t,m,secret,ad){const pb=typeof password==='string'?enc.encode(password):password;const sb=salt;return blake2b(concat(le32(p),le32(32),le32(m),le32(t),le32(0x13),le32(TYPE_ID),le32(pb.length),pb,le32(sb.length),sb,le32(secret.length),secret,le32(ad.length),ad),64);}
function hpU32(inputBytes,outLen){return bytesToU32(Hprime(inputBytes,outLen));}
function argon2id(password,salt,opts,onProgress){const p=opts.p,m=opts.m,t=opts.t;const secret=opts.secret||new Uint8Array(0),ad=opts.ad||new Uint8Array(0);const H0=initialHash2(password,salt,p,t,m,secret,ad);const H0x=new Uint8Array(72);H0x.set(H0);const mP=4*p*Math.floor(m/(4*p));const laneLen=mP/p,seg=laneLen/4;const B=new Uint32Array(mP*256);for(let l=0;l<p;l++){H0x.set(le32(0),64);H0x.set(le32(l),68);B.set(hpU32(H0x,1024),256*(l*laneLen));H0x.set(le32(1),64);B.set(hpU32(H0x,1024),256*(l*laneLen+1));}let done=0,total=t*4*p*seg-2*p;for(let r=0;r<t;r++){const needXor=r!==0;for(let s=0;s<4;s++){const dataIndependent=(r===0&&s<2);for(let l=0;l<p;l++){const address=new Uint32Array(768);address[256]=r;address[258]=l;address[260]=s;address[262]=mP;address[264]=t;address[266]=TYPE_ID;address[268]=0;if(dataIndependent){address[268]=1;ablock(address,256,512,0,false);ablock(address,0,512,0,false);}let start=0;if(r===0&&s===0)start=2;let offset=l*laneLen+s*seg+start;for(let index=start;index<seg;index++,offset++){if(onProgress){done++;if(done%64===0||done===total)onProgress(done/total);}const prev=offset%laneLen?offset-1:offset+laneLen-1;let j1,j2;if(dataIndependent){const ai=index%128;j1=address[ai*2];j2=address[ai*2+1];if(ai===127&&index+1<seg){address[268]++;ablock(address,256,512,0,false);ablock(address,0,512,0,false);}}else{j1=B[prev*256];j2=B[prev*256+1];}const refLane=(r===0&&s===0)?l:(j2%p);const refPos=indexAlpha2(r,s,laneLen,seg,index,j1,refLane===l);const refBlock=refLane*laneLen+refPos;ablock(B,prev*256,refBlock*256,offset*256,needXor);}}}}return bytesToU32(new Uint8Array(Hprime(new Uint8Array(new Uint8Array(B.subarray((laneLen-1)*256,(laneLen)*256))),32)));}
// Correct final extraction: XOR last block of every lane, then H' to 32 bytes.
function derive2(password,salt,opts,onProgress){const p=opts.p,m=opts.m,t=opts.t,secret=opts.secret||new Uint8Array(0),ad=opts.ad||new Uint8Array(0);const H0=initialHash2(password,salt,p,t,m,secret,ad);const H0x=new Uint8Array(72);H0x.set(H0);const mP=4*p*Math.floor(m/(4*p)),laneLen=mP/p,seg=laneLen/4;const B=new Uint32Array(mP*256);for(let l=0;l<p;l++){H0x.set(le32(0),64);H0x.set(le32(l),68);B.set(hpU32(H0x,1024),256*(l*laneLen));H0x.set(le32(1),64);B.set(hpU32(H0x,1024),256*(l*laneLen+1));}let done=0,total=t*4*p*seg-2*p;for(let r=0;r<t;r++){const needXor=r!==0;for(let s=0;s<4;s++){const dataIndependent=(r===0&&s<2);for(let l=0;l<p;l++){const address=new Uint32Array(768);address[256]=r;address[258]=l;address[260]=s;address[262]=mP;address[264]=t;address[266]=TYPE_ID;address[268]=0;if(dataIndependent){address[268]=1;ablock(address,256,512,0,false);ablock(address,0,512,0,false);}let start=(r===0&&s===0)?2:0;let offset=l*laneLen+s*seg+start;for(let index=start;index<seg;index++,offset++){if(onProgress){done++;if(done%64===0||done===total)onProgress(done/total);}const prev=offset%laneLen?offset-1:offset+laneLen-1;let j1,j2;if(dataIndependent){const ai=index%128;j1=address[ai*2];j2=address[ai*2+1];if(ai===127&&index+1<seg){address[268]++;ablock(address,256,512,0,false);ablock(address,0,512,0,false);}}else{j1=B[prev*256];j2=B[prev*256+1];}const refLane=(r===0&&s===0)?l:(j2%p);const refPos=indexAlpha2(r,s,laneLen,seg,index,j1,refLane===l);const refBlock=refLane*laneLen+refPos;ablock(B,prev*256,refBlock*256,offset*256,needXor);}}}}const final=new Uint32Array(256);for(let l=0;l<p;l++){const pos=(l*laneLen+laneLen-1)*256;for(let i=0;i<256;i++)final[i]^=B[pos+i];}return new Uint8Array(Hprime(new Uint8Array(final.buffer),32));}
window.SFEArgon2id={derive:derive2};
})();

this.__a=window.SFEArgon2id.derive;