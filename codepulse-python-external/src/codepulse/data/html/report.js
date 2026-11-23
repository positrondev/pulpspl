const q=s=>document.querySelector(s);function apply(){const sev=q('#sev').value,el=q('#el').value,
org=q('#org').value,t=q('#txt').value.toLowerCase();let n=0;document.querySelectorAll('.f').forEach(f=>{
const ok=(!sev||f.dataset.sev===sev)&&(!el||f.dataset.el===el)&&(!org||f.dataset.org===org)&&
(!t||f.textContent.toLowerCase().includes(t));f.hidden=!ok;n+=ok});q('#count').textContent=n+' shown'}
document.querySelectorAll('select,input').forEach(e=>e.addEventListener('input',apply));apply();
const dl=q('#dl');if(dl)dl.addEventListener('click',()=>{const b=atob(dl.dataset.csv),
a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);
const u=URL.createObjectURL(new Blob([a],{type:'text/csv;charset=utf-8'})),l=document.createElement('a');
l.href=u;l.download=(dl.dataset.name||'codepulse').replace(/[^\w.-]+/g,'_')+'-findings.csv';
document.body.appendChild(l);l.click();l.remove();URL.revokeObjectURL(u)});
