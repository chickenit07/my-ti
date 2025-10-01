// Toast
let toastEl, toast;
function initToast(){ toastEl = document.querySelector('.toast'); if (toastEl && window.bootstrap) toast = new bootstrap.Toast(toastEl, { delay: 2500 }); }
function showToast(message, ok=true){ if(!toastEl) initToast(); const t=document.getElementById('toast-title'); const b=document.getElementById('toast-body'); const i=toastEl.querySelector('.toast-header i'); if(t) t.textContent = ok?'Success':'Oops'; if(i) i.className = ok?'fas fa-check-circle me-2 text-success':'fas fa-exclamation-triangle me-2 text-danger'; if(b) b.textContent = message; if(toast) toast.show(); }

async function addTokens(event){
  event.preventDefault();
  const form = event.target; const fd = new FormData(); fd.append('security_answer', form.security_answer.value);
  try{
    const res = await fetch(window.APP_URLS.addTokens, { method:'POST', body: fd });
    const data = await res.json();
    if(data.success){ showToast(data.message, true); setTimeout(()=>{ window.location.href = window.APP_URLS.search; }, 1200); }
    else { showToast(data.message, false); }
  }catch(e){ console.error(e); showToast('An error occurred.', false); }
}

// Theme
function setTheme(){ document.documentElement.setAttribute('data-theme', 'dark'); document.body.setAttribute('data-theme', 'dark'); }

document.addEventListener('DOMContentLoaded', ()=>{ initToast(); setTheme('dark'); });

window.addTokens = addTokens;

