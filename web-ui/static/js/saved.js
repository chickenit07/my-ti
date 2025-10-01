// Toast
let toastEl, toast;
function initToast(){ toastEl = document.querySelector('.toast'); if (toastEl && window.bootstrap) toast = new bootstrap.Toast(toastEl, { delay: 2500 }); }
function showToastMessage(message, ok=true){ if(!toastEl) initToast(); const t=document.getElementById('toast-title'); const b=document.getElementById('toast-body'); const i=toastEl.querySelector('.toast-header i'); if(t) t.textContent = ok?'Success':'Oops'; if(i) i.className = ok?'fas fa-check-circle me-2 text-success':'fas fa-exclamation-triangle me-2 text-danger'; if(b) b.textContent = message; if(toast) toast.show(); }

function showCreateModal() {
  const modal = new bootstrap.Modal(document.getElementById('createModal'));
  modal.show();
}

function createSavedItem() {
  const name = document.getElementById('itemName').value.trim();
  
  if (!name) {
    showToastMessage('Please enter a name for the saved record', false);
    return;
  }
  
  fetch('/create_saved_record', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name: name
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showToastMessage(data.message, true);
      // Close modal
      const modal = bootstrap.Modal.getInstance(document.getElementById('createModal'));
      modal.hide();
      // Clear form
      document.getElementById('itemName').value = '';
      // Reload page to show new record
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    } else {
      showToastMessage('Error: ' + data.error, false);
    }
  })
  .catch(error => {
    console.error('Error:', error);
    showToastMessage('Error creating saved record', false);
  });
}

document.addEventListener('DOMContentLoaded', ()=>{ initToast(); });

