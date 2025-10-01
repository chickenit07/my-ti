// Toast helpers
let toastEl, toast;
function initToast() {
  toastEl = document.querySelector('.toast');
  if (toastEl && window.bootstrap) toast = new bootstrap.Toast(toastEl, { delay: 2500 });
}
function showToastMessage(message, isSuccess = true) {
  if (!toastEl) initToast();
  const title = document.getElementById('toast-title');
  const body = document.getElementById('toast-body');
  const icon = toastEl.querySelector('.toast-header i');
  if (title) title.textContent = isSuccess ? 'Success' : 'Oops';
  if (icon) icon.className = isSuccess ? 'fas fa-check-circle me-2 text-success' : 'fas fa-exclamation-triangle me-2 text-danger';
  if (body) body.textContent = message; if (toast) toast.show();
}

// Theme
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.body.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  document.querySelectorAll('.theme-switcher .theme-icon').forEach(icon => {
    icon.classList.remove('active');
    if (icon.getAttribute('data-theme') === theme) icon.classList.add('active');
  });
}

function copyToClipboard(value, element) {
  document.querySelectorAll('.copyable-box.highlight').forEach(box => { box.classList.remove('highlight'); });
  const dummy = document.createElement('textarea'); document.body.appendChild(dummy); dummy.value = value; dummy.select(); document.execCommand('copy'); document.body.removeChild(dummy);
  showToastMessage('Copied to clipboard!', true); if (element) { element.classList.add('highlight'); }
}
function collect(selector) {
  const rows = document.querySelectorAll('tbody tr'); const values = [];
  rows.forEach(row => { const el = row.querySelector(selector); if (el) { values.push(el.textContent.trim()); }});
  return values.join('\r\n');
}
function copyAllDomains(){ 
  const values = collect('td:nth-child(3)');
  copyToClipboard(values);
  const count = values.split('\r\n').filter(v => v.trim()).length;
  showToastMessage(`Copied ${count} domains to clipboard!`, true);
}
function copyAllUsernames(){ 
  const values = collect('td:nth-child(4) .flex-grow-1');
  copyToClipboard(values);
  const count = values.split('\r\n').filter(v => v.trim()).length;
  showToastMessage(`Copied ${count} usernames to clipboard!`, true);
}
function copyAllPasswords(){ 
  const values = collect('td:nth-child(5) .flex-grow-1');
  copyToClipboard(values);
  const count = values.split('\r\n').filter(v => v.trim()).length;
  showToastMessage(`Copied ${count} passwords to clipboard!`, true);
}

function autoSelectCheckbox(textarea) {
  const row = textarea.closest('tr');
  const checkbox = row.querySelector('.item-checkbox');
  if (checkbox && !checkbox.checked) { checkbox.checked = true; updateSelectionCount(); }
}

function updateSelectionCount() {
  const selectedCheckboxes = document.querySelectorAll('.item-checkbox:checked');
  const saveBtn = document.querySelector('button[onclick="handleSaveButton()"]');
  const removeBtn = document.querySelector('button[onclick="removeSelectedItems()"]');
  if (selectedCheckboxes.length > 0) {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = `<i class="fas fa-save me-2"></i>Save (${selectedCheckboxes.length})`; }
    if (removeBtn) { removeBtn.disabled = false; removeBtn.innerHTML = `<i class="fas fa-trash me-2"></i>Remove (${selectedCheckboxes.length})`; }
  } else {
    if (saveBtn) { saveBtn.disabled = true; saveBtn.innerHTML = '<i class="fas fa-save me-2"></i>Save'; }
    if (removeBtn) { removeBtn.disabled = true; removeBtn.innerHTML = '<i class="fas fa-trash me-2"></i>Remove'; }
  }
}

function saveSelectedNotes() {
  const selectedCheckboxes = document.querySelectorAll('.item-checkbox:checked');
  if (selectedCheckboxes.length === 0) { showToastMessage('Please select records to save', false); return; }
  const updates = [];
  selectedCheckboxes.forEach(checkbox => { const itemId = checkbox.value; const textarea = document.querySelector(`textarea[data-item-id="${itemId}"]`); if (textarea) updates.push({ item_id: itemId, note: textarea.value }); });
  if (updates.length === 0) { showToastMessage('No notes to save', false); return; }
  fetch(window.APP_URLS.savedDetail, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `action=bulk_edit&updates=${encodeURIComponent(JSON.stringify(updates))}` })
    .then(r => r.json()).then(data => {
      if (data.success) { showToastMessage(`Successfully saved ${data.saved_count} notes!`, true); document.querySelectorAll('.item-checkbox:checked').forEach(cb => cb.checked = false); updateSelectionCount(); }
      else { showToastMessage('Failed to save notes: ' + data.error, false); }
    }).catch(() => showToastMessage('Failed to save notes', false));
}

function removeSelectedItems() {
  const selectedCheckboxes = document.querySelectorAll('.item-checkbox:checked');
  if (selectedCheckboxes.length === 0) { showToastMessage('Please select records to remove', false); return; }
  if (!confirm(`Are you sure you want to remove ${selectedCheckboxes.length} selected record(s)? This action cannot be undone.`)) return;
  const itemIds = Array.from(selectedCheckboxes).map(cb => cb.value);
  fetch(window.APP_URLS.savedDetail, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `action=bulk_delete&item_ids=${encodeURIComponent(JSON.stringify(itemIds))}` })
    .then(r => r.json()).then(data => {
      if (data.success) { selectedCheckboxes.forEach(cb => cb.closest('tr')?.remove()); const remaining = document.querySelectorAll('tbody tr'); if (remaining.length === 0) { const tbody = document.querySelector('tbody'); if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No records in this saved search.</td></tr>'; } showToastMessage(`Successfully removed ${data.removed_count} record(s)!`, true); updateSelectionCount(); }
      else { showToastMessage('Failed to remove records: ' + data.error, false); }
    }).catch(() => showToastMessage('Failed to remove records', false));
}

// Add, Import, Export functions
function showAddModal() {
  const modal = new bootstrap.Modal(document.getElementById('addRecordModal'));
  modal.show();
}

function showImportModal() {
  const modal = new bootstrap.Modal(document.getElementById('importModal'));
  modal.show();
}

function addRecord() {
  const domain = document.getElementById('addDomain').value.trim();
  const username = document.getElementById('addUsername').value.trim();
  const password = document.getElementById('addPassword').value.trim();
  const note = document.getElementById('addNote').value.trim();
  
  if (!domain || !username || !password) {
    showToastMessage('Domain, username, and password are required', false);
    return;
  }
  
  const data = { domain, username, password, note };
  
  fetch(`${window.APP_URLS.savedDetail}/add`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showToastMessage(data.message, true);
      bootstrap.Modal.getInstance(document.getElementById('addRecordModal')).hide();
      document.getElementById('addRecordForm').reset();
      // Reload page to show new record
      setTimeout(() => location.reload(), 1000);
    } else {
      showToastMessage(data.error, false);
    }
  })
  .catch(error => {
    showToastMessage('Failed to add record', false);
  });
}

function importCSV() {
  const fileInput = document.getElementById('csvFile');
  const file = fileInput.files[0];
  
  if (!file) {
    showToastMessage('Please select a CSV file', false);
    return;
  }
  
  const formData = new FormData();
  formData.append('file', file);
  
  fetch(`${window.APP_URLS.savedDetail}/import`, {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showToastMessage(data.message, true);
      bootstrap.Modal.getInstance(document.getElementById('importModal')).hide();
      fileInput.value = '';
      // Reload page to show imported records
      setTimeout(() => location.reload(), 1000);
    } else {
      showToastMessage(data.error, false);
    }
  })
  .catch(error => {
    showToastMessage('Failed to import CSV', false);
  });
}

function exportToCSV() {
  window.open(`${window.APP_URLS.savedDetail}/export`, '_blank');
  showToastMessage('Export started', true);
}

function downloadSampleCSV() {
  const csvContent = 'domain,username,password,note\nexample.com,user1,password123,Sample note 1\ntest.org,user2,pass456,Sample note 2\ndemo.net,admin,secret789,Admin account';
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sample_saved_records.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
  showToastMessage('Sample CSV downloaded', true);
}

function editRecord(id, domain, username, password, note) {
  // Populate the edit modal with current values
  document.getElementById('editRecordId').value = id;
  document.getElementById('editDomain').value = domain;
  document.getElementById('editUsername').value = username;
  document.getElementById('editPassword').value = password;
  document.getElementById('editNote').value = note;
  
  // Show the modal
  const modal = new bootstrap.Modal(document.getElementById('editRecordModal'));
  modal.show();
}

function handleSaveButton() {
  const selectedCheckboxes = document.querySelectorAll('.item-checkbox:checked');
  
  if (selectedCheckboxes.length === 0) {
    showToastMessage('Please select a record to edit', false);
    return;
  }
  
  if (selectedCheckboxes.length === 1) {
    // Single record selected - open edit modal
    const itemId = selectedCheckboxes[0].value;
    const row = selectedCheckboxes[0].closest('tr');
    
    // Extract data from the row
    const domain = row.querySelector('td:nth-child(3) .domain-link').textContent.trim();
    const username = row.querySelector('td:nth-child(4) .flex-grow-1').textContent.trim();
    const password = row.querySelector('td:nth-child(5) .flex-grow-1').textContent.trim();
    const note = row.querySelector('textarea[data-item-id="' + itemId + '"]').value;
    
    editRecord(itemId, domain, username, password, note);
  } else {
    // Multiple records selected - save notes as before
    saveSelectedNotes();
  }
}

function updateRecord() {
  const id = document.getElementById('editRecordId').value;
  const domain = document.getElementById('editDomain').value.trim();
  const username = document.getElementById('editUsername').value.trim();
  const password = document.getElementById('editPassword').value.trim();
  const note = document.getElementById('editNote').value.trim();
  
  if (!domain || !username || !password) {
    showToastMessage('Domain, username, and password are required', false);
    return;
  }
  
  // Create form data
  const formData = new FormData();
  formData.append('action', 'edit_full');
  formData.append('item_id', id);
  formData.append('domain', domain);
  formData.append('username', username);
  formData.append('password', password);
  formData.append('note', note);
  
  fetch(window.APP_URLS.savedDetail, {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showToastMessage('Record updated successfully!', true);
      bootstrap.Modal.getInstance(document.getElementById('editRecordModal')).hide();
      // Reload page to show updated record
      setTimeout(() => location.reload(), 1000);
    } else {
      showToastMessage('Failed to update record: ' + data.error, false);
    }
  })
  .catch(error => {
    showToastMessage('Failed to update record', false);
  });
}

function showRenameModal() {
  // Get current search name
  const currentName = document.getElementById('searchNameDisplay').textContent;
  document.getElementById('newSearchName').value = currentName;
  
  // Show the modal
  const modal = new bootstrap.Modal(document.getElementById('renameModal'));
  modal.show();
}

function updateSearchName() {
  const newName = document.getElementById('newSearchName').value.trim();
  
  if (!newName) {
    showToastMessage('Please enter a name', false);
    return;
  }
  
  // Create form data
  const formData = new FormData();
  formData.append('action', 'rename_search');
  formData.append('new_name', newName);
  
  fetch(window.APP_URLS.savedDetail, {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      showToastMessage('Saved record renamed successfully!', true);
      // Update the display name
      document.getElementById('searchNameDisplay').textContent = newName;
      bootstrap.Modal.getInstance(document.getElementById('renameModal')).hide();
    } else {
      showToastMessage('Failed to rename: ' + data.error, false);
    }
  })
  .catch(error => {
    showToastMessage('Failed to rename saved record', false);
  });
}

window.copyToClipboard = copyToClipboard;
window.copyAllDomains = copyAllDomains;
window.copyAllUsernames = copyAllUsernames;
window.copyAllPasswords = copyAllPasswords;
window.autoSelectCheckbox = autoSelectCheckbox;
window.updateSelectionCount = updateSelectionCount;
window.saveSelectedNotes = saveSelectedNotes;
window.removeSelectedItems = removeSelectedItems;
window.showAddModal = showAddModal;
window.showImportModal = showImportModal;
window.addRecord = addRecord;
window.importCSV = importCSV;
window.exportToCSV = exportToCSV;
window.downloadSampleCSV = downloadSampleCSV;

// Init handlers
document.addEventListener('DOMContentLoaded', () => {
  initToast();
  const savedTheme = localStorage.getItem('theme') || 'dark';
  setTheme(savedTheme);
  document.querySelectorAll('.theme-switcher .theme-icon').forEach(icon => {
    icon.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); setTheme(icon.getAttribute('data-theme')); });
  });
});

