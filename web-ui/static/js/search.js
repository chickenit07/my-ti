// Theme init (runs early in head)
// Force dark theme globally
document.documentElement.setAttribute('data-theme', 'dark');
document.body.setAttribute('data-theme', 'dark');

// Toast helpers
let toastEl, toast;
function initToast() {
  toastEl = document.querySelector('.toast');
  if (toastEl && window.bootstrap) {
    toast = new bootstrap.Toast(toastEl, { delay: 2500 });
  }
}
function showToastMessage(message, isSuccess = true) {
  if (!toastEl) initToast();
  const title = document.getElementById('toast-title');
  const body = document.getElementById('toast-body');
  const icon = toastEl.querySelector('.toast-header i');
  if (title) title.textContent = isSuccess ? 'Success' : 'Oops';
  if (icon) icon.className = isSuccess ? 'fas fa-check-circle me-2 text-success' : 'fas fa-exclamation-triangle me-2 text-danger';
  if (body) body.textContent = message;
  if (toast) toast.show();
}

// Toggle Search button active style based on inputs
function updateSearchButtonState() {
  const domain = document.getElementById('domain')?.value.trim() || '';
  const username = document.getElementById('username')?.value.trim() || '';
  const btn = document.querySelector('form.search-form button[type="submit"]');
  if (!btn) return;
  // If both empty -> inactive style; else active
  if (domain === '' && username === '') {
    btn.classList.add('is-inactive');
  } else {
    btn.classList.remove('is-inactive');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  updateSearchButtonState();
  const domainInput = document.getElementById('domain');
  const usernameInput = document.getElementById('username');
  if (domainInput) domainInput.addEventListener('input', updateSearchButtonState);
  if (usernameInput) usernameInput.addEventListener('input', updateSearchButtonState);

  // Prevent submitting empty search
  const searchForm = document.querySelector('form.search-form');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      const domain = domainInput?.value.trim() || '';
      const username = usernameInput?.value.trim() || '';
      if (domain === '' && username === '') {
        e.preventDefault();
        showToastMessage('Please enter a domain or username to search.', false);
        (domainInput || usernameInput)?.focus();
      }
    });
  }
});

function copyToClipboard(value, element) {
  document.querySelectorAll('.copyable-box.highlight').forEach(box => { box.classList.remove('highlight'); });
  const dummy = document.createElement('textarea');
  document.body.appendChild(dummy);
  dummy.value = value;
  dummy.select();
  document.execCommand('copy');
  document.body.removeChild(dummy);
  showToastMessage('Copied to clipboard!', true);
  if (element) { element.classList.add('highlight'); }
}

function copyAllDomains() {
  document.querySelectorAll('.copyable-box.highlight').forEach(box => { box.classList.remove('highlight'); });
  
  const rows = document.querySelectorAll('tbody tr');
  const domains = [];
  rows.forEach(row => {
    const domainCell = row.querySelector('td:nth-child(3) .domain-link');
    if (domainCell) {
      const domain = domainCell.textContent.trim();
      domains.push(domain);
      const copyableBox = domainCell.closest('td');
      if (copyableBox) {
        copyableBox.classList.add('highlight');
      }
    }
  });
  
  if (domains.length === 0) {
    showToastMessage('No domains found on current page', false);
    return;
  }
  
  copyToClipboard(domains.join('\r\n'));
  showToastMessage(`Copied ${domains.length} domains from current page!`, true);
}
function copyAllUsernames() {
  document.querySelectorAll('.copyable-box.highlight').forEach(box => { box.classList.remove('highlight'); });
  
  const rows = document.querySelectorAll('tbody tr');
  const usernames = [];
  rows.forEach(row => {
    const usernameCell = row.querySelector('td:nth-child(4) .flex-grow-1');
    if (usernameCell) {
      const username = usernameCell.textContent.trim();
      usernames.push(username);
      const copyableBox = usernameCell.closest('.copyable-box');
      if (copyableBox) {
        copyableBox.classList.add('highlight');
      }
    }
  });
  
  if (usernames.length === 0) {
    showToastMessage('No usernames found on current page', false);
    return;
  }
  
  copyToClipboard(usernames.join('\r\n'));
  showToastMessage(`Copied ${usernames.length} usernames from current page!`, true);
}
function copyAllPasswords() {
  document.querySelectorAll('.copyable-box.highlight').forEach(box => { box.classList.remove('highlight'); });
  
  const rows = document.querySelectorAll('tbody tr');
  const passwords = [];
  rows.forEach(row => {
    const passwordCell = row.querySelector('td:nth-child(5) .flex-grow-1');
    if (passwordCell) {
      const password = passwordCell.textContent.trim();
      passwords.push(password);
      const copyableBox = passwordCell.closest('.copyable-box');
      if (copyableBox) {
        copyableBox.classList.add('highlight');
      }
    }
  });
  
  if (passwords.length === 0) {
    showToastMessage('No passwords found on current page', false);
    return;
  }
  
  copyToClipboard(passwords.join('\r\n'));
  showToastMessage(`Copied ${passwords.length} passwords from current page!`, true);
}

function setTheme() {}

function autoSelectCheckbox(textarea) {
  const row = textarea.closest('tr');
  const checkbox = row.querySelector('input[name="select_checkbox"]');
  if (checkbox && !checkbox.checked) {
    checkbox.checked = true;
    checkbox.dispatchEvent(new Event('change'));
  }
}

async function addTokens(event) {
  event.preventDefault();
  const form = event.target;
  const formData = new FormData();
  formData.append('security_answer', form.security_answer.value);
  try {
    const response = await fetch(window.APP_URLS.addTokens, { method: 'POST', body: formData });
    const result = await response.json();
    if (result.success) {
      const tokenInfo = document.querySelector('.token-info');
      if (tokenInfo) tokenInfo.innerHTML = `<i class="fas fa-coins me-2"></i>${result.tokens} tokens`;
      form.reset();
      const searchBtn = document.querySelector('button[type="submit"]');
      if (searchBtn && searchBtn.disabled) searchBtn.disabled = false;
      showToastMessage(result.message, true);
    } else {
      showToastMessage(result.message, false);
    }
  } catch (error) { console.error('Error adding tokens:', error); showToastMessage('An error occurred while adding tokens.', false); }
}

async function saveSelected() {
  try {
    const rows = Array.from(document.querySelectorAll('tbody tr'));
    const items = [];
    rows.forEach((row) => {
      const checkbox = row.querySelector('input[name="select_checkbox"]');
      if (!checkbox || !checkbox.checked) return;
      const t = row.querySelector('td:nth-child(2)')?.textContent.trim();
      const d = row.querySelector('td:nth-child(3) .domain-link')?.textContent.trim();
      const u = row.querySelector('td:nth-child(4) .flex-grow-1')?.textContent.trim();
      const p = row.querySelector('td:nth-child(5) .flex-grow-1')?.textContent.trim();
      const note = row.querySelector('textarea[name="note"]')?.value.trim() || '';
      if (d && u && p) items.push({ t, d, u, p, note });
    });
    if (items.length === 0) { showToastMessage('No selected rows to save.', false); return; }
    const name = prompt('Enter a name for this saved search:');
    if (!name) return;
    const res = await fetch(window.APP_URLS.saveResults, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, items }) });
    const result = await res.json();
    if (result.success) {
      showToastMessage(`Saved ${result.count} item(s) to "${name}".`, true);
    } else {
      showToastMessage(result.message || 'Failed to save.', false);
    }
  } catch (e) {
    console.error('Failed to save', e);
    showToastMessage('Error saving items.', false);
  }
}

// Init after DOM loaded
document.addEventListener('DOMContentLoaded', function() {
  initToast();
  setTheme('dark');
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      const textElement = this.previousElementSibling;
      const textToCopy = textElement.textContent.trim();
      const copyableBox = this.closest('.copyable-box');
      copyToClipboard(textToCopy, copyableBox);
    });
  });
  document.querySelectorAll('[title]')
    .forEach(el => { if (window.bootstrap) new bootstrap.Tooltip(el); });
  document.querySelectorAll('input[name="select_checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', function() {
      const row = this.closest('tr');
      row.style.backgroundColor = this.checked ? 'rgba(52, 152, 219, 0.1)' : '';
    });
  });
  document.querySelectorAll('.note-textarea').forEach(textarea => {
    textarea.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = (this.scrollHeight) + 'px';
    });
  });

  // Show thinking overlay on form submit ONLY when there is input
  const postForm = document.querySelector('form[method="post"]');
  const overlay = document.getElementById('thinking-overlay');
  if (postForm && overlay) {
    postForm.addEventListener('submit', function(e) {
      const d = document.getElementById('domain')?.value.trim() || '';
      const u = document.getElementById('username')?.value.trim() || '';
      if (d === '' && u === '') {
        // Guard elsewhere already prevents submit; ensure overlay stays hidden
        e.preventDefault();
        overlay.style.display = 'none';
        return;
      }
      overlay.style.display = 'flex';
    });
  }
});

// Expose functions needed by inline event handlers, if any
window.copyAllDomains = copyAllDomains;
window.copyAllUsernames = copyAllUsernames;
window.copyAllPasswords = copyAllPasswords;
window.addTokens = addTokens;
window.saveSelected = saveSelected;
window.autoSelectCheckbox = autoSelectCheckbox;

// Pagination helper moved from template
function goToPage(pageNumber) {
  try {
    const pageInput = document.getElementById('page');
    if (!pageInput) return;
    pageInput.value = pageNumber;
    const form = document.querySelector('form[method="post"]');
    if (!form) return;
    const overlay = document.getElementById('thinking-overlay');
    if (overlay) overlay.style.display = 'flex';
    form.submit();
  } catch (error) {
    console.error('Error in goToPage:', error);
  }
}
window.goToPage = goToPage;

