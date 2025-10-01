// Early theme apply to avoid FOUC
// Force dark theme
document.documentElement.setAttribute('data-theme', 'dark');
if (document.body) document.body.setAttribute('data-theme', 'dark');

// Theme switching functionality
function setTheme() {}

document.addEventListener('DOMContentLoaded', function () {
  setTheme('dark');
});

// LGBT Theme Modal Functions
function showLGBTModal() {
  const modal = document.getElementById('lgbtModal');
  if (modal) modal.style.display = 'block';
}

function closeLGBTModal() {
  const modal = document.getElementById('lgbtModal');
  if (modal) modal.style.display = 'none';
}

window.setTheme = setTheme;
window.showLGBTModal = showLGBTModal;
window.closeLGBTModal = closeLGBTModal;

// Close modal when clicking outside of it
window.addEventListener('click', function (event) {
  const modal = document.getElementById('lgbtModal');
  if (!modal) return;
  if (event.target === modal) {
    modal.style.display = 'none';
  }
});


