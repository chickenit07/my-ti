// Minimal admin helpers
function confirmClearAllSaved(){ return confirm('Clear ALL saved results?'); }
function confirmDeleteSaved(name){ return confirm('Delete saved item ' + name + '?'); }
window.confirmClearAllSaved = confirmClearAllSaved;
window.confirmDeleteSaved = confirmDeleteSaved;

