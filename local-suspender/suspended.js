const params = new URLSearchParams(window.location.search);
const token = params.get('token');
const detailsEl = document.getElementById('details');
const hintEl = document.getElementById('hint');
const wakeButton = document.getElementById('wake');

let tabId = null;
let tabInfo = null;

function sendMessage(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

async function init() {
  if (!token) {
    detailsEl.textContent = 'Missing suspension metadata.';
    wakeButton.disabled = true;
    return;
  }

  chrome.tabs.getCurrent(async tab => {
    tabId = tab?.id ?? null;
    await loadInfo();
  });
}

async function loadInfo() {
  hintEl.textContent = '';
  const payload = { token };
  if (typeof tabId === 'number') {
    payload.tabId = tabId;
  }
  const response = await sendMessage('SUSPENDED_VIEW_INFO', payload);
  if (response.locked) {
    detailsEl.textContent = 'Suspension log is encrypted. Unlock it from the options page to resume this tab.';
    wakeButton.disabled = true;
    return;
  }
  if (!response.found) {
    detailsEl.textContent = 'Suspension metadata missing.';
    wakeButton.disabled = true;
    return;
  }
  tabInfo = response.info;
  detailsEl.textContent = `${tabInfo.title || tabInfo.url}`;
  hintEl.textContent = `Original URL: ${tabInfo.url}`;
}

wakeButton.addEventListener('click', async () => {
  if (typeof tabId !== 'number') return;
  wakeButton.disabled = true;
  wakeButton.textContent = 'Unsuspending…';
  const response = await sendMessage('UNSUSPEND_TOKEN', { token, tabId });
  if (!response || !response.ok) {
    wakeButton.disabled = false;
    wakeButton.textContent = 'Retry unsuspend';
    detailsEl.textContent = 'Failed to unsuspend automatically. Try reloading the tab.';
    return;
  }
  detailsEl.textContent = 'Waking up…';
});

init();
