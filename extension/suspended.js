const params = new URLSearchParams(window.location.search);
const token = params.get('token');
const urlParam = params.get('url');
const titleParam = params.get('title');
const faviconParam = params.get('favicon');

const detailsEl = document.getElementById('details');
const hintEl = document.getElementById('hint');
const wakeButton = document.getElementById('wake');

let tabId = null;
let tabInfo = null;

// Immediately render available info from URL params
if (titleParam) {
  document.title = titleParam;
  detailsEl.textContent = titleParam;
}
if (urlParam) {
  hintEl.textContent = `Original URL: ${urlParam}`;
}
if (faviconParam) {
  const link = document.querySelector("link[rel~='icon']") || document.createElement('link');
  link.type = 'image/x-icon';
  link.rel = 'icon';
  link.href = faviconParam;
  document.getElementsByTagName('head')[0].appendChild(link);
}

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
  const payload = { token };
  if (typeof tabId === 'number') {
    payload.tabId = tabId;
  }

  try {
    const response = await sendMessage('SUSPENDED_VIEW_INFO', payload);

    if (response && response.locked) {
      detailsEl.textContent = 'Suspension log is encrypted. Unlock it from the options page to resume this tab.';
      wakeButton.disabled = true;
      return;
    }

    if (response && response.found && response.info) {
      tabInfo = response.info;
      detailsEl.textContent = `${tabInfo.title || tabInfo.url}`;
      hintEl.textContent = `Original URL: ${tabInfo.url}`;
      document.title = tabInfo.title || 'Tab suspended';
      return;
    }
  } catch (err) {
    console.warn('Failed to fetch info from background', err);
  }

  // Fallback to URL params if background request failed or returned no info
  if (urlParam) {
    tabInfo = {
      url: urlParam,
      title: titleParam || urlParam,
    };
    // UI is already set from params at the top, but ensure consistency
    detailsEl.textContent = tabInfo.title;
    hintEl.textContent = `Original URL: ${tabInfo.url}`;
  } else {
    detailsEl.textContent = 'Suspension metadata missing.';
    wakeButton.disabled = true;
  }
}

wakeButton.addEventListener('click', async () => {
  wakeButton.disabled = true;
  wakeButton.textContent = 'Unsuspending...';

  // Try to unsuspend via background script first
  if (typeof tabId === 'number') {
    try {
      const response = await sendMessage('UNSUSPEND_TOKEN', { token, tabId });
      if (response && response.ok) {
        detailsEl.textContent = 'Waking up...';
        return;
      }
    } catch (err) {
      console.warn('Background unsuspend failed', err);
    }
  }

  // Fallback: navigate current tab to original URL
  if (tabInfo && tabInfo.url) {
    window.location.href = tabInfo.url;
  } else if (urlParam) {
    window.location.href = urlParam;
  } else {
    wakeButton.disabled = false;
    wakeButton.textContent = 'Retry unsuspend';
    detailsEl.textContent = 'Failed to unsuspend automatically. Try reloading the tab.';
  }
});

init();
