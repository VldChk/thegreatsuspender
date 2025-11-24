const statusEl = document.getElementById('status');
const tabsListEl = document.getElementById('tabs');
const tabsHeaderEl = document.getElementById('tabsHeader');
const tabsCountEl = document.getElementById('tabsCount');
const suspendedContextEl = document.getElementById('suspendedContext');
const actionsGroupEl = document.getElementById('actionsGroup');
const unsuspendCurrentBtn = document.getElementById('unsuspendCurrent');
const neverSuspendSiteBtn = document.getElementById('neverSuspendSite');
const unsuspendAllBtn = document.getElementById('unsuspendAll');

let currentSuspendedTabId = null;
let currentSuspendedUrl = null;

async function sendMessage(type, payload = {}) {
  return await chrome.runtime.sendMessage({ type, ...payload });
}

// --- Event Listeners ---

document.getElementById('suspendCurrent').addEventListener('click', async () => {
  await sendMessage('SUSPEND_CURRENT');
  await refreshState('Suspended current tab.');
});

document.getElementById('suspendInactive').addEventListener('click', async () => {
  await sendMessage('SUSPEND_INACTIVE');
  await refreshState('Suspended inactive tabs.');
});

document.getElementById('unsuspendAll').addEventListener('click', async () => {
  await sendMessage('RESUME_ALL');
  await refreshState('Unsuspended all tabs.');
});

document.getElementById('openOptions').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

tabsHeaderEl.addEventListener('click', () => {
  const icon = tabsHeaderEl.querySelector('.toggle-icon');
  tabsListEl.classList.toggle('hidden');
  icon.textContent = tabsListEl.classList.contains('hidden') ? '+' : '-';
});

if (unsuspendCurrentBtn) {
  unsuspendCurrentBtn.addEventListener('click', async () => {
    if (currentSuspendedTabId) {
      await sendMessage('RESUME_TAB', { tabId: currentSuspendedTabId });
      window.close(); // Close popup as we are navigating away
    }
  });
}

if (neverSuspendSiteBtn) {
  neverSuspendSiteBtn.addEventListener('click', async () => {
    if (currentSuspendedUrl) {
      const settings = await sendMessage('GET_SETTINGS');
      const urlObj = new URL(currentSuspendedUrl);
      const domain = urlObj.hostname.replace(/^www\./, '');

      const newWhitelist = Array.from(new Set([...(settings.whitelist || []), domain]));
      const payload = { ...settings, whitelist: newWhitelist };
      await sendMessage('SAVE_SETTINGS', { payload });
      await refreshState(`Added ${domain} to whitelist and unsuspended.`);
      // Auto-unsuspend is handled by background on SAVE_SETTINGS
      setTimeout(() => window.close(), 1000);
    }
  });
}

// --- Helpers ---

function formatTimestamp(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  return date.toLocaleTimeString();
}

async function checkActiveTabContext() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // Check if it's a suspended page
  if (tab.url && tab.url.startsWith(chrome.runtime.getURL('suspended.html'))) {
    const urlObj = new URL(tab.url);
    const originalUrl = urlObj.searchParams.get('url');
    if (originalUrl) {
      currentSuspendedTabId = tab.id;
      currentSuspendedUrl = originalUrl;
      suspendedContextEl.classList.remove('hidden');
      actionsGroupEl?.classList.add('hidden');
      unsuspendAllBtn?.classList.add('hidden');

      // Disable suspend buttons since it's already suspended
      document.getElementById('suspendCurrent').disabled = true;
      document.getElementById('suspendInactive').disabled = true;
      return;
    }
  }
  suspendedContextEl.classList.add('hidden');
  actionsGroupEl?.classList.remove('hidden');
  unsuspendAllBtn?.classList.remove('hidden');
  document.getElementById('suspendCurrent').disabled = false;
  document.getElementById('suspendInactive').disabled = false;
}

async function refreshState(message) {
  const response = await sendMessage('GET_STATE');
  tabsListEl.innerHTML = '';
  statusEl.textContent = message || '';

  if (response.locked) {
    statusEl.textContent = 'State locked. Unlock from options to view suspended tabs.';
    return;
  }

  const entries = Object.entries(response.state.suspendedTabs || {}).sort(
    (a, b) => (b[1].suspendedAt || 0) - (a[1].suspendedAt || 0)
  );

  tabsCountEl.textContent = `${entries.length} suspended tabs`;
  tabsHeaderEl.querySelector('.toggle-icon').textContent = tabsListEl.classList.contains('hidden') ? '+' : '-';

  if (!entries.length) {
    const li = document.createElement('li');
    li.textContent = 'No suspended tabs.';
    tabsListEl.appendChild(li);
    return;
  }

  for (const [tabId, info] of entries) {
    const li = document.createElement('li');
    li.className = 'tab-item';
    const tabIdNum = Number(tabId);

    const contentDiv = document.createElement('div');
    contentDiv.className = 'tab-content';
    contentDiv.title = 'Click to switch to this tab';

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tab-title';
    titleSpan.textContent = info.title || info.url;

    const metaSpan = document.createElement('span');
    metaSpan.className = 'tab-meta';
    metaSpan.textContent = formatTimestamp(info.suspendedAt);

    contentDiv.appendChild(titleSpan);
    contentDiv.appendChild(metaSpan);

    contentDiv.addEventListener('click', async () => {
      await chrome.tabs.update(tabIdNum, { active: true });
      if (info.windowId) {
        await chrome.windows.update(info.windowId, { focused: true });
      }
    });

    li.addEventListener('click', async () => {
      await chrome.tabs.update(tabIdNum, { active: true });
      if (info.windowId) {
        await chrome.windows.update(info.windowId, { focused: true });
      }
    });

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'tab-actions';

    const unsuspendBtn = document.createElement('button');
    unsuspendBtn.className = 'btn-sm';
    unsuspendBtn.textContent = 'Unsuspend';
    unsuspendBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      await sendMessage('RESUME_TAB', { tabId: tabIdNum });
      await chrome.tabs.update(tabIdNum, { active: true });
      if (info.windowId) {
        await chrome.windows.update(info.windowId, { focused: true });
      }
      await refreshState('Unsuspended tab.');
    });

    actionsDiv.appendChild(unsuspendBtn);

    li.appendChild(contentDiv);
    li.appendChild(actionsDiv);
    tabsListEl.appendChild(li);
  }
}

// --- Init ---

(async () => {
  await checkActiveTabContext();
  await refreshState();
})();
