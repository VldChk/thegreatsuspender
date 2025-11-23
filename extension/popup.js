const statusEl = document.getElementById('status');
const tabsListEl = document.getElementById('tabs');

async function sendMessage(type, payload = {}) {
  return await chrome.runtime.sendMessage({ type, ...payload });
}

document.getElementById('suspendCurrent').addEventListener('click', async () => {
  await sendMessage('SUSPEND_CURRENT');
  await refreshState('Suspended current tab.');
});

document.getElementById('suspendInactive').addEventListener('click', async () => {
  await sendMessage('SUSPEND_INACTIVE');
  await refreshState('Suspended inactive tabs.');
});

function formatTimestamp(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  return date.toLocaleTimeString();
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
  if (!entries.length) {
    const li = document.createElement('li');
    li.textContent = 'No suspended tabs.';
    tabsListEl.appendChild(li);
    return;
  }
  for (const [tabId, info] of entries) {
    const li = document.createElement('li');
    const span = document.createElement('span');
    const parts = [info.title || info.url];
    if (info.reason) {
      parts.push(`reason: ${info.reason}`);
    }
    parts.push(info.method === 'discard' ? 'native discard' : 'parked page');
    span.textContent = `${parts.join(' - ')} (${formatTimestamp(info.suspendedAt)})`;
    const button = document.createElement('button');
    button.textContent = 'Unsuspend';
    button.addEventListener('click', async () => {
      await sendMessage('RESUME_TAB', { tabId: Number(tabId) });
      await refreshState('Unsuspended tab.');
    });
    li.appendChild(span);
    li.appendChild(button);
    tabsListEl.appendChild(li);
  }
}

refreshState();
