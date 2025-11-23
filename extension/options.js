const form = document.getElementById('settingsForm');
const statusEl = document.getElementById('status');
const autoMinutesEl = document.getElementById('autoMinutes');
const excludeActiveEl = document.getElementById('excludeActive');
const excludePinnedEl = document.getElementById('excludePinned');
const excludeAudibleEl = document.getElementById('excludeAudible');
const whitelistEl = document.getElementById('whitelist');
const unsuspendMethodEl = document.getElementById('unsuspendMethod');
const passphraseEl = document.getElementById('passphrase');
const encryptionHintEl = document.getElementById('encryptionHint');

const fallbackSettings = {
  autoSuspendMinutes: 30,
  excludePinned: true,
  excludeAudible: true,
  excludeActive: true,
  whitelist: [],
  unsuspendMethod: 'activate',
  encryption: {
    enabled: true,
    salt: null,
    iterations: 150000,
  },
};

let currentSettings = { ...fallbackSettings };


async function sendMessage(type, payload = {}) {
  try {
    return await chrome.runtime.sendMessage({ type, ...payload });
  } catch (err) {
    console.warn('Message failed', type, err);
    throw err;
  }
}

async function loadSettings() {
  try {
    const response = await sendMessage('GET_SETTINGS');
    currentSettings = {
      ...fallbackSettings,
      ...(response || {}),
      encryption: {
        ...fallbackSettings.encryption,
        ...(response?.encryption || {}),
      },
    };
  } catch (err) {
    currentSettings = { ...fallbackSettings };
    showStatus('Background process not yet ready. Using defaults.', true);
  }
  autoMinutesEl.value = currentSettings.autoSuspendMinutes;
  excludeActiveEl.checked = currentSettings.excludeActive;
  excludePinnedEl.checked = currentSettings.excludePinned;
  excludeAudibleEl.checked = currentSettings.excludeAudible;
  unsuspendMethodEl.value = currentSettings.unsuspendMethod;
  whitelistEl.value = (currentSettings.whitelist || []).join('\n');

  const isPassphraseActive = !!currentSettings.encryption?.salt;
  const statusDiv = document.getElementById('encryptionStatus');
  const setBtn = document.getElementById('setPassphraseBtn');
  const removeBtn = document.getElementById('removePassphraseBtn');

  if (isPassphraseActive) {
    statusDiv.textContent = 'Status: Protected by Passphrase';
    statusDiv.style.color = '#2d7a2d';
    passphraseEl.placeholder = 'Enter new passphrase to change';
    setBtn.textContent = 'Change Passphrase';
    removeBtn.style.display = 'inline-block';
    encryptionHintEl.textContent = 'Your data is encrypted with your custom passphrase.';
  } else {
    statusDiv.textContent = 'Status: Protected by Device Key (Auto-Generated)';
    statusDiv.style.color = '#666';
    passphraseEl.placeholder = 'Set a passphrase (optional)';
    setBtn.textContent = 'Set Passphrase';
    removeBtn.style.display = 'none';
    encryptionHintEl.textContent = 'Your data is encrypted automatically. Set a passphrase to lock it further.';
  }
}

function collectSettingsFromForm() {
  return {
    autoSuspendMinutes: Number(autoMinutesEl.value) || 1,
    excludeActive: excludeActiveEl.checked,
    excludePinned: excludePinnedEl.checked,
    excludeAudible: excludeAudibleEl.checked,
    unsuspendMethod: unsuspendMethodEl.value,
    whitelist: whitelistEl.value
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean),
    encryption: {
      enabled: true,
      salt: currentSettings?.encryption?.salt || null,
      iterations: currentSettings?.encryption?.iterations || 150000,
    },
  };
}

function showStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#a11' : '#2d7a2d';
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const nextSettings = collectSettingsFromForm();

  try {
    await sendMessage('SAVE_SETTINGS', { payload: nextSettings });
    showStatus('Settings saved.');
    await loadSettings();
  } catch (err) {
    showStatus('Failed to save settings.', true);
  }
});

document.getElementById('setPassphraseBtn').addEventListener('click', async () => {
  const passphrase = passphraseEl.value.trim();
  if (!passphrase) {
    showStatus('Please enter a passphrase first.', true);
    return;
  }

  if (!confirm('Setting a passphrase will re-encrypt your data. Make sure you remember it!')) {
    return;
  }

  try {
    const response = await sendMessage('SET_PASSPHRASE', { passphrase });
    if (response?.ok) {
      passphraseEl.value = '';
      await loadSettings();
      showStatus('Passphrase set successfully.');
    } else {
      showStatus('Failed to set passphrase.', true);
    }
  } catch (err) {
    showStatus('Error setting passphrase.', true);
  }
});

document.getElementById('removePassphraseBtn').addEventListener('click', async () => {
  if (!confirm('Are you sure? This will revert to using an auto-generated Device Key. Your data will remain encrypted but accessible without a password on this device.')) {
    return;
  }

  try {
    const response = await sendMessage('SET_PASSPHRASE', { passphrase: null }); // Null removes it
    if (response?.ok) {
      passphraseEl.value = '';
      await loadSettings();
      showStatus('Passphrase removed. Using Device Key.');
    } else {
      showStatus('Failed to remove passphrase.', true);
    }
  } catch (err) {
    showStatus('Error removing passphrase.', true);
  }
});

// --- Logging ---

const downloadLogsBtn = document.getElementById('downloadLogs');
const clearLogsBtn = document.getElementById('clearLogs');

downloadLogsBtn.addEventListener('click', async () => {
  try {
    const stored = await chrome.storage.local.get('logs');
    const logs = stored.logs || [];
    if (logs.length === 0) {
      showStatus('No logs to download.');
      return;
    }

    const text = logs.map(entry => {
      const dataStr = entry.data ? `\nData: ${JSON.stringify(entry.data, null, 2)}` : '';
      return `[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}${dataStr}`;
    }).join('\n\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tab-suspender-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('Failed to download logs', err);
    showStatus('Failed to download logs.', true);
  }
});

clearLogsBtn.addEventListener('click', async () => {
  if (!confirm('Are you sure you want to clear all logs?')) {
    return;
  }
  try {
    await chrome.storage.local.remove('logs');
    showStatus('Logs cleared.');
  } catch (err) {
    console.error('Failed to clear logs', err);
    showStatus('Failed to clear logs.', true);
  }
});

loadSettings();
