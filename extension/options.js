const form = document.getElementById('settingsForm');
const statusEl = document.getElementById('status');
const autoMinutesEl = document.getElementById('autoMinutes');
const excludeActiveEl = document.getElementById('excludeActive');
const excludePinnedEl = document.getElementById('excludePinned');
const excludeAudibleEl = document.getElementById('excludeAudible');
const whitelistEl = document.getElementById('whitelist');
const unsuspendMethodEl = document.getElementById('unsuspendMethod');
const passphraseEl = document.getElementById('passphrase');
const cloudBackupEl = document.getElementById('cloudBackup');
const unlockPassphraseEl = document.getElementById('unlockPassphrase');
const unlockBtn = document.getElementById('unlockBtn');
const lockedPanel = document.getElementById('lockedPanel');
const unlockedPanel = document.getElementById('unlockedPanel');
const resetEncryptionBtn = document.getElementById('resetEncryptionBtn');
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
    iterations: 150000,
    cloudBackupEnabled: true,
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
  cloudBackupEl.checked = !!currentSettings.encryption.cloudBackupEnabled;
  await refreshEncryptionStatus();
}

function applyEncryptionStatus(status) {
  const statusDiv = document.getElementById('encryptionStatus');
  const setBtn = document.getElementById('setPassphraseBtn');
  const removeBtn = document.getElementById('removePassphraseBtn');

  cloudBackupEl.checked = !!status.cloudBackupEnabled;

  if (status.locked) {
    statusDiv.textContent = 'Status: Locked - passkey required';
    statusDiv.style.color = '#a11';
    lockedPanel.style.display = 'block';
    unlockedPanel.style.display = 'none';
    setBtn.disabled = true;
    removeBtn.disabled = true;
    encryptionHintEl.textContent = 'Enter your passkey to unlock your data.';
    return;
  }

  lockedPanel.style.display = 'none';
  unlockedPanel.style.display = 'block';
  setBtn.disabled = false;
  removeBtn.disabled = false;

  if (status.usingPasskey) {
    statusDiv.textContent = 'Status: Protected by Passkey';
    statusDiv.style.color = '#2d7a2d';
    passphraseEl.placeholder = 'Enter new passkey to change';
    setBtn.textContent = 'Change Passkey';
    removeBtn.style.display = 'inline-block';
    encryptionHintEl.textContent = 'Your data key is wrapped with your passkey.';
  } else {
    statusDiv.textContent = status.cloudBackupEnabled
      ? 'Status: Key stored in Chrome Sync'
      : 'Status: Key stored locally only';
    statusDiv.style.color = '#666';
    passphraseEl.placeholder = 'Set a passkey (optional)';
    setBtn.textContent = 'Set Passkey';
    removeBtn.style.display = 'none';
    encryptionHintEl.textContent = status.cloudBackupEnabled
      ? 'Your data is encrypted locally; the key is backed up to Chrome Sync.'
      : 'Your data is encrypted locally; the key stays on this device.';
  }
}

async function refreshEncryptionStatus() {
  try {
    const status = await sendMessage('GET_ENCRYPTION_STATUS');
    applyEncryptionStatus(status || {});
  } catch (err) {
    console.warn('Failed to load encryption status', err);
    applyEncryptionStatus({
      locked: false,
      usingPasskey: false,
      cloudBackupEnabled: currentSettings.encryption.cloudBackupEnabled,
    });
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
      iterations: currentSettings?.encryption?.iterations || 150000,
      cloudBackupEnabled: cloudBackupEl.checked,
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

  if (!confirm('Setting a passphrase will wrap your key. Make sure you remember it!')) {
    return;
  }

  try {
    const response = await sendMessage('SET_PASSKEY', { passkey: passphrase });
    if (response?.ok) {
      passphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Passphrase set successfully.');
    } else {
      showStatus('Failed to set passphrase.', true);
    }
  } catch (err) {
    showStatus('Error setting passphrase.', true);
  }
});

document.getElementById('removePassphraseBtn').addEventListener('click', async () => {
  if (!confirm('Are you sure? This will remove the passkey. The data key will be stored in plaintext in storage (or sync if enabled).')) {
    return;
  }

  try {
    const response = await sendMessage('REMOVE_PASSKEY');
    if (response?.ok) {
      passphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Passphrase removed.');
    } else {
      showStatus('Failed to remove passphrase.', true);
    }
  } catch (err) {
    showStatus('Error removing passphrase.', true);
  }
});

unlockBtn.addEventListener('click', async () => {
  const passphrase = unlockPassphraseEl.value.trim();
  if (!passphrase) {
    showStatus('Please enter your passkey to unlock.', true);
    return;
  }
  try {
    const response = await sendMessage('UNLOCK_WITH_PASSKEY', { passkey: passphrase });
    if (response?.ok) {
      unlockPassphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Unlocked successfully.');
    } else {
      showStatus('Incorrect passkey.', true);
    }
  } catch (err) {
    showStatus('Failed to unlock.', true);
  }
});

cloudBackupEl.addEventListener('change', async () => {
  try {
    await sendMessage('SET_CLOUD_BACKUP', { enabled: cloudBackupEl.checked });
    await refreshEncryptionStatus();
    showStatus('Cloud backup preference saved.');
  } catch (err) {
    console.error('Failed to toggle cloud backup', err);
    showStatus('Failed to update cloud backup.', true);
  }
});

resetEncryptionBtn.addEventListener('click', async () => {
  if (!confirm('This will erase encrypted session data and snapshots and generate a new key. Continue?')) {
    return;
  }
  try {
    const response = await sendMessage('RESET_ENCRYPTION');
    if (response?.ok) {
      await loadSettings();
      showStatus('Encryption reset. Using fresh key.');
    } else {
      showStatus('Failed to reset encryption.', true);
    }
  } catch (err) {
    console.error('Failed to reset encryption', err);
    showStatus('Failed to reset encryption.', true);
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
