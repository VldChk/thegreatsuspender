const form = document.getElementById('settingsForm');
const statusEl = document.getElementById('status');
const autoMinutesEl = document.getElementById('autoMinutes');
const excludeActiveEl = document.getElementById('excludeActive');
const excludePinnedEl = document.getElementById('excludePinned');
const excludeAudibleEl = document.getElementById('excludeAudible');
const whitelistEl = document.getElementById('whitelist');
const unsuspendMethodEl = document.getElementById('unsuspendMethod');
const encryptionEnabledEl = document.getElementById('encryptionEnabled');
const passphraseEl = document.getElementById('passphrase');

let currentSettings = null;

async function sendMessage(type, payload = {}) {
  return await chrome.runtime.sendMessage({ type, ...payload });
}

async function loadSettings() {
  currentSettings = await sendMessage('GET_SETTINGS');
  autoMinutesEl.value = currentSettings.autoSuspendMinutes;
  excludeActiveEl.checked = currentSettings.excludeActive;
  excludePinnedEl.checked = currentSettings.excludePinned;
  excludeAudibleEl.checked = currentSettings.excludeAudible;
  unsuspendMethodEl.value = currentSettings.unsuspendMethod;
  whitelistEl.value = (currentSettings.whitelist || []).join('\n');
  encryptionEnabledEl.checked = !!currentSettings.encryption?.enabled;
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
      enabled: encryptionEnabledEl.checked,
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
  const passphrase = passphraseEl.value.trim();

  if (nextSettings.encryption.enabled && !currentSettings?.encryption?.enabled && !passphrase) {
    showStatus('Enter a passphrase to enable encryption.', true);
    return;
  }

  await sendMessage('SAVE_SETTINGS', { payload: nextSettings });

  if (nextSettings.encryption.enabled) {
    if (!passphrase && !currentSettings?.encryption?.enabled) {
      showStatus('Encryption enabled but passphrase missing.', true);
      return;
    }
    if (passphrase) {
      await sendMessage('SET_PASSPHRASE', { passphrase });
    }
  } else if (currentSettings?.encryption?.enabled) {
    await sendMessage('SET_PASSPHRASE', { passphrase: null });
  }

  passphraseEl.value = '';
  showStatus('Settings saved.');
  await loadSettings();
});

loadSettings();
