const SETTINGS_KEY = 'settings';
const STATE_KEY = 'suspenderState';
const SESSION_LAST_ACTIVE_KEY = 'lastActive';
const SESSION_PENDING_STATE_KEY = 'pendingSuspenderState';

const defaultSettings = {
  autoSuspendMinutes: 30,
  excludePinned: true,
  excludeAudible: true,
  excludeActive: true,
  whitelist: [],
  unsuspendMethod: 'activate', // 'activate' | 'manual'
  encryption: {
    enabled: true,
    salt: null,
    iterations: 150000,
  },
};

let cachedSettings = null;
let cachedState = null;
let cryptoKey = null;
let lastActiveCache = {};
let stateLocked = false;
const sessionArea = chrome.storage?.session || null;
const sessionFallback = {};

// --- Logger ---

const Logger = {
  async log(level, message, data = null) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data: data instanceof Error ? { message: data.message, stack: data.stack } : data,
    };
    console[level](message, data || '');

    try {
      const stored = await chrome.storage.local.get('logs');
      const logs = stored.logs || [];
      logs.push(entry);
      // Keep last 1000 logs
      if (logs.length > 1000) {
        logs.shift();
      }
      await chrome.storage.local.set({ logs });
    } catch (err) {
      console.error('Failed to save log', err);
    }
  },
  info(message, data) { this.log('info', message, data); },
  warn(message, data) { this.log('warn', message, data); },
  error(message, data) { this.log('error', message, data); }
};

// --- Snapshot Service ---

const SnapshotService = {
  async createSnapshot() {
    const state = await loadState();
    if (!state || !state.suspendedTabs || Object.keys(state.suspendedTabs).length === 0) {
      return;
    }

    // We only create snapshots if we have the key to encrypt them (if encryption is on)
    const settings = await ensureSettings();
    if (settings.encryption.enabled && !cryptoKey) {
      Logger.warn('Skipping snapshot: Encryption enabled but key not available');
      return;
    }

    try {
      let snapshotData;
      if (settings.encryption.enabled) {
        snapshotData = await encryptPayload(state);
      } else {
        snapshotData = { plain: state };
      }

      const snapshot = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        tabCount: Object.keys(state.suspendedTabs).length,
        data: snapshotData
      };

      const stored = await chrome.storage.local.get('backups');
      const backups = stored.backups || [];
      backups.push(snapshot);

      // Prune old backups (keep last 20)
      if (backups.length > 20) {
        backups.shift();
      }

      await chrome.storage.local.set({ backups });
      Logger.info('Snapshot created', { id: snapshot.id, tabCount: snapshot.tabCount });
    } catch (err) {
      Logger.error('Failed to create snapshot', err);
    }
  },

  async getSnapshots() {
    const stored = await chrome.storage.local.get('backups');
    return (stored.backups || []).map(b => ({
      id: b.id,
      timestamp: b.timestamp,
      tabCount: b.tabCount
    })).reverse(); // Newest first
  },

  async restoreSnapshot(snapshotId) {
    const stored = await chrome.storage.local.get('backups');
    const backups = stored.backups || [];
    const snapshot = backups.find(b => b.id === snapshotId);

    if (!snapshot) {
      throw new Error('Snapshot not found');
    }

    let restoredState;
    if (snapshot.data.ct) {
      // Encrypted snapshot
      if (!cryptoKey) {
        throw new Error('Encryption key required to restore this snapshot');
      }
      restoredState = await decryptPayload(snapshot.data);
    } else if (snapshot.data.plain) {
      restoredState = snapshot.data.plain;
    } else {
      throw new Error('Invalid snapshot format');
    }

    // Merge with current pending state to avoid losing very recent changes if possible,
    // but generally restoration replaces the state.
    // For safety, let's just replace the state but keep the current pending buffer if any.
    cachedState = restoredState;
    await saveState(cachedState);
    Logger.info('Snapshot restored', { id: snapshotId });
    return true;
  }
};

// --- Initialization ---

// Create a promise that resolves when initialization is complete.
// This ensures that event handlers can wait for settings/state to be loaded.
let readyResolve;
const ready = new Promise(resolve => {
  readyResolve = resolve;
});

async function init() {
  try {
    await ensureSettings();
    await loadLastActive();

    // Try to restore key from session
    if (!cryptoKey) {
      await restoreKeyFromSession();
    }

    // If still no key, try to load/generate device key
    if (!cryptoKey) {
      await ensureDeviceKey();
    }

    // Only schedule if not already scheduled
    const alarm = await chrome.alarms.get('autoSuspend');
    if (!alarm) {
      await scheduleAutoSuspendAlarm();
    }

    const snapshotAlarm = await chrome.alarms.get('snapshotTimer');
    if (!snapshotAlarm) {
      await chrome.alarms.create('snapshotTimer', { periodInMinutes: 60 });
    }
  } catch (err) {
    Logger.error('Initialization failed', err);
  } finally {
    readyResolve();
  }
}

// Start initialization immediately
init();

// --- Event Listeners (Registered Synchronously) ---

chrome.runtime.onInstalled.addListener(handleInstalled);
chrome.runtime.onStartup.addListener(handleStartup);
chrome.runtime.onMessage.addListener(handleMessage);
chrome.tabs.onActivated.addListener(handleTabActivated);
chrome.windows.onFocusChanged.addListener(handleWindowFocusChanged);
chrome.tabs.onRemoved.addListener(handleTabRemoved);
chrome.tabs.onUpdated.addListener(handleTabUpdated);
chrome.alarms.onAlarm.addListener(handleAlarm);
chrome.idle.onStateChanged.addListener(handleIdleStateChange);

// --- Event Handlers ---

async function handleInstalled(details) {
  // onInstalled is a special case where we might want to force a reset
  if (details.reason === 'install') {
    await chrome.storage.local.set({ [SETTINGS_KEY]: defaultSettings });
    cachedSettings = { ...defaultSettings };
    await saveState({ suspendedTabs: {} });
    await scheduleAutoSuspendAlarm(); // Force schedule on install
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: 60 });
    try {
      await chrome.runtime.openOptionsPage();
    } catch (err) {
      Logger.warn('Failed to open options page on install', err);
    }
  } else if (details.reason === 'update') {
    await ready; // Wait for init to ensure we have settings
    await scheduleAutoSuspendAlarm(); // Ensure alarm is correct after update
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: 60 });
  }
}

async function handleStartup() {
  await ready;
}

async function ensureSettings() {
  if (cachedSettings) {
    return cachedSettings;
  }
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  if (!stored[SETTINGS_KEY]) {
    cachedSettings = { ...defaultSettings };
    await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
  } else {
    cachedSettings = {
      ...defaultSettings,
      ...stored[SETTINGS_KEY],
      encryption: {
        ...defaultSettings.encryption,
        ...(stored[SETTINGS_KEY].encryption || {}),
        enabled: true,
      },
    };
    await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
  }
  return cachedSettings;
}

async function saveSettings(nextSettings) {
  cachedSettings = {
    ...defaultSettings,
    ...nextSettings,
    encryption: {
      ...defaultSettings.encryption,
      ...(nextSettings.encryption || {}),
      enabled: true,
    },
  };
  await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
  await scheduleAutoSuspendAlarm(); // Reschedule when settings change
}

async function loadState() {
  if (cachedState) {
    return cachedState;
  }
  const settings = await ensureSettings();
  const stored = await chrome.storage.local.get(STATE_KEY);
  const payload = stored[STATE_KEY];
  if (payload && payload.ct) {
    if (!cryptoKey) {
      stateLocked = true;
      cachedState = await loadPendingState();
      return cachedState;
    }
    try {
      cachedState = await decryptPayload(payload);
      stateLocked = false;
      await clearPendingState();
    } catch (err) {
      Logger.warn('Failed to decrypt state', err);
      cachedState = { suspendedTabs: {} };
      stateLocked = false;
    }
  } else if (payload && payload.plain) {
    cachedState = payload.plain;
    stateLocked = false;
  } else {
    if (settings.encryption.enabled && !cryptoKey) {
      stateLocked = true;
      cachedState = await loadPendingState();
    } else {
      cachedState = { suspendedTabs: {} };
      stateLocked = false;
    }
  }
  return cachedState;
}

async function saveState(state) {
  cachedState = state;
  const settings = await ensureSettings();
  if (settings.encryption.enabled) {
    if (!cryptoKey) {
      stateLocked = true;
      await savePendingState(state);
      return;
    }
    const encrypted = await encryptPayload(state);
    await chrome.storage.local.set({ [STATE_KEY]: encrypted });
    await clearPendingState();
    stateLocked = false;
  } else {
    await chrome.storage.local.set({ [STATE_KEY]: { plain: state } });
    await clearPendingState();
    stateLocked = false;
  }
}

function wildcardToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexString = '^' + escaped.replace(/\*/g, '.*') + '$';
  return new RegExp(regexString);
}

function matchesWhitelist(url, whitelist) {
  return whitelist.some(pattern => {
    try {
      return wildcardToRegExp(pattern).test(url);
    } catch (e) {
      Logger.warn('Invalid whitelist pattern', pattern, e);
      return false;
    }
  });
}

async function sessionGet(key) {
  if (sessionArea) {
    return sessionArea.get(key);
  }
  return { [key]: sessionFallback[key] };
}

async function sessionSet(key, value) {
  if (sessionArea) {
    await sessionArea.set({ [key]: value });
  } else {
    sessionFallback[key] = value;
  }
}

async function sessionRemove(key) {
  if (sessionArea) {
    await sessionArea.remove(key);
  }
  delete sessionFallback[key];
}

async function loadPendingState() {
  const stored = await sessionGet(SESSION_PENDING_STATE_KEY);
  return stored[SESSION_PENDING_STATE_KEY] || { suspendedTabs: {} };
}

async function savePendingState(state) {
  await sessionSet(SESSION_PENDING_STATE_KEY, state);
}

async function clearPendingState() {
  await sessionRemove(SESSION_PENDING_STATE_KEY);
}

function mergeStates(primary, secondary) {
  const merged = {
    suspendedTabs: { ...(primary?.suspendedTabs || {}) },
  };
  for (const [tabId, entry] of Object.entries(secondary?.suspendedTabs || {})) {
    if (!merged.suspendedTabs[tabId]) {
      merged.suspendedTabs[tabId] = entry;
    }
  }
  return merged;
}

async function handleTabActivated(activeInfo) {
  await ready;
  await markTabActive(activeInfo.tabId);
  const settings = await ensureSettings();
  if (settings.unsuspendMethod === 'activate') {
    const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
    if (tab) {
      await maybeAutoUnsuspend(tab);
    }
  }
}

async function handleWindowFocusChanged(windowId) {
  await ready;
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, windowId });
  if (tab) {
    await markTabActive(tab.id);
    if ((await ensureSettings()).unsuspendMethod === 'activate') {
      await maybeAutoUnsuspend(tab);
    }
  }
}

async function handleTabRemoved(tabId) {
  await ready;
  delete lastActiveCache[tabId];
  await sessionSet(SESSION_LAST_ACTIVE_KEY, lastActiveCache);
  const state = await loadState();
  if (state && state.suspendedTabs && state.suspendedTabs[tabId]) {
    delete state.suspendedTabs[tabId];
    await saveState(state);
  }
}

async function handleTabUpdated(tabId, changeInfo, tab) {
  await ready;
  if (changeInfo.status === 'loading') {
    await markTabActive(tabId);
  }
  if ('discarded' in changeInfo) {
    const state = await loadState();
    if (!state) {
      return;
    }
    if (changeInfo.discarded) {
      state.suspendedTabs[tabId] = {
        url: tab.url,
        title: tab.title,
        windowId: tab.windowId,
        suspendedAt: Date.now(),
        method: 'discard',
      };
      await saveState(state);
    } else if (state.suspendedTabs[tabId]?.method === 'discard') {
      delete state.suspendedTabs[tabId];
      await saveState(state);
    }
  }
  if (tab.url && !tab.url.startsWith('chrome-extension://')) {
    const state = await loadState();
    if (state && state.suspendedTabs[tabId]?.method === 'page') {
      if (!tab.url.startsWith(chrome.runtime.getURL('suspended.html'))) {
        delete state.suspendedTabs[tabId];
        await saveState(state);
      }
    }
  }
}

async function handleAlarm(alarm) {
  await ready;
  if (alarm.name === 'autoSuspend') {
    await autoSuspendTick();
  } else if (alarm.name === 'snapshotTimer') {
    await SnapshotService.createSnapshot();
  }
}

async function handleIdleStateChange(newState) {
  await ready;
  if (newState === 'locked' || newState === 'idle') {
    await autoSuspendTick();
  }
}

async function markTabActive(tabId) {
  if (!tabId || tabId === chrome.tabs.TAB_ID_NONE) {
    return;
  }
  lastActiveCache[tabId] = Date.now();
  await sessionSet(SESSION_LAST_ACTIVE_KEY, lastActiveCache);
}

async function loadLastActive() {
  const stored = await sessionGet(SESSION_LAST_ACTIVE_KEY);
  lastActiveCache = stored[SESSION_LAST_ACTIVE_KEY] || {};
}

async function autoSuspendTick() {
  const settings = await ensureSettings();
  const tabs = await chrome.tabs.query({ windowType: 'normal' });
  const now = Date.now();
  for (const tab of tabs) {
    if (!(await shouldSuspendTab(tab, settings, now))) {
      continue;
    }
    await suspendTab(tab, 'auto');
  }
}

async function shouldSuspendTab(tab, settings, now) {
  if (!tab || !tab.id) return false;
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
    return false;
  }
  if (settings.excludeActive && tab.active) {
    return false;
  }
  if (settings.excludePinned && tab.pinned) {
    return false;
  }
  if (settings.excludeAudible && tab.audible) {
    return false;
  }
  if (settings.whitelist.length && matchesWhitelist(tab.url, settings.whitelist)) {
    return false;
  }
  const lastActive = lastActiveCache[tab.id] || tab.lastAccessed || now;
  const threshold = settings.autoSuspendMinutes * 60 * 1000;
  if (!threshold || threshold <= 0) {
    return false;
  }
  return now - lastActive >= threshold;
}

async function suspendTab(tab, reason) {
  const settings = await ensureSettings();
  if (settings.unsuspendMethod === 'manual') {
    return suspendViaPage(tab, reason);
  }
  return suspendViaDiscard(tab, reason);
}

async function suspendViaDiscard(tab, reason) {
  if (tab.discarded) {
    return false;
  }
  try {
    await chrome.tabs.discard(tab.id);
    const updated = await chrome.tabs.get(tab.id);
    if (!updated.discarded) {
      throw new Error('Tab was not discarded');
    }
    const state = await loadState();
    if (state) {
      state.suspendedTabs[tab.id] = {
        url: tab.url,
        title: tab.title,
        windowId: tab.windowId,
        suspendedAt: Date.now(),
        method: 'discard',
        reason,
      };
      await saveState(state);
    }
    return true;
  } catch (err) {
    Logger.warn('Failed to discard tab, falling back to parked page suspension', err);
    return suspendViaPage(tab, reason);
  }
}

async function suspendViaPage(tab, reason) {
  const state = await loadState();
  if (!state) {
    Logger.warn('State locked; cannot record suspension');
    return false;
  }
  const token = crypto.randomUUID();
  const metadata = {
    url: tab.url,
    title: tab.title,
    windowId: tab.windowId,
    suspendedAt: Date.now(),
    method: 'page',
    reason,
    token,
  };
  state.suspendedTabs[tab.id] = metadata;
  await saveState(state);

  const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
  suspendedUrl.searchParams.set('token', token);
  suspendedUrl.searchParams.set('url', tab.url);
  if (tab.title) {
    suspendedUrl.searchParams.set('title', tab.title);
  }
  if (tab.favIconUrl) {
    suspendedUrl.searchParams.set('favicon', tab.favIconUrl);
  }

  try {
    await chrome.tabs.update(tab.id, { url: suspendedUrl.toString() });
    return true;
  } catch (err) {
    Logger.warn('Failed to navigate tab to parked page', err);
    delete state.suspendedTabs[tab.id];
    await saveState(state);
    return false;
  }
}

async function maybeAutoUnsuspend(tab) {
  const state = await loadState();
  if (!state || !state.suspendedTabs[tab.id]) {
    return;
  }
  const metadata = state.suspendedTabs[tab.id];
  if ((await ensureSettings()).unsuspendMethod !== 'activate') {
    return;
  }
  const resumed = await resumeSuspendedTab(tab.id, metadata, { focus: false });
  if (resumed) {
    delete state.suspendedTabs[tab.id];
    await saveState(state);
  }
}

async function scheduleAutoSuspendAlarm() {
  const settings = await ensureSettings();
  const threshold = Math.max(1, Math.round(settings.autoSuspendMinutes));
  const period = Math.min(60, Math.max(1, Math.round(threshold / 3)));
  await chrome.alarms.clear('autoSuspend');
  await chrome.alarms.create('autoSuspend', {
    delayInMinutes: period,
    periodInMinutes: period,
  });
}

async function resumeSuspendedTab(tabId, metadata, { focus = true } = {}) {
  if (!metadata) {
    return false;
  }
  try {
    if (metadata.method === 'discard') {
      if (focus) {
        await chrome.tabs.update(tabId, { active: true });
      }
      // Chrome will reload discarded tabs automatically on activation.
      return true;
    }
    const updateInfo = { url: metadata.url };
    if (focus) {
      updateInfo.active = true;
    }
    await chrome.tabs.update(tabId, updateInfo);
    return true;
  } catch (err) {
    Logger.warn('Failed to resume suspended tab', err);
    return false;
  }
}

async function encryptPayload(data) {
  if (!cryptoKey) {
    throw new Error('Encryption key not available');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(cipher)) };
}

async function decryptPayload(payload) {
  if (!cryptoKey) {
    throw new Error('Encryption key not available');
  }
  const iv = new Uint8Array(payload.iv);
  const ct = new Uint8Array(payload.ct);
  const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct);
  const text = new TextDecoder().decode(plainBuffer);
  return JSON.parse(text);
}

async function ensureCryptoKey(passphrase) {
  const settings = await ensureSettings();
  let salt = settings.encryption.salt;
  if (!salt) {
    salt = Array.from(crypto.getRandomValues(new Uint8Array(16)));
    await saveSettings({
      ...settings,
      encryption: {
        ...settings.encryption,
        salt,
      },
    });
  }
  const saltBytes = new Uint8Array(salt);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  cryptoKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: settings.encryption.iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt', 'exportKey']
  );

  // Save key to session storage for persistence across SW restarts
  await saveKeyToSession(cryptoKey);
  // Remove device key if switching to passphrase
  await chrome.storage.local.remove('deviceKey');

  await reencryptState();
}

async function ensureDeviceKey() {
  const settings = await ensureSettings();
  // If user has a salt, they are using a passphrase, so don't use device key
  if (settings.encryption.salt) {
    return;
  }

  const stored = await chrome.storage.local.get('deviceKey');
  if (stored.deviceKey) {
    try {
      cryptoKey = await crypto.subtle.importKey(
        'jwk',
        stored.deviceKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt', 'exportKey']
      );
      await saveKeyToSession(cryptoKey);
      return;
    } catch (err) {
      Logger.warn('Failed to import device key', err);
    }
  }

  // Generate new device key
  cryptoKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'exportKey']
  );
  const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
  await chrome.storage.local.set({ deviceKey: jwk });
  await saveKeyToSession(cryptoKey);
  Logger.info('Generated new device encryption key');
}

async function reencryptState() {
  const stored = await chrome.storage.local.get(STATE_KEY);
  const payload = stored[STATE_KEY];
  const pending = await loadPendingState();
  let merged = { suspendedTabs: {} };

  // Try to decrypt with CURRENT key (which is already set)
  // Note: This logic assumes we are re-encrypting FROM a state that we can read.
  // But if we just switched keys, we might not be able to read the old state unless we decrypted it BEFORE switching.
  // Ideally, the UI should handle "Decrypt old -> Switch Key -> Encrypt new".
  // For simplicity here, we assume the state is either plain or we accept starting fresh/merging pending.

  if (payload && payload.plain) {
    merged = mergeStates(payload.plain, pending);
  } else {
    // If it was encrypted with a DIFFERENT key, we can't read it now.
    // We just use pending state.
    merged = pending;
  }

  cachedState = merged;
  stateLocked = false;
  await clearPendingState();
  await saveState(cachedState);
}

async function saveKeyToSession(key) {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', key);
    await sessionSet('cryptoKey', jwk);
  } catch (err) {
    Logger.warn('Failed to save key to session', err);
  }
}

async function restoreKeyFromSession() {
  try {
    const stored = await sessionGet('cryptoKey');
    const jwk = stored.cryptoKey;
    if (jwk) {
      cryptoKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }
  } catch (err) {
    Logger.warn('Failed to restore key from session', err);
  }
}

async function clearCryptoKey() {
  // Clearing crypto key means switching back to device key (or no key if disabled, but we enforce enabled)
  cryptoKey = null;
  await sessionRemove('cryptoKey');

  const settings = await ensureSettings();
  await saveSettings({
    ...settings,
    encryption: {
      ...settings.encryption,
      salt: null, // Remove salt to indicate no passphrase
    },
  });

  await ensureDeviceKey();
  await reencryptState();
}

function handleMessage(message, sender, sendResponse) {
  (async () => {
    // Wait for init before handling messages that might depend on settings/state
    await ready;

    switch (message.type) {
      case 'GET_SETTINGS': {
        const settings = await ensureSettings();
        sendResponse(settings);
        break;
      }
      case 'SAVE_SETTINGS': {
        await saveSettings(message.payload);
        sendResponse({ ok: true });
        break;
      }
      case 'SET_PASSPHRASE': {
        if (message.passphrase) {
          await ensureCryptoKey(message.passphrase);
          await loadState();
          if (cachedState) {
            await saveState(cachedState);
          }
          sendResponse({ ok: true });
        } else {
          await clearCryptoKey();
          sendResponse({ ok: true });
        }
        break;
      }
      case 'SUSPEND_CURRENT': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab) {
          await suspendTab(tab, 'manual');
        }
        sendResponse({ ok: true });
        break;
      }
      case 'SUSPEND_INACTIVE': {
        const tabs = await chrome.tabs.query({ windowType: 'normal' });
        const settings = await ensureSettings();
        for (const tab of tabs) {
          if (tab.active) continue;
          if (await shouldSuspendTab(tab, settings, Date.now())) {
            await suspendTab(tab, 'manual');
          }
        }
        sendResponse({ ok: true });
        break;
      }
      case 'RESUME_TAB': {
        if (typeof message.tabId === 'number') {
          const state = await loadState();
          const entry = state?.suspendedTabs?.[message.tabId];
          if (entry) {
            const resumed = await resumeSuspendedTab(message.tabId, entry, { focus: true });
            if (resumed) {
              delete state.suspendedTabs[message.tabId];
              await saveState(state);
            }
          } else {
            try {
              await chrome.tabs.update(message.tabId, { active: true });
            } catch (err) {
              Logger.warn('Failed to activate tab during resume fallback', err);
            }
          }
        }
        sendResponse({ ok: true });
        break;
      }
      case 'GET_STATE': {
        const state = await loadState();
        if (stateLocked) {
          sendResponse({ locked: true });
        } else {
          sendResponse({ locked: false, state });
        }
        break;
      }
      case 'SUSPENDED_VIEW_INFO': {
        const state = await loadState();
        if (!state) {
          sendResponse({ locked: true });
          break;
        }
        const { token } = message;
        let entry;
        const maybeId = Number(message.tabId);
        if (Number.isInteger(maybeId)) {
          const tabEntry = state.suspendedTabs?.[maybeId];
          if (tabEntry?.token === token) {
            entry = tabEntry;
          }
        }
        if (!entry && token) {
          entry = Object.values(state.suspendedTabs || {}).find(item => item.token === token);
        }
        if (!entry) {
          sendResponse({ found: false });
          break;
        }
        sendResponse({ found: true, info: entry });
        break;
      }
      case 'UNSUSPEND_TOKEN': {
        const state = await loadState();
        if (!state) {
          sendResponse({ locked: true });
          break;
        }
        const { token } = message;
        const tabId = Number(message.tabId);
        if (!Number.isInteger(tabId)) {
          sendResponse({ ok: false });
          break;
        }
        const entry = state.suspendedTabs[tabId];
        if (entry && entry.token === token) {
          const resumed = await resumeSuspendedTab(tabId, entry, { focus: true });
          if (resumed) {
            delete state.suspendedTabs[tabId];
            await saveState(state);
            sendResponse({ ok: true });
          } else {
            sendResponse({ ok: false });
          }
        } else {
          sendResponse({ ok: false });
        }
        break;
      }
      case 'GET_SNAPSHOTS': {
        const snapshots = await SnapshotService.getSnapshots();
        sendResponse({ snapshots });
        break;
      }
      case 'RESTORE_SNAPSHOT': {
        try {
          await SnapshotService.restoreSnapshot(message.snapshotId);
          sendResponse({ ok: true });
        } catch (err) {
          Logger.error('Restore failed', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      default:
        sendResponse({ ok: false, error: 'Unknown message' });
    }
  })();
  return true;
}
