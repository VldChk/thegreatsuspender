import Logger from './logger.js';
import {
  initializeEncryption,
  getCryptoKey,
  isEncryptionLocked,
  getEncryptionLockReason,
  unlockWithPasskey as decryptWithPasskey,
  setPasskey as persistPasskey,
  removePasskey as clearPasskey,
  setCloudBackupEnabled as updateCloudBackup,
  clearSessionKey,
  clearKeyRecords,
  generateAndPersistDataKey,
  getEncryptionStatusPayload,
  loadKeyRecord,
  retryImportPlaintextKey,
} from './encryption.js';
import { ensureSettings, saveSettings as persistSettings, defaultSettings, SETTINGS_KEY } from './settings.js';
import { sessionGet, sessionSet, sessionRemove } from './session.js';

const STATE_KEY = 'suspenderState';
const SESSION_LAST_ACTIVE_KEY = 'lastActive';
const SESSION_PENDING_STATE_KEY = 'pendingSuspenderState';
const SNAPSHOT_RETENTION_DAYS = 7;
const SNAPSHOT_MAX = 20;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const SNAPSHOT_PERIOD_MINUTES = 180;

let cachedState = null;
let lastActiveCache = {};

function hasCryptoKey() {
  return !!getCryptoKey();
}

function encryptionIsLocked() {
  return isEncryptionLocked();
}

function encryptionReason() {
  return getEncryptionLockReason();
}

function stateIsLocked() {
  return encryptionIsLocked() || !hasCryptoKey();
}

// --- Snapshot Service ---

const SnapshotService = {
  async createSnapshot() {
    const previousLock = snapshotLock;
    let release;
    snapshotLock = new Promise(resolve => { release = resolve; });

    try {
      await previousLock; // serialize

      const state = await loadState();

      // Validate state against actual open tabs to ensure we only snapshot truly suspended tabs
      await validateState(state);

      if (!state || !state.suspendedTabs || Object.keys(state.suspendedTabs).length === 0) {
        return;
      }

      // We only create snapshots if we have the key to encrypt them (if encryption is on)
      const settings = await ensureSettings();
      if (settings.encryption.enabled && (encryptionIsLocked() || !hasCryptoKey())) {
        Logger.warn('Skipping snapshot: Encryption enabled but key not available');
        return;
      }

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
      const existing = stored.backups || [];
      const backups = pruneSnapshots([...existing, snapshot]);

      await chrome.storage.local.set({ backups });
      Logger.info('Snapshot created', { id: snapshot.id, tabCount: snapshot.tabCount });
    } catch (err) {
      Logger.error('Failed to create snapshot', err);
    } finally {
      release?.();
    }
  },

  async getSnapshots() {
    const stored = await chrome.storage.local.get('backups');
    const pruned = pruneSnapshots(stored.backups || []);
    if (pruned.length !== (stored.backups || []).length) {
      await chrome.storage.local.set({ backups: pruned });
    }
    return pruned.map(b => ({
      id: b.id,
      timestamp: b.timestamp,
      tabCount: b.tabCount
    }));
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
      if (encryptionIsLocked() || !hasCryptoKey()) {
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
  },

  async openSnapshot(snapshotId, unsuspend = false) {
    const stored = await chrome.storage.local.get('backups');
    const backups = stored.backups || [];
    const snapshot = backups.find(b => b.id === snapshotId);

    if (!snapshot) {
      throw new Error('Snapshot not found');
    }

    let restoredState;
    if (snapshot.data.ct) {
      if (encryptionIsLocked() || !hasCryptoKey()) {
        throw new Error('Encryption key required');
      }
      restoredState = await decryptPayload(snapshot.data);
    } else if (snapshot.data.plain) {
      restoredState = snapshot.data.plain;
    } else {
      throw new Error('Invalid snapshot format');
    }

    const tabsToOpen = Object.values(restoredState.suspendedTabs || {});
    if (tabsToOpen.length === 0) {
      return;
    }

    const win = await chrome.windows.create({ focused: true });
    const settings = await ensureSettings();
    const embedOriginalUrl = settings.embedOriginalUrl !== false;

    // Load current state to append new suspended tabs
    const currentState = await loadState();

    for (const entry of tabsToOpen) {
      if (unsuspend) {
        await chrome.tabs.create({ windowId: win.id, url: entry.url, active: false });
      } else {
        // Create as suspended
        const token = crypto.randomUUID();
        const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
        suspendedUrl.searchParams.set('token', token);
        if (embedOriginalUrl) {
          suspendedUrl.searchParams.set('url', entry.url);
          if (entry.title) suspendedUrl.searchParams.set('title', entry.title);
          // We don't have favicon in metadata usually, but if we did:
          if (entry.favIconUrl) suspendedUrl.searchParams.set('favicon', entry.favIconUrl);
        }

        const newTab = await chrome.tabs.create({ windowId: win.id, url: suspendedUrl.toString(), active: false });

        // Add to current state
        currentState.suspendedTabs[newTab.id] = {
          ...entry,
          token,
          windowId: win.id,
          suspendedAt: Date.now(), // Reset timestamp to now as it's a new suspension
          tokenIssuedAt: Date.now(),
          tokenUsed: false,
          reason: 'restored-from-snapshot'
        };
      }
    }

    // Remove the default blank tab if we created others
    const [blankTab] = await chrome.tabs.query({ windowId: win.id, url: 'chrome://newtab/' });
    if (blankTab && tabsToOpen.length > 0) {
      // Only remove if it's the only one, but we just added tabs.
      // Actually chrome.windows.create with url would be better but we have multiple URLs.
      // chrome.windows.create creates a default tab if no url.
      await chrome.tabs.remove(blankTab.id);
    }

    if (!unsuspend) {
      await saveState(currentState);
    }
  }
};

function pruneSnapshots(list) {
  if (!Array.isArray(list)) return [];
  const cutoff = Date.now() - SNAPSHOT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const filtered = list.filter(item => typeof item.timestamp === 'number' && item.timestamp >= cutoff);
  filtered.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  return filtered.slice(0, SNAPSHOT_MAX);
}

async function getSnapshotById(snapshotId) {
  const stored = await chrome.storage.local.get('backups');
  let backups = stored.backups || [];
  backups = pruneSnapshots(backups);
  const snapshot = backups.find(b => b.id === snapshotId);
  if (backups.length !== (stored.backups || []).length) {
    await chrome.storage.local.set({ backups });
  }
  return snapshot || null;
}

async function getSnapshotData(snapshot) {
  if (!snapshot || !snapshot.data) {
    throw new Error('Snapshot missing data');
  }
  if (snapshot.data.ct) {
    const state = await decryptPayload(snapshot.data);
    return state;
  }
  if (snapshot.data.plain) {
    return snapshot.data.plain;
  }
  throw new Error('Invalid snapshot format');
}

async function openSnapshotTabs(snapshotId, { unsuspend = false } = {}) {
  const snapshot = await getSnapshotById(snapshotId);
  if (!snapshot) {
    return { ok: false, error: 'not-found' };
  }
  const needsKey = !!snapshot.data?.ct;
  if (needsKey && (encryptionIsLocked() || !hasCryptoKey())) {
    return { ok: false, locked: true };
  }
  const state = await getSnapshotData(snapshot);
  const entries = Object.values(state?.suspendedTabs || {});
  if (!entries.length) {
    return { ok: true, opened: 0 };
  }

  const win = await chrome.windows.create({ url: 'about:blank', focused: true });
  const windowId = win.id;
  const tabs = win.tabs || [];
  let firstTabId = tabs[0]?.id || null;
  let opened = 0;
  const settings = await ensureSettings();
  const embedOriginalUrl = settings.embedOriginalUrl !== false;

  // Load current state to append new suspended tabs
  const currentState = await loadState();
  const existingUrls = new Set(Object.values(currentState?.suspendedTabs || {}).map(e => e.url));
  const seenUrls = new Set();

  for (const [index, entry] of entries.entries()) {
    if (!unsuspend) {
      const urlKey = entry.url;
      if (existingUrls.has(urlKey) || seenUrls.has(urlKey)) {
        continue; // Avoid duplicates in state and tabs
      }
      seenUrls.add(urlKey);
    }
    let urlToOpen;
    let isSuspended = false;
    let token = null;

    if (unsuspend) {
      urlToOpen = entry.url;
    } else {
      // Construct suspended URL directly
      token = crypto.randomUUID();
      const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
      suspendedUrl.searchParams.set('token', token);
      if (embedOriginalUrl) {
        suspendedUrl.searchParams.set('url', entry.url);
        if (entry.title) suspendedUrl.searchParams.set('title', entry.title);
        if (entry.favIconUrl) suspendedUrl.searchParams.set('favicon', entry.favIconUrl);
      }

      urlToOpen = suspendedUrl.toString();
      isSuspended = true;
    }

    let tab;
    if (index === 0 && firstTabId) {
      tab = await chrome.tabs.update(firstTabId, { url: urlToOpen, active: true });
    } else {
      tab = await chrome.tabs.create({ windowId, url: urlToOpen, active: false });
    }
    opened += 1;

    if (isSuspended) {
      // Add to current state manually since we bypassed suspendTab
      currentState.suspendedTabs[tab.id] = {
        ...entry,
        token,
        windowId,
        suspendedAt: Date.now(),
        tokenIssuedAt: Date.now(),
        tokenUsed: false,
        reason: 'restored-from-snapshot'
      };
    }
  }

  if (!unsuspend) {
    await saveState(currentState);
  }

  return { ok: true, opened };
}

// --- Initialization ---

// Create a promise that resolves when initialization is complete.
// This ensures that event handlers can wait for settings/state to be loaded.
  let readyResolve;
  const ready = new Promise(resolve => {
    readyResolve = resolve;
  });

let snapshotLock = Promise.resolve();

async function init() {
  try {
    await ensureSettings();
    await loadLastActive();

    await initializeEncryption();

    // Only schedule if not already scheduled
    const alarm = await chrome.alarms.get('autoSuspend');
    if (!alarm) {
      await scheduleAutoSuspendAlarm();
    }

    const snapshotAlarm = await chrome.alarms.get('snapshotTimer');
    if (!snapshotAlarm) {
      await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
    }

    const validateAlarm = await chrome.alarms.get('stateValidator');
    if (!validateAlarm) {
      await scheduleStateValidationAlarm();
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
chrome.storage.onChanged.addListener(handleStorageChanged);

// --- Event Handlers ---

async function handleInstalled(details) {
  // onInstalled is a special case where we might want to force a reset
  if (details.reason === 'install') {
    await chrome.storage.local.set({ [SETTINGS_KEY]: defaultSettings });
    await saveState({ suspendedTabs: {} });
    await scheduleAutoSuspendAlarm(); // Force schedule on install
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
    try {
      await chrome.runtime.openOptionsPage();
    } catch (err) {
      Logger.warn('Failed to open options page on install', err);
    }
  } else if (details.reason === 'update') {
    await ready; // Wait for init to ensure we have settings
    await scheduleAutoSuspendAlarm(); // Ensure alarm is correct after update
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
  }
}

async function handleStartup() {
  await ready;
}

function handleStorageChanged(changes, areaName) {
  if (areaName === 'local' && changes[STATE_KEY]) {
    cachedState = null;
  }
}

async function saveSettings(nextSettings) {
  const merged = {
    ...defaultSettings,
    ...nextSettings,
    encryption: {
      ...defaultSettings.encryption,
      ...(nextSettings.encryption || {}),
      enabled: true,
      cloudBackupEnabled: nextSettings.encryption?.cloudBackupEnabled ?? defaultSettings.encryption.cloudBackupEnabled,
    },
  };
  await persistSettings(merged);
  await scheduleAutoSuspendAlarm(); // Reschedule when settings change
}

async function loadState() {
  if (stateIsLocked()) {
    cachedState = await loadPendingState();
    return cachedState;
  }
  if (cachedState) {
    return cachedState;
  }
  const stored = await chrome.storage.local.get(STATE_KEY);
  const payload = stored[STATE_KEY];
  if (payload && payload.ct) {
    try {
      cachedState = await decryptPayload(payload);
      await clearPendingState();
    } catch (err) {
      Logger.warn('Failed to decrypt state', err);
      cachedState = { suspendedTabs: {} };
    }
  } else if (payload && payload.plain) {
    cachedState = payload.plain;
  } else {
    cachedState = { suspendedTabs: {} };
  }
  return cachedState;
}

let reconciliationLock = Promise.resolve();

async function saveState(state) {
  // Wait for any ongoing reconciliation to finish
  await reconciliationLock;

  cachedState = state;
  const settings = await ensureSettings();
  if (settings.encryption.enabled) {
    if (stateIsLocked()) {
      await savePendingState(state);
      return;
    }
    const encrypted = await encryptPayload(state);
    await chrome.storage.local.set({ [STATE_KEY]: encrypted });
    await clearPendingState();
  } else {
    await chrome.storage.local.set({ [STATE_KEY]: { plain: state } });
    await clearPendingState();
  }
}

function wildcardToRegExp(pattern) {
  // Normalize pattern: remove protocol, www, trailing slash
  let p = pattern.trim().toLowerCase();
  p = p.replace(/^(https?:\/\/)?(www\.)?/, '');
  if (p.endsWith('/')) {
    p = p.slice(0, -1);
  }

  // Escape regex characters except *
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');

  // Convert * to .*
  // If pattern ends with *, it matches prefix.
  // If pattern starts with *, it matches suffix.
  // If no *, we match exact domain or path prefix.

  let regexString = escaped.replace(/\*/g, '.*');

  // If it's just a domain like "leetcode.com", we want to match "leetcode.com" AND "leetcode.com/problems" AND "sub.leetcode.com"
  // But we don't want "myleetcode.com"

  // Simple heuristic: if no slash, assume domain match
  if (!p.includes('/')) {
    // Match exact domain or subdomain
    // regex: (^|\.)leetcode\.com(\/|$)
    regexString = `(^|\\.)${regexString}(\\/|$)`;
  } else {
    // Path match, anchor start
    regexString = `^${regexString}`;
  }

  return new RegExp(regexString);
}

function matchesWhitelist(url, whitelist) {
  if (!url) return false;

  // Normalize URL for matching: lower-case host/path, strip protocol and www
  let normalized = '';
  try {
    const u = new URL(url);
    const host = (u.hostname || '').toLowerCase().replace(/^www\./, '');
    const path = (u.pathname || '').toLowerCase();
    normalized = `${host}${path}`;
  } catch (err) {
    // Fallback: strip protocol/www manually
    normalized = url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');
  }

  return whitelist.some(pattern => {
    try {
      return wildcardToRegExp(pattern).test(normalized);
    } catch (e) {
      Logger.warn('Invalid whitelist pattern', pattern, e);
      return false;
    }
  });
}

async function unsuspendWhitelistedTabs(whitelist) {
  const state = await loadState();
  if (!state || !state.suspendedTabs) return;

  const entries = Object.entries(state.suspendedTabs);
  for (const [tabIdStr, entry] of entries) {
    if (matchesWhitelist(entry.url, whitelist)) {
      const tabId = Number(tabIdStr);
      Logger.info('Auto-unsuspending whitelisted tab', { tabId, url: entry.url });
      await resumeSuspendedTab(tabId, entry, { focus: false, reloadIfDiscarded: true });
      delete state.suspendedTabs[tabId];
    }
  }
  await saveState(state);
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
  const merged = { suspendedTabs: {} };
  const addOrMerge = (tabId, entry) => {
    const existing = merged.suspendedTabs[tabId];
    if (!existing) {
      merged.suspendedTabs[tabId] = entry;
      return;
    }
    const existingTs = Number(existing.suspendedAt ?? existing.tokenIssuedAt ?? 0);
    const incomingTs = Number(entry.suspendedAt ?? entry.tokenIssuedAt ?? 0);
    if (incomingTs > existingTs) {
      merged.suspendedTabs[tabId] = { ...existing, ...entry };
    } else if (!existingTs && incomingTs) {
      merged.suspendedTabs[tabId] = { ...existing, ...entry };
    }
  };

  for (const [tabId, entry] of Object.entries(primary?.suspendedTabs || {})) {
    merged.suspendedTabs[tabId] = entry;
  }
  for (const [tabId, entry] of Object.entries(secondary?.suspendedTabs || {})) {
    addOrMerge(tabId, entry);
  }
  return merged;
}

async function validateState(state) {
  if (!state || !state.suspendedTabs) return;

  const tabIds = Object.keys(state.suspendedTabs).map(Number);
  if (tabIds.length === 0) return;

  // Batch query tabs once to avoid N calls
  const allTabs = await chrome.tabs.query({});
  const tabMap = new Map(allTabs.map(t => [t.id, t]));
  const suspendedPagePrefix = chrome.runtime.getURL('suspended.html');

  let changed = false;
  for (const tabId of tabIds) {
    const entry = state.suspendedTabs[tabId];
    const tab = tabMap.get(tabId);

    if (!tab) {
      delete state.suspendedTabs[tabId];
      changed = true;
      continue;
    }

    // Never keep incognito entries
    if (tab.incognito) {
      delete state.suspendedTabs[tabId];
      changed = true;
      continue;
    }

    if (entry.method === 'discard') {
      if (!tab.discarded) {
        delete state.suspendedTabs[tabId];
        changed = true;
      }
    } else if (entry.method === 'page') {
      if (!tab.url.startsWith(suspendedPagePrefix)) {
        delete state.suspendedTabs[tabId];
        changed = true;
      }
    } else {
      // Unknown method — prune
      delete state.suspendedTabs[tabId];
      changed = true;
    }
  }

  if (changed) {
    await saveState(state);
  }
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
    await validateState(state);
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
      const settings = await ensureSettings();
      // Only record discards we would intentionally suspend (eligibility rules + non-incognito)
      if (tab.incognito || !(await shouldSuspendTab(tab, settings, Date.now()))) {
        return;
      }
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
  const currentState = await loadState();
  if (currentState) {
    await validateState(currentState);
  }
}

async function handleAlarm(alarm) {
  await ready;
  if (alarm.name === 'autoSuspend') {
    await autoSuspendTick();
  } else if (alarm.name === 'snapshotTimer') {
    await SnapshotService.createSnapshot();
  } else if (alarm.name === 'stateValidator') {
    const state = await loadState();
    if (state) {
      await validateState(state);
    }
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
  const candidates = [];
  for (const tab of tabs) {
    if (await shouldSuspendTab(tab, settings, now)) {
      candidates.push(tab);
    }
  }

  const limit = 5;
  let index = 0;
  const worker = async () => {
    while (index < candidates.length) {
      const current = candidates[index++];
      try {
        await suspendTab(current, 'auto');
      } catch (err) {
        if (!err.message.includes('No tab with id')) {
          Logger.warn('Failed to auto-suspend tab', { tabId: current.id, err });
        }
      }
    }
  };

  const workers = Array.from({ length: Math.min(limit, candidates.length) }, () => worker());
  await Promise.all(workers);
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

async function cacheFavicon(faviconUrl) {
  if (!faviconUrl || faviconUrl.startsWith('data:')) return faviconUrl;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const response = await fetch(faviconUrl, { signal: controller.signal });
    clearTimeout(timeout);
    const blob = await response.blob();
    return await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
  } catch (err) {
    Logger.warn('Failed to cache favicon', { url: faviconUrl, err });
    return null;
  }
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

    // Re-check shortly after to detect silent reloads
    await new Promise(resolve => setTimeout(resolve, 1000));
    const rechecked = await chrome.tabs.get(tab.id).catch(() => null);
    if (!rechecked || !rechecked.discarded) {
      Logger.warn('Discard did not persist; falling back to page suspension', { tabId: tab.id, url: tab.url });
      return suspendViaPage(tab, reason);
    }
    const state = await loadState();
    if (state) {
      // Cache favicon if available
      let faviconDataUri = null;
      if (tab.favIconUrl) {
        faviconDataUri = await cacheFavicon(tab.favIconUrl);
      }

      const metadata = {
        url: tab.url,
        title: tab.title,
        windowId: tab.windowId,
        suspendedAt: Date.now(),
        method: 'discard',
        reason,
        favIconUrl: tab.favIconUrl,
        faviconDataUri // Store cached Data URI
      };
      state.suspendedTabs[tab.id] = metadata;
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
  const settings = await ensureSettings();
  const embedOriginalUrl = settings.embedOriginalUrl !== false;

  // Cache favicon if available
  let faviconDataUri = null;
  if (tab.favIconUrl) {
    faviconDataUri = await cacheFavicon(tab.favIconUrl);
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
    tokenIssuedAt: Date.now(),
    tokenUsed: false,
    favIconUrl: tab.favIconUrl,
    faviconDataUri // Store cached Data URI
  };
  const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
  suspendedUrl.searchParams.set('token', token);
  if (embedOriginalUrl) {
    suspendedUrl.searchParams.set('url', tab.url);
    if (tab.title) {
      suspendedUrl.searchParams.set('title', tab.title);
    }
    if (tab.favIconUrl) {
      suspendedUrl.searchParams.set('favicon', tab.favIconUrl);
    }
  }

  try {
    await chrome.tabs.update(tab.id, { url: suspendedUrl.toString() });
    state.suspendedTabs[tab.id] = metadata;
    await saveState(state);
    return true;
  } catch (err) {
    Logger.warn('Failed to navigate tab to parked page', err);
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

async function scheduleStateValidationAlarm() {
  // Run every 15 minutes to keep state clean
  await chrome.alarms.clear('stateValidator');
  await chrome.alarms.create('stateValidator', {
    periodInMinutes: 15,
  });
}

async function resumeSuspendedTab(tabId, metadata, { focus = true, reloadIfDiscarded = false } = {}) {
  if (!metadata) {
    return false;
  }
  try {
    if (metadata.method === 'discard') {
      if (focus) {
        await chrome.tabs.update(tabId, { active: true });
      } else if (reloadIfDiscarded) {
        await chrome.tabs.reload(tabId);
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
  const key = getCryptoKey();
  if (!key) {
    throw new Error('Encryption key not available');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(cipher)) };
}

async function decryptPayload(payload) {
  const key = getCryptoKey();
  if (!key) {
    throw new Error('Encryption key not available');
  }
  const iv = new Uint8Array(payload.iv);
  const ct = new Uint8Array(payload.ct);
  const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  const text = new TextDecoder().decode(plainBuffer);
  return JSON.parse(text);
}

async function reconcilePendingStateAfterUnlock() {
  // Create a lock promise that resolves when this function completes
  let releaseLock;
  const lockPromise = new Promise(resolve => { releaseLock = resolve; });
  // Chain it to the existing lock to ensure sequential execution if multiple unlocks happen (unlikely but safe)
  const previousLock = reconciliationLock;
  reconciliationLock = lockPromise;

  try {
    await previousLock; // Wait for any previous operation

    const stored = await chrome.storage.local.get(STATE_KEY);
    const payload = stored[STATE_KEY];
    const pending = await loadPendingState();
    let merged = mergeStates({ suspendedTabs: {} }, pending);

    if (payload && payload.ct) {
      try {
        const decrypted = await decryptPayload(payload);
        merged = mergeStates(decrypted, pending);
      } catch (err) {
        Logger.warn('Failed to decrypt stored state after unlock', err);
      }
    } else if (payload && payload.plain) {
      merged = mergeStates(payload.plain, pending);
    }

    cachedState = merged;
    await clearPendingState();

    // We must call the internal save logic directly or ensure saveState doesn't deadlock.
    // Since saveState waits for reconciliationLock, calling it here would deadlock.
    // So we duplicate the save logic or extract a lower-level save.
    // For simplicity, let's just do the save here since we know the state is unlocked.
    const encrypted = await encryptPayload(cachedState);
    await chrome.storage.local.set({ [STATE_KEY]: encrypted });

  } finally {
    releaseLock();
  }
}

async function unlockAndReconcile(passkey) {
  const result = await decryptWithPasskey(passkey);
  if (result?.ok) {
    await reconcilePendingStateAfterUnlock();
  }
  return result;
}

async function resetEncryption() {
  await clearSessionKey();
  await clearKeyRecords();
  cachedState = null;
  await chrome.storage.local.remove([STATE_KEY, 'backups']);
  await clearPendingState();

  const settings = await ensureSettings();
  await generateAndPersistDataKey(settings.encryption.cloudBackupEnabled);
  cachedState = { suspendedTabs: {} };
  await saveState(cachedState);
  return { ok: true };
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
      case 'GET_ENCRYPTION_STATUS': {
        const settings = await ensureSettings();
        const record = await loadKeyRecord(settings.encryption.cloudBackupEnabled);
        const payload = getEncryptionStatusPayload(settings, record);
        sendResponse(payload);
        break;
      }
      case 'SAVE_SETTINGS': {
        const { payload } = message;
        await saveSettings(payload);

        // Check if we need to auto-unsuspend tabs based on new whitelist
        if (payload.whitelist && payload.whitelist.length > 0) {
          unsuspendWhitelistedTabs(payload.whitelist).catch(err => {
            Logger.error('Failed to auto-unsuspend whitelisted tabs', err);
          });
        }

        sendResponse({ ok: true });
        break;
      }
      case 'UNLOCK_WITH_PASSKEY': {
        const result = await unlockAndReconcile(message.passkey);
        sendResponse(result);
        break;
      }
      case 'RETRY_IMPORT_KEY': {
        const result = await retryImportPlaintextKey();
        if (result?.ok) {
          await reconcilePendingStateAfterUnlock();
        }
        sendResponse(result);
        break;
      }
      case 'SET_PASSKEY': {
        const result = await persistPasskey(message.passkey);
        sendResponse(result);
        break;
      }
      case 'REMOVE_PASSKEY': {
        const result = await clearPasskey();
        sendResponse(result);
        break;
      }
      case 'SET_CLOUD_BACKUP': {
        const result = await updateCloudBackup(message.enabled);
        sendResponse(result);
        break;
      }
      case 'RESET_ENCRYPTION': {
        const result = await resetEncryption();
        sendResponse(result);
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
      if (typeof message.tabId === 'number' && Number.isInteger(message.tabId)) {
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
      case 'RESUME_ALL': {
        const state = await loadState();
        if (!state || !state.suspendedTabs) {
          sendResponse({ ok: true });
          break;
        }
        const entries = Object.entries(state.suspendedTabs);
        for (const [tabIdStr, entry] of entries) {
          const tabId = Number(tabIdStr);
          // We don't focus on individual tabs when resuming all
          const resumed = await resumeSuspendedTab(tabId, entry, { focus: false, reloadIfDiscarded: true });
          if (resumed) {
            delete state.suspendedTabs[tabId];
          }
        }
        await saveState(state);
        sendResponse({ ok: true });
        break;
      }
      case 'GET_STATE': {
        const state = await loadState();
        if (stateIsLocked()) {
          sendResponse({ locked: true, reason: encryptionReason() });
          break;
        }
        await validateState(state);
        sendResponse({ locked: false, state });
        break;
      }
      case 'SUSPENDED_VIEW_INFO': {
        const state = await loadState();
        if (!state || stateIsLocked()) {
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
        if (!entry || entry.token !== token) {
          sendResponse({ ok: false, error: 'invalid-token' });
          break;
        }
        if (entry.tokenUsed) {
          sendResponse({ ok: false, error: 'used' });
          break;
        }
        const issuedAt = entry.tokenIssuedAt || entry.suspendedAt;
        if (TOKEN_TTL_MS && issuedAt && Date.now() - issuedAt > TOKEN_TTL_MS) {
          sendResponse({ ok: false, error: 'expired' });
          break;
        }
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
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ locked: true, reason: encryptionReason() });
          break;
        }
        const snapshots = await SnapshotService.getSnapshots();
        sendResponse({ snapshots });
        break;
      }
      case 'GET_SNAPSHOT_DETAILS': {
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ locked: true, reason: encryptionReason() });
          break;
        }
        try {
          const snapshot = await getSnapshotById(message.snapshotId);
          if (!snapshot) {
            sendResponse({ ok: false, error: 'not-found' });
            break;
          }
          const state = await getSnapshotData(snapshot);
          sendResponse({ ok: true, tabs: state.suspendedTabs });
        } catch (err) {
          Logger.error('Failed to get snapshot details', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      case 'RESTORE_SNAPSHOT': {
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ ok: false, locked: true, error: 'locked' });
          break;
        }
        try {
          await SnapshotService.restoreSnapshot(message.snapshotId);
          sendResponse({ ok: true });
        } catch (err) {
          Logger.error('Restore failed', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      case 'OPEN_SNAPSHOT': {
        try {
          const result = await openSnapshotTabs(message.snapshotId, { unsuspend: !!message.unsuspend });
          sendResponse(result);
        } catch (err) {
          Logger.error('Open snapshot failed', err);
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
