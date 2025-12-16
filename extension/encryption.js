import Logger from './logger.js';
import { ensureSettings, defaultSettings, saveSettings } from './settings.js';
import { sessionGet, sessionSet, sessionRemove } from './session.js';

export const KEY_RECORD_KEY = 'encryptionKeyRecord';
export const KEY_VERSION = 1;

let cryptoKey = null;
let encryptionLocked = false;
let encryptionLockReason = null;

export function getCryptoKey() {
  return cryptoKey;
}

export function isEncryptionLocked() {
  return encryptionLocked;
}

export function getEncryptionLockReason() {
  return encryptionLockReason;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64 || '');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function generateDataKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKeyBase64(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(raw);
}

export async function importKeyBase64(b64) {
  const bytes = base64ToUint8(b64);
  return crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function deriveWrappingKey(passkey, saltBytes, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passkey),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: iterations || defaultSettings.encryption.iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapDataKey(passkey) {
  if (!cryptoKey) {
    throw new Error('Data key not available to wrap');
  }
  const settings = await ensureSettings();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(passkey, salt, settings.encryption.iterations);
  const raw = await crypto.subtle.exportKey('raw', cryptoKey);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, raw);
  return {
    encryptedKey: bufferToBase64(encrypted),
    keySalt: bufferToBase64(salt),
    keyIV: bufferToBase64(iv),
    iterations: settings.encryption.iterations,
  };
}

export async function unwrapDataKey(passkey, record) {
  const required = record?.encryptedKey && record?.keySalt && record?.keyIV;
  if (!required) {
    throw new Error('Encrypted key record is incomplete');
  }
  const salt = base64ToUint8(record.keySalt);
  const iv = base64ToUint8(record.keyIV);
  const encrypted = base64ToUint8(record.encryptedKey);
  const wrappingKey = await deriveWrappingKey(passkey, salt, record.iterations || defaultSettings.encryption.iterations);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, encrypted);
  cryptoKey = await crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  await saveKeyToSession(cryptoKey);
  encryptionLocked = false;
  encryptionLockReason = null;
  return cryptoKey;
}

export async function saveKeyToSession(key) {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', key);
    await sessionSet('cryptoKey', jwk);
  } catch (err) {
    Logger.warn('Failed to save key to session', err);
  }
}

export async function restoreKeyFromSession() {
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
      encryptionLocked = false;
      encryptionLockReason = null;
    }
  } catch (err) {
    Logger.warn('Failed to restore key from session', err);
  }
}

export async function clearSessionKey() {
  cryptoKey = null;
  await sessionRemove('cryptoKey');
}

export async function persistKeyRecord(record) {
  const payload = { [KEY_RECORD_KEY]: record };
  if (record?.cloudBackupEnabled) {
    try {
      await chrome.storage.sync.set(payload);
    } catch (err) {
      Logger.warn('Failed to persist key record to sync', err);
    }
  } else {
    try {
      await chrome.storage.sync.remove(KEY_RECORD_KEY);
    } catch (err) {
      Logger.warn('Failed to remove key record from sync', err);
    }
  }

  try {
    await chrome.storage.local.set(payload);
  } catch (err) {
    Logger.warn('Failed to persist key record locally', err);
  }
}

export async function loadKeyRecord(preferCloud = true) {
  let syncRecord = null;
  let localRecord = null;
  try {
    const syncStored = await chrome.storage.sync.get(KEY_RECORD_KEY);
    syncRecord = syncStored[KEY_RECORD_KEY] || null;
  } catch (err) {
    Logger.warn('Failed to read key record from sync', err);
  }

  try {
    const localStored = await chrome.storage.local.get(KEY_RECORD_KEY);
    localRecord = localStored[KEY_RECORD_KEY] || null;
  } catch (err) {
    Logger.warn('Failed to read key record from local storage', err);
  }

  return preferCloud ? (syncRecord || localRecord) : (localRecord || syncRecord);
}

export async function clearKeyRecords() {
  try {
    await chrome.storage.sync.remove(KEY_RECORD_KEY);
  } catch (err) {
    Logger.warn('Failed to clear key record from sync', err);
  }
  try {
    await chrome.storage.local.remove(KEY_RECORD_KEY);
  } catch (err) {
    Logger.warn('Failed to clear key record from local storage', err);
  }
}

export async function generateAndPersistDataKey(cloudBackupEnabled) {
  cryptoKey = await generateDataKey();
  const b64 = await exportKeyBase64(cryptoKey);
  const record = {
    usingPasskey: false,
    dataKey: b64,
    cloudBackupEnabled: !!cloudBackupEnabled,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  await persistKeyRecord(record);
  await saveKeyToSession(cryptoKey);
  encryptionLocked = false;
  encryptionLockReason = null;
  Logger.info('Generated new data key', { cloudBackupEnabled: !!cloudBackupEnabled });
  return record;
}

export function markEncryptionLocked(reason = null) {
  encryptionLocked = true;
  encryptionLockReason = reason || null;
}

export async function retryImportPlaintextKey() {
  const settings = await ensureSettings();
  const record = await loadKeyRecord(settings.encryption.cloudBackupEnabled);
  if (!record || record.usingPasskey || !record.dataKey) {
    return { ok: false, error: 'no-plaintext-record' };
  }
  try {
    cryptoKey = await importKeyBase64(record.dataKey);
    encryptionLocked = false;
    encryptionLockReason = null;
    await saveKeyToSession(cryptoKey);
    return { ok: true };
  } catch (err) {
    Logger.warn('Retry import of plaintext key failed', err);
    markEncryptionLocked('corrupt-key');
    return { ok: false, error: 'corrupt-key' };
  }
}

export async function initializeEncryption() {
  const settings = await ensureSettings();

  if (!cryptoKey) {
    await restoreKeyFromSession();
  }
  if (cryptoKey) {
    encryptionLocked = false;
    encryptionLockReason = null;
    return;
  }

  const record = await loadKeyRecord(settings.encryption.cloudBackupEnabled);
  if (!record) {
    await generateAndPersistDataKey(settings.encryption.cloudBackupEnabled);
    return;
  }

  if (record.usingPasskey) {
    if (record.encryptedKey && record.keySalt && record.keyIV) {
      markEncryptionLocked('passkey-required');
    } else {
      markEncryptionLocked('corrupt-key');
    }
    return;
  }

  if (record.dataKey) {
    try {
      cryptoKey = await importKeyBase64(record.dataKey);
      encryptionLocked = false;
      encryptionLockReason = null;
      await saveKeyToSession(cryptoKey);
      if (record.cloudBackupEnabled !== settings.encryption.cloudBackupEnabled) {
        record.cloudBackupEnabled = settings.encryption.cloudBackupEnabled;
        await persistKeyRecord(record);
      }
      return;
    } catch (err) {
      Logger.warn('Failed to import plaintext data key', err);
      markEncryptionLocked('corrupt-key');
      return;
    }
  }

  markEncryptionLocked('corrupt-key');
}

export async function unlockWithPasskey(passkey) {
  const settings = await ensureSettings();
  const record = await loadKeyRecord(settings.encryption.cloudBackupEnabled);
  if (!record || !record.usingPasskey) {
    return { ok: false, error: 'not-locked' };
  }
  try {
    await unwrapDataKey(passkey, record);
    return { ok: true };
  } catch (err) {
    Logger.warn('Passkey unlock failed', err);
    markEncryptionLocked('bad-passkey');
    return { ok: false, error: 'bad-passkey' };
  }
}

export async function setPasskey(passkey) {
  if (!passkey) {
    return { ok: false, error: 'missing-passkey' };
  }
  if (encryptionLocked || !cryptoKey) {
    return { ok: false, error: 'locked' };
  }
  const settings = await ensureSettings();
  const wrapped = await wrapDataKey(passkey);
  const record = {
    usingPasskey: true,
    encryptedKey: wrapped.encryptedKey,
    keySalt: wrapped.keySalt,
    keyIV: wrapped.keyIV,
    iterations: wrapped.iterations,
    cloudBackupEnabled: settings.encryption.cloudBackupEnabled,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  await persistKeyRecord(record);
  return { ok: true };
}

export async function removePasskey() {
  if (encryptionLocked || !cryptoKey) {
    return { ok: false, error: 'locked' };
  }
  const settings = await ensureSettings();
  const b64 = await exportKeyBase64(cryptoKey);
  const record = {
    usingPasskey: false,
    dataKey: b64,
    cloudBackupEnabled: settings.encryption.cloudBackupEnabled,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  await persistKeyRecord(record);
  return { ok: true };
}

export async function setCloudBackupEnabled(enabled) {
  const settings = await ensureSettings();
  const nextSettings = {
    ...settings,
    encryption: {
      ...settings.encryption,
      cloudBackupEnabled: !!enabled,
    },
  };
  await saveSettings(nextSettings);

  let record = await loadKeyRecord(enabled);
  if (!record && cryptoKey) {
    const b64 = await exportKeyBase64(cryptoKey);
    record = {
      usingPasskey: false,
      dataKey: b64,
      cloudBackupEnabled: !!enabled,
      keyVersion: KEY_VERSION,
      updatedAt: Date.now(),
    };
  }

  if (record) {
    record.cloudBackupEnabled = !!enabled;
    await persistKeyRecord(record);
  } else {
    await clearKeyRecords();
  }
  return { ok: true };
}

export function getEncryptionStatusPayload(settings, record) {
  const locked = encryptionLocked || (!cryptoKey && record?.usingPasskey);
  return {
    locked,
    reason: locked ? (encryptionLockReason || (record?.usingPasskey ? 'passkey-required' : null)) : null,
    usingPasskey: !!record?.usingPasskey,
    cloudBackupEnabled: settings.encryption.cloudBackupEnabled,
    hasKeyRecord: !!record,
  };
}
