export const SETTINGS_KEY = 'settings';

export const defaultSettings = {
  autoSuspendMinutes: 30,
  excludePinned: true,
  excludeAudible: true,
  excludeActive: true,
  whitelist: [],
  unsuspendMethod: 'activate', // 'activate' | 'manual'
  embedOriginalUrl: true, // Whether to include original URL in suspended page for recovery
  encryption: {
    enabled: true,
    iterations: 150000,
    cloudBackupEnabled: true,
  },
};

let cachedSettings = null;

export async function ensureSettings() {
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
        cloudBackupEnabled: stored[SETTINGS_KEY].encryption?.cloudBackupEnabled ?? defaultSettings.encryption.cloudBackupEnabled,
      },
    };
    await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
  }
  return cachedSettings;
}

export async function saveSettings(nextSettings) {
  cachedSettings = {
    ...defaultSettings,
    ...nextSettings,
    encryption: {
      ...defaultSettings.encryption,
      ...(nextSettings.encryption || {}),
      enabled: true,
      cloudBackupEnabled: nextSettings.encryption?.cloudBackupEnabled ?? defaultSettings.encryption.cloudBackupEnabled,
    },
  };
  await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
}
