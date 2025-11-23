Implementation Plan

Storage schema

Define a single data key record in chrome.storage.sync (with local-only fallback):
cloudBackupEnabled: boolean (default true).
usingPasskey: boolean.
dataKey (Base64 raw AES key) when unlocked & no passkey.
encryptedKey (Base64 AES-GCM ciphertext of data key).
keySalt (Base64 PBKDF2 salt), keyIV (Base64 AES-GCM IV), iterations (e.g., 150k).
keyVersion (for future migrations), updatedAt.
Local chrome.storage.local:
STATE_KEY: encrypted state per existing shape { iv, ct } or { plain } for compatibility.
backups (snapshots) unchanged shape but always encrypted when possible.
logs, lastActive, pendingSuspenderState unchanged.
Session (chrome.storage.session fallback to in-memory):
cryptoKey (JWK of decrypted data key) for runtime unlock.
Keep pendingSuspenderState buffering while locked.
Key lifecycle & helpers

Add helpers: generateDataKey, exportKeyBase64, importKeyBase64, wrapDataKey(passkey), unwrapDataKey(passkey), persistKeyRecord(record), loadKeyRecord().
Generate 256-bit AES-GCM data key on first run; store plaintext in sync if cloudBackupEnabled, otherwise in local-only store (or sync with cloudBackupEnabled=false marker but no key).
Always operate on the stable data key; passkey only wraps/unwraps it (no more deriving the data key itself).
Cache decrypted data key in session storage for reuse across service-worker restarts; never write plaintext key to local/sync when usingPasskey=true.
Startup state machine (background.js)

On init: load settings + key record.
If usingPasskey=true and no session key: enter locked state; refuse decrypt/ encrypt, buffer pending state, and surface locked in GET_STATE/GET_SNAPSHOTS/etc.
If plaintext key present (and allowed by cloudBackupEnabled or local-only), import to CryptoKey, cache in session, continue normal ops.
If no key record: treat as first install -> generate data key, store according to cloud toggle, continue.
Handle corrupted key record (missing fields, bad Base64): log, expose locked with error: 'corrupt-key', allow reset.
Message/API surface

New messages:
GET_ENCRYPTION_STATUS: returns key record, locked flag, cloud toggle.
UNLOCK_WITH_PASSKEY { passkey }: derives wrap key (PBKDF2), unwraps data key, caches it; on failure returns error.
SET_PASSKEY { passkey }: requires current unlocked data key; wrap and persist (remove plaintext dataKey); set usingPasskey=true.
REMOVE_PASSKEY: unwrap already unlocked data key, persist plaintext (or keep in local-only if cloudBackupEnabled=false), set usingPasskey=false, delete encrypted fields.
SET_CLOUD_BACKUP { enabled }: when enabled=false, remove key from sync; keep key in local-only store; when enabled=true, push plaintext or wrapped blob to sync.
RESET_ENCRYPTION: wipe local/sync key records, wipe encrypted state/backups, clear session key, regenerate fresh data key and state.
Adjust existing messages to propagate locked/error responses where relevant (state queries, snapshot listing/restoring, suspend/unsuspend operations).
State encryption flow

All encrypt/decrypt uses the stable data key.
If locked: saveState writes to pending buffer; loadState returns { locked: true } with pending merged where safe.
On unlock: decrypt persisted state/backups with data key; merge pending buffer; re-encrypt and persist; clear pending; clear stateLocked.
Snapshot creation/restore: skip creation when locked; require unlocked key to restore.
Key persistence rules

Cloud backup ON + no passkey: store dataKey plaintext in sync (Base64), mirror to local for resilience? (optional).
Cloud backup ON + passkey: store encryptedKey, keySalt, keyIV, iterations in sync; delete plaintext everywhere except session.
Cloud backup OFF: store plaintext data key only in local storage (never sync); passkey mode still allowed by storing encrypted blob locally instead of sync (so locked across restarts but no cloud copy).
User flows to implement

First install: generate data key, store per cloud toggle, no prompts.
Enable passkey: user provides passkey, background wraps current data key, persists encrypted blob, clears plaintext from persistent storage; state remains unlocked in-memory; on restart will be locked until passkey entered.
Unlock on startup: options/popup detects locked and prompts for passkey → UNLOCK_WITH_PASSKEY.
Remove passkey: unwrap (requires unlocked), persist plaintext key per cloud toggle, remove encrypted fields.
Toggle cloud backup: if disabling, delete sync key (plain or encrypted), keep local copy; if enabling, push current key/plain or encrypted blob to sync.
Reset when forgotten/corrupt: UI button → RESET_ENCRYPTION wipes state/backups/key, regenerates fresh key, reinitializes state.
UI changes (primitive, function-first)

Options page:
Show encryption status (Locked, Plaintext key in cloud, Passkey protected, Local-only).
Passkey form: set/change, remove, unlock prompt when locked, show errors.
Cloud backup toggle.
Reset button with clear warning (loss of history).
Basic error/status messages; no fancy styling needed.
Popup:
If locked, replace list with “Locked. Unlock in options.” or a simple inline unlock form (optional minimal).
Suspended page:
If locked when trying to unsuspend, show message to unlock via options.
Refactors in background.js

Replace current passphrase-as-key flow with stable data key + wrapping logic.
Replace deviceKey concept with dataKey record + cloud/local control.
Introduce key record loader/saver to sync/local; handle missing fields.
Update ensureCryptoKey/ensureDeviceKey to new abstractions or replace with ensureDataKey + wrap/unwrap.
Update logging to avoid leaking secrets; include key-state transitions (locked/unlocked, backup toggled).
Edge cases & error handling

Wrong passkey: return specific error; allow retries; optional exponential backoff.
Corrupt encrypted key blob: surface corrupt-key and offer reset.
Sync unavailable/offline: if passkey mode and blob unavailable, stay locked; if cloud disabled, rely on local-only key.
Service worker restarts: rely on chrome.storage.session for decrypted key; if lost, require re-unlock.
Testing checklist (manual)

First install: state encrypt/decrypt works; key saved per cloud toggle.
Restart with plaintext key: auto-unlocks, data readable.
Set passkey → restart → locked → correct passkey unlocks; wrong passkey fails.
Remove passkey → restart → auto-unlocks.
Toggle cloud backup off/on in both passkey/plain modes.
Reset flow clears history and regenerates key.
Snapshot create/restore works only when unlocked; behaves gracefully when locked.