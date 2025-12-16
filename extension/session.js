const sessionArea = chrome.storage?.session || null;
const memoryFallback = {};

export async function sessionGet(key) {
  if (sessionArea) {
    return sessionArea.get(key);
  }
  return { [key]: memoryFallback[key] };
}

export async function sessionSet(key, value) {
  if (sessionArea) {
    await sessionArea.set({ [key]: value });
  } else {
    memoryFallback[key] = value;
  }
}

export async function sessionRemove(key) {
  if (sessionArea) {
    await sessionArea.remove(key);
  }
  delete memoryFallback[key];
}
