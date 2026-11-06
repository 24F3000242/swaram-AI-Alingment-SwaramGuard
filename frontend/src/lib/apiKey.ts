/** The API key this browser uses when the server has SWARMGUARD_API_KEYS set (see backend/app/auth.py). */
const STORE = "swarmguard.apiKey";
export const AUTH_REQUIRED = "swarmguard-auth-required";

export function getApiKey(): string {
  try {
    return localStorage.getItem(STORE) ?? "";
  } catch {
    return ""; // private mode / blocked storage: no key
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) localStorage.setItem(STORE, key);
    else localStorage.removeItem(STORE);
  } catch {
    /* storage unavailable: the key lasts until reload */
  }
}

export function authHeaders(): Record<string, string> {
  const key = getApiKey();
  return key ? { Authorization: `Bearer ${key}` } : {};
}
