// End-to-end encryption helpers (Web Crypto API only; no dependencies).
//
// From (space name, password) we derive 512 bits with PBKDF2-SHA256:
//   * the first 256 bits are an AES-256-GCM key, which never leaves the device
//   * the last 256 bits are an "auth token" sent to the server, which stores only
//     its SHA-256 hash
// The server therefore can't decrypt notes, and the password itself is never sent.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
const SALT_PREFIX = 'note-transfer/v1/space/';

export function cryptoAvailable() {
  return typeof crypto !== 'undefined' && !!crypto.subtle;
}

export async function deriveSpaceKeys(name, password) {
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(SALT_PREFIX + name), iterations: PBKDF2_ITERATIONS },
    baseKey, 512));
  return { keyHex: toHex(bits.slice(0, 32)), auth: toHex(bits.slice(32, 64)) };
}

export function importKey(keyHex) {
  return crypto.subtle.importKey('raw', fromHex(keyHex), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// The space name is bound in as additional authenticated data, so ciphertext
// can't be moved between spaces.
export async function encryptNote(key, spaceName, note) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify({ v: 1, title: note.title, body: note.body }));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(spaceName) }, key, plaintext);
  return { ciphertext: toBase64(new Uint8Array(ct)), iv: toBase64(iv) };
}

export async function decryptNote(key, spaceName, ciphertext, iv) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(iv), additionalData: enc.encode(spaceName) },
    key, fromBase64(ciphertext));
  const obj = JSON.parse(dec.decode(pt));
  return { title: String(obj.title ?? ''), body: String(obj.body ?? '') };
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function fromBase64(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
