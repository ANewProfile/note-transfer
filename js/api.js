// Thin client for the Supabase RPC functions defined in supabase/schema.sql.
import { SUPABASE_URL, SUPABASE_KEY } from './config.js';

const MESSAGES = {
  invalid_name: 'Space names can only use lowercase letters, numbers and "-" (max 64 characters).',
  invalid_auth: 'Could not derive a valid key from that password.',
  invalid_lifespan: 'Lifespan must be between 1 minute and 5 days.',
  invalid_expiry: 'The new expiry must be at least a minute from now.',
  name_taken: 'That space name is already taken. Pick another, or join it if it’s yours.',
  not_found: 'No active space with that name. It may have expired or been deleted.',
  bad_password: 'Wrong password for that space.',
  locked: 'Too many wrong passwords. This space is locked for 10 minutes.',
  too_large: 'That note is too large (about 300 KB max).',
  too_many_notes: 'This space has reached its 500-note limit.',
  note_not_found: 'That note no longer exists. It may have been deleted on another device.',
  network: 'Can’t reach the server. Check your connection and try again.',
};

export class ApiError extends Error {
  constructor(code, message) {
    super(message || MESSAGES[code] || code);
    this.code = code;
  }
}

export function isConfigured() {
  return typeof SUPABASE_URL === 'string' && typeof SUPABASE_KEY === 'string'
    && /^https?:\/\//.test(SUPABASE_URL) && SUPABASE_KEY.length > 20 && !SUPABASE_KEY.startsWith('YOUR_');
}

async function rpc(fn, args) {
  const headers = { 'Content-Type': 'application/json', apikey: SUPABASE_KEY };
  // Legacy anon keys are JWTs and also go in Authorization; new publishable keys must not.
  if (SUPABASE_KEY.startsWith('eyJ')) headers.Authorization = `Bearer ${SUPABASE_KEY}`;

  let res;
  try {
    res = await fetch(`${SUPABASE_URL.replace(/\/+$/, '')}/rest/v1/rpc/${fn}`, {
      method: 'POST', headers, body: JSON.stringify(args), cache: 'no-store',
    });
  } catch {
    throw new ApiError('network');
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data && (data.message || data.hint);
    if (res.status === 404 && data && data.code === 'PGRST202') {
      throw new ApiError('server', 'The database isn’t set up yet. Run supabase/schema.sql in the Supabase SQL editor.');
    }
    throw new ApiError('server', `Server error (${res.status})${detail ? `: ${detail}` : ''}`);
  }
  if (data && typeof data === 'object' && data.error) throw new ApiError(data.error);
  return data;
}

export const api = {
  createSpace: (name, auth, lifespanSeconds) =>
    rpc('nt_create_space', { p_name: name, p_auth: auth, p_lifespan_seconds: lifespanSeconds }),
  openSpace: (name, auth) => rpc('nt_open_space', { p_name: name, p_auth: auth }),
  addNote: (name, auth, ciphertext, iv) =>
    rpc('nt_add_note', { p_name: name, p_auth: auth, p_ciphertext: ciphertext, p_iv: iv }),
  updateNote: (name, auth, id, ciphertext, iv) =>
    rpc('nt_update_note', { p_name: name, p_auth: auth, p_id: id, p_ciphertext: ciphertext, p_iv: iv }),
  deleteNote: (name, auth, id) => rpc('nt_delete_note', { p_name: name, p_auth: auth, p_id: id }),
  setExpiry: (name, auth, expiresAtIso) =>
    rpc('nt_set_expiry', { p_name: name, p_auth: auth, p_expires_at: expiresAtIso }),
  deleteSpace: (name, auth) => rpc('nt_delete_space', { p_name: name, p_auth: auth }),
};
