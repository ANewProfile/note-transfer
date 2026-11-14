// Supabase connection settings.
//
// Find both values in Supabase Dashboard → Project Settings → API (or "Connect").
// They are PUBLIC by design: the key only allows calling the nt_* database
// functions, and every note is encrypted in the browser before upload.
//
// SUPABASE_KEY can be either the legacy "anon" key (starts with "eyJ...") or the
// newer "publishable" key (starts with "sb_publishable_...").

export const SUPABASE_URL = 'YOUR_SUPABASE_URL'; // e.g. 'https://abcdefghijkl.supabase.co'
export const SUPABASE_KEY = 'YOUR_SUPABASE_ANON_OR_PUBLISHABLE_KEY';
