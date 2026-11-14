# Note Transfer

Move notes, code snippets and tokens between devices (work, school, home, mobile, any OS) using short-lived, **end-to-end encrypted** note spaces.

- **Note spaces** are joined with a name and password. Names use lowercase letters, numbers and `-`, and only one active space can hold a name at a time.
- **Notes** are a plain-text title and body. Anyone in the space can add, edit, copy and delete them.
- **Lifespan** is chosen at creation (presets or custom, up to 5 days). It can be shortened or extended later, but never past **5 days after the space was created**. When a space expires (or is deleted early), its notes are destroyed and its name is free for anyone.
- **Encryption:** the browser derives an AES-256-GCM key from the password (PBKDF2-SHA256, 600k iterations). The password and key never leave the device, and the server only stores ciphertext plus a hash of a separate auth token. A forgotten password can't be recovered.
- **Brute-force protection:** 10 wrong passwords lock a space for 10 minutes.
- **Remember on this device** (optional) keeps the derived key in `localStorage` until the space expires, so you can reopen it without retyping the password. Without it, the key lives only for the browser tab's session.

The frontend is static HTML/CSS/JS with no build step and no dependencies, hosted on GitHub Pages. Storage is a free [Supabase](https://supabase.com) Postgres database.

## Setup (one time, about 5 minutes)

### 1. Create the database

1. Sign up at [supabase.com](https://supabase.com) and create a new project (the free tier is plenty).
2. In the project, open **SQL Editor → New query**, paste the whole of [`supabase/schema.sql`](supabase/schema.sql), and click **Run**.
   - It creates private tables, the `nt_*` API functions, and a `pg_cron` job that deletes expired spaces every 5 minutes. Expired spaces are also purged on every request, so names free up immediately either way.
   - It's safe to re-run after updates.

### 2. Point the site at it

1. In Supabase, open **Project Settings → API** (or the **Connect** button) and copy:
   - the **Project URL** (`https://xxxx.supabase.co`)
   - the **anon** key (`eyJ...`) or the **publishable** key (`sb_publishable_...`)
2. Put them in [`js/config.js`](js/config.js). Both values are public by design: the key can only call the `nt_*` functions, which all require the space's auth token.

### 3. Turn on GitHub Pages

1. Commit and push.
2. On GitHub: **Settings → Pages → Build and deployment → Source: Deploy from a branch**, then pick branch `main` and folder `/ (root)`.
3. After a minute the site is live at `https://<user>.github.io/note-transfer/`.

> **Tip:** share `https://<user>.github.io/note-transfer/#space-name` to pre-fill the space name on another device.

## Local development

Web Crypto only works on `https://` or `localhost`:

```sh
python3 -m http.server 8000   # then open http://localhost:8000
```

## Security notes

- The Content-Security-Policy in `index.html` only allows connections to `*.supabase.co` (and localhost). If you use a custom Supabase domain, add it to `connect-src`.
- Encryption protects notes from the database and anyone with access to it. It does **not** protect against a weak password: anyone who can guess the name and password can read the space. Use a strong password for sensitive tokens.
- Since anyone can try passwords against a known name, someone could deliberately trigger the 10-minute lockout. Uncommon names make that harder.
- Anyone with the password has full control (edit/delete notes, change expiry, delete the space).
- Each note can hold about 300 KB, and each space up to 500 notes.

## Project layout

```
index.html            page markup
css/styles.css        styles (light and dark)
js/config.js          Supabase URL + public key  ← edit this
js/app.js             UI and app logic
js/api.js             calls the Supabase RPC functions
js/crypto.js          key derivation and AES-GCM encryption
supabase/schema.sql   database schema, API functions, cleanup job
```
