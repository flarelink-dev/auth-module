# Flarelink Auth Module

The auth Worker that [Flarelink](https://flarelink.dev) deploys onto your own Cloudflare account. BetterAuth + KV-only sessions + email flows, bundled as a single `.mjs` and uploaded to CF via the Scripts API.

This repo exists so you can read, audit, and rebuild the exact code that ends up handling your users' authentication. Flarelink never sees the secrets — they live in `flarelink_config` on the D1 attached to **your** auth Worker.

**License:** [FSL-1.1-MIT](LICENSE.md) — source available; each version converts to MIT two years after its release. Free to read, modify, and use for any purpose other than building a competing auth/backend product.

---

## What it does

- **Email + password** sign-up / sign-in / sign-out via BetterAuth.
- **OAuth providers** — Google and GitHub. OAuth client IDs + secrets stored in `flarelink_config` on the customer's D1, read at boot with a 60s cache.
- **Magic links** with single-use tokens + per-IP rate limits.
- **Email verification** (auto-send on signup optional, auto-sign-in after verify optional).
- **Password reset** via email.
- **Sessions in KV** — every auth check is a ~10ms KV read. D1 holds user / account / verification rows; not sessions.
- **Storage endpoints** for the SDK (`flarelink.storage.from(bucket).createSignedUploadUrl(...)`) — SigV4-signed presigned URLs against R2.
- **Database endpoints** for the SDK (`flarelink.from(table).select(...)` / `flarelink.sql\`...\``) — single statement + atomic batch against D1.
- **Per-deployment service key** — bearer-auth for the SDK's db + storage routes. Hashed (SHA-256) at rest; plaintext never persisted by Flarelink.
- **Custom domain support** — attach a hostname on a CF zone (e.g. `auth.yourapp.com`); BetterAuth picks up the new origin automatically.

## Architecture in one paragraph

This Worker lives on **your** Cloudflare account. Flarelink's dashboard talks to the CF REST API to upload, configure, and update it; once deployed, your app talks to this Worker directly (`https://auth.yourapp.com/api/auth/sign-in`, etc.) and Flarelink's servers are entirely out of the request path. If Flarelink shuts down, this Worker keeps running on your account — you keep the D1, the KV, the R2 keys, the source code, everything.

## Repo layout

```
worker.ts                Main Hono entry. Mounts /api/auth (BetterAuth),
                         /api/storage, /api/db, /__flarelink, /__flarelink/reload-config.
lib/email-sender.ts      Resend + CF Email Sending implementations.
lib/email-templates.ts   Renders reset / verify / magic-link emails. Per-field
                         overrides supported.
lib/callback-rewrite.ts  Normalizes `callbackURL` so verify links always land on
                         the customer app's origin, never on the Worker.
lib/sigv4.ts             AWS SigV4 in pure JS (no aws-sdk dep) for R2 presigning.
lib/service-key.ts       SHA-256 hash + constant-time verify for the SDK service key.
migrations/0000_init.sql The D1 schema: user, account, verification, flarelink_config.
version.ts               Single source of truth for FLARELINK_AUTH_VERSION.
build.mjs                esbuild bundler → dist/worker.mjs (~820 KB raw, ~215 KB gz).
```

## How Flarelink deploys it

The customer's flow, end to end:

1. Customer signs in to dash.flarelink.dev, connects their CF account with a scoped API token.
2. They click "Provision project" — the dashboard's `provisionProject` orchestrator (closed source) runs the seven-step atomic chain: insert project → create D1 + apply migrations → create KV → mint R2 keys → upload this Worker bundle with bindings → write `flarelink_config` rows → activate the project.
3. This Worker boots, reads `flarelink_config` to discover `BETTER_AUTH_SECRET`, `TRUSTED_ORIGINS`, OAuth credentials, email provider config, R2 keys, and the service key hash.
4. Customer points their app at `https://<their-worker-url>/api/auth/*` via the SDK; Flarelink is no longer in the loop.

All config (secrets, OAuth credentials, R2 keys, service key hash) lives in **the customer's** D1. Flarelink stores nothing. If you want to inspect what the Worker reads at boot, look at the `loadConfig` function in `worker.ts`.

## Audit pointers

If you're here to verify the auth code, these are the relevant files:

- **Password hashing** — the Worker supplies its own `hash`/`verify` to BetterAuth (the `password:` block under `emailAndPassword` in `worker.ts`), not BetterAuth's default. Algorithm: **PBKDF2-SHA256, 16-byte random salt, 32-byte derived key**, stored as `pbkdf2$<iterations>$<salt>$<hash>`. scrypt was dropped in v0.1.1 because its wasm path exceeded the Workers free-tier ~10 ms CPU budget; native PBKDF2 runs in ~1–5 ms.
  - **Iterations are configurable per deployment** (`PBKDF2_ITERATIONS` in `flarelink_config`, read in `loadConfig`, clamped to `[100_000, 1_000_000]`). The default is **100,000** — chosen to fit the free-tier CPU budget, which is below OWASP's 600k PBKDF2-SHA256 baseline. The dashboard's auth-module Settings exposes a **Hardened (600,000)** option; it requires the auth Worker to run on the Cloudflare **Workers paid plan** (30 s CPU), because 600k iterations would exceed the free-plan CPU limit on every sign-in. Flarelink can't auto-select this — reading your account's plan would need a billing-scoped token it deliberately never requests.
  - **Rehash-on-login** (v0.3.0): each hash records the iteration count it was produced with, so verification works across counts; when a stored hash's count is below the deployment's current target, a successful sign-in transparently re-hashes the password at the new target. No bulk migration, no forced password reset.
  - **Threat model:** the iteration count is one layer. Sessions are KV-backed (no password material at rest beyond the salted hash), email verification / reset / magic-link tokens are single-use and short-lived, and per-IP rate limiting (below) bounds online guessing. The honest caveat: at 100k a stolen hash database is brute-forced faster than at 600k — raise to Hardened on a paid plan if your threat model includes D1 exfiltration.
- **Session storage** — sessions live in KV (`SESSIONS` binding), never in D1. See `secondaryStorage` + `session.storeSessionInDatabase: false` in the BetterAuth config block. Disabling cookieCache avoids issue [#4203](https://github.com/better-auth/better-auth/issues/4203) (5-min logout window).
- **Cookie shape** — `__Secure-better-auth.session_token`, `SameSite=None; Secure; Partitioned` set by BetterAuth's `advanced.crossSubDomainCookies`.
- **IP address resolution** — `advanced.ipAddress.ipAddressHeaders: ['cf-connecting-ip']`. Without this, BetterAuth's per-IP rate limits silently disable in a Workers context.
- **Service key auth** — `requireServiceKey` middleware in `worker.ts` extracts `Authorization: Bearer <key>`, hashes it with SHA-256 via `lib/service-key.ts`, and constant-time-compares against the `SERVICE_KEY_HASH` row in `flarelink_config`.
- **SigV4** — `lib/sigv4.ts`, lifted verbatim from the dashboard's `server/lib/sigv4.ts` so they stay byte-identical. UNSIGNED-PAYLOAD for PUT/GET presigning so the browser doesn't need to pre-hash large uploads.
- **No telemetry, no analytics, no outbound calls** to anywhere other than R2 (S3 API), CF Email Sending, Resend (if configured), and Google/GitHub OAuth providers.

## Versioning

`version.ts` exports `FLARELINK_AUTH_VERSION` — the single source of truth for the Worker bundle's version. Bumped on every meaningful change to the auth surface (new routes, behavior changes, security fixes). Two places consume it:

- The bundled Worker itself surfaces `/__flarelink` returning `{ version: '0.3.0', ... }` — your dashboard reads this to detect stale deployments and show a "Redeploy → vX" prompt.
- The Flarelink dashboard's `auth_module_deployment.flarelinkAuthVersion` column records what version each customer is on, so the version pill knows when an update is available.

Semver convention:
- **Patch** (`0.2.2` → `0.2.3`) — bug fixes, behavior preserved.
- **Minor** (`0.2.2` → `0.3.0`) — new routes / config keys / opt-in features.
- **Major** (`0.2.2` → `1.0.0`) — wire-format changes; customers need to migrate.

If you fork or modify this Worker for your own use, bump the version so your downstream tooling can tell.

## Building locally

The Worker bundles via [esbuild](https://esbuild.github.io/). The output (`dist/worker.mjs`) is what Flarelink uploads to CF via the Scripts API multipart endpoint.

```bash
npm ci             # installs the exact pinned deps from package-lock.json
npm run build      # produces dist/worker.mjs
```

`npm ci` (not `npm install`) matters: the build is byte-for-byte reproducible only against the **pinned** dependency versions in `package-lock.json`. Same source + same lockfile + the Node version in [`.github/workflows/release.yml`](.github/workflows/release.yml) → identical bytes.

## Verify the deployed bundle

Two independent checks, neither of which requires trusting Flarelink:

**1. Does the source here reproduce the published bundle?** Clone at the version's tag, rebuild, and compare against [`HASHES.md`](HASHES.md):

```bash
git checkout v0.3.0
npm ci && npm run build
shasum -a 256 dist/worker.mjs    # must equal the v0.3.0 row in HASHES.md
```

**2. Does the bundle running in YOUR Cloudflare account match?** The deployed Worker reports its version at `GET https://<your-auth-worker>/__flarelink`. Pull the live script with your own CF token (Workers Scripts API download endpoint) and hash it — it must equal the same `HASHES.md` row. The [`flarelink-verify`](https://github.com/flarelink-dev/flarelink-verify) CLI does this in one command:

```bash
npx @flarelink/verify    # reads /__flarelink, downloads the script, compares to the published hash
```

Together these prove: the public source → the published hash → the bytes Cloudflare is actually running for your users. Flarelink's dashboard is closed source, but everything it *produces* in your account is verifiable this way.

Every released `FLARELINK_AUTH_VERSION` is git-tagged `v<version>`; the [release workflow](.github/workflows/release.yml) rebuilds from pinned deps, asserts the hash matches `HASHES.md`, and attaches `dist/worker.mjs` + its SHA-256 to the GitHub Release.

## Deploying it yourself (without Flarelink's dashboard)

This is supported but not the recommended path — you lose the dashboard's orchestration, version-tracking, and config UI. If you want to do it anyway:

1. Build the bundle: `npm run build`.
2. Create a D1 + KV on your CF account.
3. Apply the migration: `wrangler d1 execute <your-d1> --file=migrations/0000_init.sql`.
4. Write the required config rows to `flarelink_config` (see `loadConfig` in `worker.ts` for the keys: `BETTER_AUTH_SECRET`, `TRUSTED_ORIGINS`, `FLARELINK_PROJECT_ID`, etc.).
5. Upload the Worker with `DB`, `SESSIONS` bindings pointing at the D1 + KV above.

The Flarelink dashboard automates all of this and surfaces the right error messages when things drift. Going manual means you own the operational story.

## Contributing

The project is in beta and I'm not actively reviewing PRs while the dashboard's orchestration and this Worker's wire format are still settling. If you find a bug or have a concern about the auth surface, **please file an issue** — that's the most useful contribution today. If the fix is a one-line patch, I'll usually just take it.

## Background

Flarelink is a Supabase-style backend bundle for the Cloudflare developer stack — auth (this Worker), D1 with a table editor, R2 with a file browser, email — all provisioned on the customer's own CF account. The dashboard at https://flarelink.dev does the orchestration; this Worker is one piece of what gets deployed.

This Worker repo is the open piece. The dashboard itself (closed for now) lives separately. If you want the SDK that talks to this Worker, see [`@flarelink/client`](https://www.npmjs.com/package/@flarelink/client). If you want a starter app showing this Worker in use, see [`flarelink-dev/starter-vite-react-hono`](https://github.com/flarelink-dev/starter-vite-react-hono).

---

**License:** [FSL-1.1-MIT](LICENSE.md). Copyright 2026 Koppe Digital OÜ.
