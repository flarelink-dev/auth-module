/// <reference types="@cloudflare/workers-types" />
// Flarelink Auth Module — customer-facing Worker.
//
// Flarelink bundles this and uploads it to the customer's Cloudflare account on
// "Add auth". Once deployed it runs entirely there — Flarelink is not in the
// request path. Same shape as Linear's GitHub integration: orchestrate, walk
// away. See architecture.md.
//
// Bindings (set at upload time):
//   DB       D1Database  — users, accounts, verifications, flarelink_config.
//   SESSIONS KVNamespace — the only place sessions live.
//
// All runtime configuration lives in the `flarelink_config` table on the
// customer's own D1 (key/value rows). The Worker reads it at boot with a
// 60s module-level cache. Flarelink dies → no keys are lost; the customer can
// inspect or edit their own config via any D1 client. POST
// /__flarelink/reload-config invalidates the cache so dashboard writes
// propagate instantly without waiting on the TTL.
//
// Keys we read from flarelink_config:
//   BETTER_AUTH_SECRET   32-byte hex; signs session tokens.
//   TRUSTED_ORIGINS      comma-separated app origins (CORS + redirect gate).
//   FLARELINK_PROJECT_ID     opaque id stamped at deploy time.
//   GOOGLE_CLIENT_ID     OAuth — optional, paired with secret.
//   GOOGLE_CLIENT_SECRET
//   GITHUB_CLIENT_ID
//   GITHUB_CLIENT_SECRET
//
// Session storage choice — KV only, no D1 session table:
//   * BetterAuth's secondaryStorage gives us KV-cached session reads (Pattern
//     1 from the product brief — auth check on hot path doesn't hit D1).
//   * We deliberately set storeSessionInDatabase: false. With both stores on,
//     BetterAuth #6993 leaves session.id missing in the KV copy and breaks
//     OAuth.
//   * We deliberately do NOT enable cookieCache. With secondaryStorage,
//     BetterAuth #4203 logs users out after exactly 5 minutes once the cookie
//     cache expires.
//   * KV minimum TTL is 60s; secondaryStorage.set clamps anything shorter.
//
// Cross-origin cookie strategy:
//   The customer's app is on theirapp.com; this Worker is on a workers.dev
//   subdomain (or auth.theirapp.com later). Default cookie attributes are
//   SameSite=None; Secure; Partitioned so the browser sends them on
//   cross-site fetch with credentials: 'include'.
//
// Password hashing:
//   BetterAuth's default scrypt-via-wasm runs right at the 10ms CPU edge on
//   Workers free tier — sometimes fits, sometimes 1102s with no consistency.
//   We swap in PBKDF2-SHA256 (native via Web Crypto, no wasm), 100k iterations.
//   Native PBKDF2 runs in ~1–5ms on Workers, well under the free-tier ceiling.
//   Cryptographically respectable for a typical indie SaaS — AWS Cognito uses
//   a PBKDF2 variant. Bump iterations if the customer is on Workers paid plan
//   and wants OWASP-recommended 600k.

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { magicLink } from 'better-auth/plugins';
import { drizzle } from 'drizzle-orm/d1';
import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { FLARELINK_AUTH_VERSION } from './version.ts';
import { buildEmailProvider, EmailError, type EmailConfig } from './lib/email-sender.ts';
import {
  appNameFromOrigins,
  effectiveTemplate,
  render,
  previewUrl,
  isTemplateType,
  type Template,
  type TemplateType,
} from './lib/email-templates.ts';
import { rewriteEmailLinkCallback } from './lib/callback-rewrite.ts';
import { sharedCookieDomain } from './lib/cookie-domain.ts';
import {
  presignUrl,
  signedFetch,
  type R2Creds,
} from './lib/sigv4.ts';
import { constantTimeEqual, hashServiceKey } from './lib/service-key.ts';

export { FLARELINK_AUTH_VERSION };

// --- schema (mirrors migrations/0000_init.sql) -----------------------------

const user = sqliteTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  image: text('image'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
});

const account = sqliteTable('account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: integer('access_token_expires_at', { mode: 'timestamp' }),
  refreshTokenExpiresAt: integer('refresh_token_expires_at', { mode: 'timestamp' }),
  scope: text('scope'),
  password: text('password'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
});

const verification = sqliteTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }),
  updatedAt: integer('updated_at', { mode: 'timestamp' }),
});

const schema = { user, account, verification };

// --- bindings (the only thing baked into the deployed Worker) --------------

type Bindings = {
  DB: D1Database;
  SESSIONS: KVNamespace;
  // Cloudflare Email Sending binding. Attached by deploy.ts on every project
  // Worker, but the binding only does anything once the customer's CF account
  // has Email Sending enabled + a verified outbound domain. Optional at the
  // type level so the Worker can boot on accounts that don't have it.
  EMAIL?: SendEmail;
};

// --- runtime config (read from customer's D1, cached) ----------------------

type Config = {
  BETTER_AUTH_SECRET: string;
  TRUSTED_ORIGINS: string[];
  FLARELINK_PROJECT_ID: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  EMAIL_PROVIDER?: 'cloudflare' | 'resend';
  EMAIL_FROM?: string;
  RESEND_API_KEY?: string;
  // Email-flow flags (v0.1.4). Default to false — flipping either on a
  // deployment without email configured would lock users out (verification
  // required + no way to verify) or fail signups silently (sendOnSignUp +
  // no provider). Dashboard guards the toggle; Worker re-guards here.
  REQUIRE_EMAIL_VERIFICATION: boolean;
  SEND_VERIFICATION_ON_SIGNUP: boolean;
  // Magic-link toggles (v0.1.5). Default true so existing v0.1.3/v0.1.4
  // deployments — which have no row — keep magic-link enabled after a
  // redeploy. Customers who want it off explicitly write 'false'.
  MAGIC_LINK_ENABLED: boolean;
  MAGIC_LINK_DISABLE_SIGNUP: boolean;
  // PBKDF2-SHA256 iteration count for password hashing. Read from config so
  // the dashboard can raise it on deployments running on the Workers *paid*
  // plan (30s CPU) without breaking free-plan deployments, where native PBKDF2
  // must stay within the ~10ms CPU ceiling. Absent/invalid → 100k (the highest
  // value that comfortably fits the free-tier budget). Clamped in loadConfig.
  PBKDF2_ITERATIONS: number;
  // v0.1.10 per-customer template overrides. Each field is optional —
  // absent → use the bundled default. Subject / html / text override
  // independently so customising one doesn't force the others.
  TEMPLATE_OVERRIDES: Record<TemplateType, Partial<Template>>;
  // v0.2 storage + db gated surface. SERVICE_KEY_HASH is the SHA-256 hex of
  // the project's service key; absence means "v0.2 features not provisioned
  // — return 401 with a clear hint". R2 creds are read from the same config
  // table the dashboard writes via cfClient at provision / regenerate time.
  // Plaintext in flarelink_config is acceptable — customer's CF account is the
  // trust boundary (same reasoning as plaintext OAuth secrets above).
  SERVICE_KEY_HASH?: string;
  R2_ACCOUNT_ID?: string;
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
};

// Module-level cache. Survives across requests in the same isolate; cold
// isolates pay one D1 read on first request. POST /__flarelink/reload-config
// invalidates it so dashboard writes don't have to wait the TTL out.
const CONFIG_TTL_MS = 60_000;
let configCache: Config | null = null;
let configCacheAt = 0;

async function loadConfig(db: D1Database): Promise<Config> {
  if (configCache && Date.now() - configCacheAt < CONFIG_TTL_MS) {
    return configCache;
  }
  const r = await db
    .prepare('SELECT key, value FROM flarelink_config')
    .all<{ key: string; value: string }>();
  const map = new Map(r.results.map((row) => [row.key, row.value]));

  const secret = map.get('BETTER_AUTH_SECRET');
  if (!secret) {
    throw new Error('flarelink_config is missing BETTER_AUTH_SECRET — re-run the deploy from Flarelink');
  }
  const originsRaw = map.get('TRUSTED_ORIGINS') ?? '';

  const provider = map.get('EMAIL_PROVIDER');
  const emailProvider =
    provider === 'cloudflare' || provider === 'resend' ? provider : undefined;

  const emailConfigured = Boolean(emailProvider && map.get('EMAIL_FROM'));
  // Treat anything other than literal "true" as false. Defaults to false on
  // a missing row. Worker re-guards on emailConfigured below so the dashboard
  // toggle can't accidentally lock users out if email is wiped post-toggle.
  const requireVerify = map.get('REQUIRE_EMAIL_VERIFICATION') === 'true';
  const sendOnSignup = map.get('SEND_VERIFICATION_ON_SIGNUP') === 'true';
  // Magic-link defaults to enabled — existing v0.1.3/v0.1.4 deployments
  // don't have this row, and silently turning it off after a redeploy
  // would break apps already calling signInWithMagicLink. Customer has to
  // explicitly write 'false' to disable.
  const magicLinkEnabled = (map.get('MAGIC_LINK_ENABLED') ?? 'true') === 'true';
  const magicLinkDisableSignup = map.get('MAGIC_LINK_DISABLE_SIGNUP') === 'true';
  // Iteration target for new/upgraded password hashes. Clamp to [MIN, MAX] so
  // a hand-edited config can't drop below the documented baseline or set a
  // value that would exceed the CPU budget on every sign-in. verifyPassword
  // reads each hash's own count, so existing hashes verify regardless.
  const iterRaw = parseInt(map.get('PBKDF2_ITERATIONS') ?? '', 10);
  const pbkdf2Iterations = Number.isInteger(iterRaw)
    ? Math.min(Math.max(iterRaw, PBKDF2_ITERATIONS_MIN), PBKDF2_ITERATIONS_MAX)
    : PBKDF2_ITERATIONS_DEFAULT;

  const next: Config = {
    BETTER_AUTH_SECRET: secret,
    TRUSTED_ORIGINS: originsRaw.split(',').map((s) => s.trim()).filter(Boolean),
    FLARELINK_PROJECT_ID: map.get('FLARELINK_PROJECT_ID') ?? '',
    GOOGLE_CLIENT_ID: map.get('GOOGLE_CLIENT_ID') || undefined,
    GOOGLE_CLIENT_SECRET: map.get('GOOGLE_CLIENT_SECRET') || undefined,
    GITHUB_CLIENT_ID: map.get('GITHUB_CLIENT_ID') || undefined,
    GITHUB_CLIENT_SECRET: map.get('GITHUB_CLIENT_SECRET') || undefined,
    EMAIL_PROVIDER: emailProvider,
    EMAIL_FROM: map.get('EMAIL_FROM') || undefined,
    RESEND_API_KEY: map.get('RESEND_API_KEY') || undefined,
    // Force both flags off when email isn't configured. Belt-and-braces
    // alongside the dashboard guard — defends against a customer hand-editing
    // flarelink_config directly, or email config being removed after toggles.
    REQUIRE_EMAIL_VERIFICATION: emailConfigured && requireVerify,
    SEND_VERIFICATION_ON_SIGNUP: emailConfigured && sendOnSignup,
    // Magic-link also needs email to actually deliver. Force-off when
    // email isn't configured so the plugin doesn't load endpoints that
    // can only ever fail. Customer flips email on → plugin re-enables on
    // next reload-config.
    MAGIC_LINK_ENABLED: emailConfigured && magicLinkEnabled,
    MAGIC_LINK_DISABLE_SIGNUP: magicLinkDisableSignup,
    PBKDF2_ITERATIONS: pbkdf2Iterations,
    TEMPLATE_OVERRIDES: readTemplateOverrides(map),
    SERVICE_KEY_HASH: map.get('SERVICE_KEY_HASH') || undefined,
    R2_ACCOUNT_ID: map.get('R2_ACCOUNT_ID') || undefined,
    R2_ACCESS_KEY_ID: map.get('R2_ACCESS_KEY_ID') || undefined,
    R2_SECRET_ACCESS_KEY: map.get('R2_SECRET_ACCESS_KEY') || undefined,
  };
  configCache = next;
  configCacheAt = Date.now();
  return next;
}

function invalidateConfigCache() {
  configCache = null;
  configCacheAt = 0;
}

// flarelink_config row keys for per-field template overrides. Three template
// types × three fields each = 9 rows when fully customised. Absent row → no
// override (use baked-in default). Subject / html / text override
// independently; customising the subject doesn't force you to override the
// body.
function overrideKey(type: TemplateType, field: 'subject' | 'html' | 'text'): string {
  const t = type === 'magic-link' ? 'MAGIC_LINK' : type.toUpperCase();
  return `EMAIL_TEMPLATE_${t}_${field.toUpperCase()}`;
}

function readTemplateOverrides(
  map: Map<string, string>
): Record<TemplateType, Partial<Template>> {
  const types: TemplateType[] = ['reset', 'verify', 'magic-link'];
  const out = {} as Record<TemplateType, Partial<Template>>;
  for (const t of types) {
    const partial: Partial<Template> = {};
    const s = map.get(overrideKey(t, 'subject'));
    const h = map.get(overrideKey(t, 'html'));
    const x = map.get(overrideKey(t, 'text'));
    if (s !== undefined) partial.subject = s;
    if (h !== undefined) partial.html = h;
    if (x !== undefined) partial.text = x;
    out[t] = partial;
  }
  return out;
}

// --- email helper ----------------------------------------------------------

// Single chokepoint for every email the Worker sends (reset / verify /
// magic link / test). Throws EmailError with an actionable message when the
// customer hasn't configured the email module yet — BetterAuth surfaces it
// as a 500 to the caller, which the dashboard turns into a "configure email
// first" prompt.
async function sendFlarelinkEmail(
  cfg: Config,
  env: Bindings,
  to: string,
  tpl: Template
): Promise<void> {
  if (!cfg.EMAIL_PROVIDER || !cfg.EMAIL_FROM) {
    throw new EmailError(
      'Email module is not configured for this deployment. Set it up in the Flarelink dashboard (Email panel) before triggering reset / verify / magic-link flows.'
    );
  }
  const emailCfg: EmailConfig = {
    provider: cfg.EMAIL_PROVIDER,
    from: cfg.EMAIL_FROM,
    resendApiKey: cfg.RESEND_API_KEY,
  };
  const provider = buildEmailProvider(emailCfg, env.EMAIL);
  await provider.send({
    from: cfg.EMAIL_FROM,
    to,
    subject: tpl.subject,
    html: tpl.html,
    text: tpl.text,
  });
}

type SocialProvidersConfig = NonNullable<
  Parameters<typeof betterAuth>[0]['socialProviders']
>;

function buildSocialProviders(cfg: Config): SocialProvidersConfig {
  const providers: SocialProvidersConfig = {};
  if (cfg.GOOGLE_CLIENT_ID && cfg.GOOGLE_CLIENT_SECRET) {
    providers.google = {
      clientId: cfg.GOOGLE_CLIENT_ID,
      clientSecret: cfg.GOOGLE_CLIENT_SECRET,
    };
  }
  if (cfg.GITHUB_CLIENT_ID && cfg.GITHUB_CLIENT_SECRET) {
    providers.github = {
      clientId: cfg.GITHUB_CLIENT_ID,
      clientSecret: cfg.GITHUB_CLIENT_SECRET,
    };
  }
  return providers;
}

// --- password hashing (PBKDF2-SHA256 via Web Crypto) -----------------------
//
// The iteration count is configurable per-deployment (flarelink_config →
// PBKDF2_ITERATIONS, read in loadConfig). Default 100k fits the Workers
// free-tier CPU budget; the dashboard raises it toward OWASP's 600k baseline
// on paid-plan deployments. Each hash stores the count it was produced with
// (`pbkdf2$<iterations>$<salt>$<hash>`), so verifyPassword can validate any
// historical count and createAuth's verify closure transparently re-hashes a
// below-target hash on the next successful sign-in.

const PBKDF2_ITERATIONS_DEFAULT = 100_000;
const PBKDF2_ITERATIONS_MIN = 100_000; // documented floor — never hash below this
const PBKDF2_ITERATIONS_MAX = 1_000_000; // ceiling so a typo can't DoS sign-in CPU

function toB64(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.byteLength; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number, bytes: number): Promise<Uint8Array> {
  const enc = new TextEncoder().encode(password) as unknown as BufferSource;
  const key = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations, hash: 'SHA-256' },
    key,
    bytes * 8
  );
  return new Uint8Array(bits);
}

async function hashPassword(password: string, iterations: number): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, iterations, 32);
  return `pbkdf2$${iterations}$${toB64(salt)}$${toB64(hash)}`;
}

// Returns the iteration count encoded in a stored hash, or null if the hash
// isn't in our pbkdf2 format. Used by the rehash-on-login check.
function iterationsOf(hash: string): number | null {
  const parts = hash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return null;
  const n = parseInt(parts[1], 10);
  return Number.isInteger(n) && n >= 1000 ? n : null;
}

async function verifyPassword({ hash, password }: { hash: string; password: string }): Promise<boolean> {
  const parts = hash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1], 10);
  if (!Number.isInteger(iterations) || iterations < 1000) return false;
  const salt = fromB64(parts[2]);
  const expected = fromB64(parts[3]);
  const got = await pbkdf2(password, salt, iterations, expected.byteLength);
  if (got.byteLength !== expected.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < got.byteLength; i++) diff |= got[i] ^ expected[i];
  return diff === 0;
}

// --- auth factory ----------------------------------------------------------

async function createAuth(env: Bindings, baseUrl: string) {
  const cfg = await loadConfig(env.DB);
  const db = drizzle(env.DB, { schema });
  const appName = appNameFromOrigins(cfg.TRUSTED_ORIGINS);

  // When the auth Worker runs on a custom domain that shares a registrable
  // domain with the app (e.g. auth.gridsnap.app + editor.gridsnap.app), scope
  // cookies to that shared domain so the session + OAuth-state cookies are
  // sent across both subdomains. Without this they're host-only and the OAuth
  // round-trip breaks (state cookie set on the app host isn't sent to the
  // auth host the redirect_uri is pinned to) and the app's own server routes
  // can't see the session. Null on the workers.dev fallback / cross-site
  // topology → BetterAuth keeps host-only + Partitioned cookies (correct
  // there). See lib/cookie-domain.ts.
  const authHost = (() => {
    try {
      return new URL(baseUrl).hostname;
    } catch {
      return '';
    }
  })();
  const cookieDomain = sharedCookieDomain(authHost, cfg.TRUSTED_ORIGINS);

  // Computed once so accountLinking.trustedProviders below stays in sync with
  // exactly the providers configured on this deployment.
  const socialProviders = buildSocialProviders(cfg);

  // Convenience: build the rendered template for a given type + URL.
  // Overlays the customer's per-field overrides on top of the bundled
  // default, then substitutes {{url}} and {{appName}}. Used by all three
  // BetterAuth hooks below.
  const renderFor = (type: TemplateType, url: string): Template =>
    render(effectiveTemplate(type, cfg.TEMPLATE_OVERRIDES[type]), url, appName);

  return betterAuth({
    database: drizzleAdapter(db, { provider: 'sqlite', schema }),
    secret: cfg.BETTER_AUTH_SECRET,
    baseURL: baseUrl,
    trustedOrigins: cfg.TRUSTED_ORIGINS,
    emailAndPassword: {
      enabled: true,
      // Toggled from the dashboard (v0.1.4). Defaults to false and is force-
      // cleared in loadConfig when email isn't configured, so flipping the
      // flag never silently locks users out.
      requireEmailVerification: cfg.REQUIRE_EMAIL_VERIFICATION,
      password: {
        // New hashes use the deployment's configured iteration target.
        hash: (password) => hashPassword(password, cfg.PBKDF2_ITERATIONS),
        // Rehash-on-login: verify against the count baked into the stored hash,
        // then — if it predates a raised target — transparently upgrade it now
        // that we have the plaintext. Keyed on the old hash string (unique via
        // its random salt). Best-effort: a failed write just retries next login.
        verify: async ({ hash, password }) => {
          const ok = await verifyPassword({ hash, password });
          if (ok) {
            const current = iterationsOf(hash);
            if (current !== null && current < cfg.PBKDF2_ITERATIONS) {
              try {
                const fresh = await hashPassword(password, cfg.PBKDF2_ITERATIONS);
                await env.DB.prepare('UPDATE account SET password = ? WHERE password = ?')
                  .bind(fresh, hash)
                  .run();
              } catch {
                /* non-fatal — hash stays at its old count until the next login */
              }
            }
          }
          return ok;
        },
      },
      // BetterAuth's url here is `{baseURL}/reset-password/{token}?callbackURL={redirectTo}`.
      // The user clicks it, BetterAuth validates the token + redirects to
      // the customer app's redirectTo with `?token=...`, the app calls
      // /api/auth/reset-password with { newPassword, token }.
      //
      // v0.1.6: rewriteEmailLinkCallback normalises a missing/relative
      // callbackURL to an absolute URL on the customer's app. Without it,
      // the user lands on `{workerHost}/?token=...` after verification → 404.
      sendResetPassword: async ({ user, url }, request) => {
        const fixed = rewriteEmailLinkCallback(
          url,
          request?.headers.get('origin'),
          cfg.TRUSTED_ORIGINS
        );
        await sendFlarelinkEmail(cfg, env, user.email, renderFor('reset', fixed));
      },
    },
    emailVerification: {
      // Dashboard-toggled (v0.1.4). When on, BetterAuth fires a verification
      // email automatically on signup; when off, the app calls
      // /api/auth/send-verification-email explicitly. Both paths use the
      // same sendVerificationEmail hook below.
      sendOnSignUp: cfg.SEND_VERIFICATION_ON_SIGNUP,
      // v0.1.8. When requireEmailVerification is on, BetterAuth deliberately
      // skips creating a session at signup — the user has to verify, then
      // sign in. Without this flag, clicking the verify link only flips
      // emailVerified=true but doesn't create a session, so the user lands
      // back on the app still signed-out. autoSignInAfterVerification fixes
      // that by issuing a session + Set-Cookie on the verify redirect.
      // Same risk surface as magic-link sign-in (anyone with the link can
      // assume that identity), which is the industry-standard tradeoff.
      autoSignInAfterVerification: true,
      sendVerificationEmail: async ({ user, url }, request) => {
        const fixed = rewriteEmailLinkCallback(
          url,
          request?.headers.get('origin'),
          cfg.TRUSTED_ORIGINS
        );
        await sendFlarelinkEmail(cfg, env, user.email, renderFor('verify', fixed));
      },
    },
    socialProviders,
    account: {
      accountLinking: {
        enabled: true,
        // Auto-link a social sign-in to an existing account with the same
        // email (including one created via email/password) → one user row with
        // multiple `account` rows, not a duplicate or an `account_not_linked`
        // error. Only safe because Google + GitHub return provider-verified
        // emails, so a matching email proves ownership. We trust exactly the
        // providers configured on this deployment (both are email-verifying);
        // an unverifying provider must never be added here.
        trustedProviders: Object.keys(socialProviders),
      },
    },
    plugins: cfg.MAGIC_LINK_ENABLED
      ? [
          magicLink({
            // v0.1.5 dashboard toggle. BetterAuth's default is `false` (magic
            // link to a new email creates the account); customers who want
            // existing-accounts-only flip this on.
            disableSignUp: cfg.MAGIC_LINK_DISABLE_SIGNUP,
            sendMagicLink: async ({ email, url }, ctx) => {
              const fixed = rewriteEmailLinkCallback(
                url,
                ctx?.request?.headers.get('origin'),
                cfg.TRUSTED_ORIGINS
              );
              await sendFlarelinkEmail(cfg, env, email, renderFor('magic-link', fixed));
            },
          }),
        ]
      : [],
    session: {
      storeSessionInDatabase: false,
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
    },
    secondaryStorage: {
      get: async (key) => (await env.SESSIONS.get(key)) ?? null,
      set: async (key, value, ttl) => {
        const opts = ttl != null ? { expirationTtl: Math.max(ttl, 60) } : undefined;
        await env.SESSIONS.put(key, value, opts);
      },
      delete: async (key) => env.SESSIONS.delete(key),
    },
    advanced: {
      // CF Workers receive the real client IP in `cf-connecting-ip`. Without
      // this, BetterAuth's per-IP rate limiting (default: 100/min, stricter
      // on sensitive endpoints) silently disables and brute-force attempts
      // are unbounded. CF-set, can't be spoofed by the client.
      ipAddress: {
        ipAddressHeaders: ['cf-connecting-ip'],
      },
      // Shared-registrable-domain topology (custom auth domain): add
      // `Domain=<registrable>` so cookies span the app + auth subdomains.
      // Partitioned stays on (below) — every relevant state shares the same
      // top-level site (the registrable domain), so the partition key is
      // consistent and older browsers that ignore Partitioned just see a
      // normal cross-subdomain cookie. Matches BetterAuth's documented
      // cross-subdomain recipe.
      ...(cookieDomain
        ? { crossSubDomainCookies: { enabled: true, domain: cookieDomain } }
        : {}),
      defaultCookieAttributes: {
        sameSite: 'none',
        secure: true,
        partitioned: true,
      },
    },
  });
}

// --- app -------------------------------------------------------------------

const app = new Hono<{ Bindings: Bindings }>();

// Defense in depth: never let an auth response sit in any shared cache.
// This Worker is pure API — sessions, OAuth callbacks, presigned-URL mints,
// password resets — none of it should ever be served from a cache to a
// different request. CF doesn't edge-cache Worker responses by default,
// but a customer-added Page Rule / Cache Rule that matches /api/auth/*
// could turn caching on; this header overrides anything they configure.
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('Cache-Control', 'no-store');
});

// Flarelink's own dashboard drives the management endpoints (/__flarelink,
// /__flarelink/test-email, /__flarelink/reload-config) browser-direct — it
// never proxies through Flarelink's server (architecture invariant). So the
// dashboard's origin must ALWAYS pass CORS, independently of the customer's
// app trustedOrigins (which are their app URLs, not the dashboard's). Without
// this, "Send test email" and config-reload pings fail CORS on every
// deployment. Hardcoded because these are Flarelink's own fixed origins.
const FLARELINK_DASHBOARD_ORIGINS = [
  'https://dash.flarelink.dev',
  'http://localhost:5173',
];

// Load config first so CORS knows trusted origins for this request. The
// loadConfig call is cached, so this is ~free on warm isolates.
app.use('*', async (c, next) => {
  const cfg = await loadConfig(c.env.DB);
  return cors({
    origin: [...cfg.TRUSTED_ORIGINS, ...FLARELINK_DASHBOARD_ORIGINS],
    credentials: true,
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  })(c, next);
});

// Bare GET / lands here only when something bypassed the callbackURL rewrite
// (an external link generator, a redirect chain that stripped the param, or
// a deployment that hasn't yet picked up v0.1.6). Redirect to the first
// trusted origin so the user is never stranded on the Worker's hostname.
// Read the config inline rather than calling createAuth — this needs to be
// cheap and never throw.
app.get('/', async (c) => {
  const cfg = await loadConfig(c.env.DB).catch(() => null);
  const target = cfg?.TRUSTED_ORIGINS?.[0];
  if (target) return c.redirect(target, 302);
  return c.text(
    `This is a Flarelink auth Worker (${FLARELINK_AUTH_VERSION}). It runs the auth API for an app on the customer's domain — open the app, not this URL.`,
    200
  );
});

app.on(['GET', 'POST'], '/api/auth/*', async (c) => {
  const baseUrl = new URL(c.req.url).origin;
  const auth = await createAuth(c.env, baseUrl);
  return auth.handler(c.req.raw);
});

app.get('/api/me', async (c) => {
  const baseUrl = new URL(c.req.url).origin;
  const auth = await createAuth(c.env, baseUrl);
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session?.user) return c.json({ user: null }, 401);
  return c.json({ user: session.user, session: session.session });
});

app.get('/__flarelink', async (c) => {
  const cfg = await loadConfig(c.env.DB);
  return c.json({
    version: FLARELINK_AUTH_VERSION,
    projectId: cfg.FLARELINK_PROJECT_ID,
    providers: Object.keys(buildSocialProviders(cfg)),
    email: cfg.EMAIL_PROVIDER ?? null,
  });
});

// Renders one of the bundled email templates as HTML for in-browser
// preview. No auth, no rate-limit — templates aren't secret and the route
// has no side effects. URLs in the rendered email are clearly-fake
// "preview-token" placeholders so a curious click can't authenticate
// anyone (the token won't validate).
//
// Returned content type is text/html so the dashboard can just
// `target="_blank"` a link to this URL.
app.get('/__flarelink/preview-email/:type', async (c) => {
  const type = c.req.param('type');
  if (!isTemplateType(type)) {
    return c.text(`unknown template type: ${type}`, 400);
  }
  const cfg = await loadConfig(c.env.DB);
  const appName = appNameFromOrigins(cfg.TRUSTED_ORIGINS);
  const workerUrl = new URL(c.req.url).origin;
  const tpl = render(
    effectiveTemplate(type, cfg.TEMPLATE_OVERRIDES[type]),
    previewUrl(type, cfg.TRUSTED_ORIGINS, workerUrl),
    appName
  );
  return new Response(tpl.html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
});

// Test-send through the configured provider. Used by the dashboard's
// "Send test email" button. Rate-limited and only sends when the caller
// supplies the deployment's FLARELINK_PROJECT_ID — that's not really a secret
// (it's exposed via /__flarelink), but it's enough to deflect drive-by spam.
// Real abuse-resistance would be a dedicated token; defer until needed.
//
// v0.1.9: optional `template` parameter sends a sample of the actual
// reset / verify / magic-link template (fake token) so customers can see
// rendering across their email clients. Omitted → original generic test
// email.
const TEST_EMAIL_MIN_INTERVAL_MS = 5_000;
let lastTestEmailAt = 0;
app.post('/__flarelink/test-email', async (c) => {
  const cfg = await loadConfig(c.env.DB);
  type Body = { to?: string; projectId?: string; template?: string };
  const body = await c.req.json<Body>().catch((): Body => ({}));
  if (!body.projectId || body.projectId !== cfg.FLARELINK_PROJECT_ID) {
    return c.json({ error: 'projectId mismatch' }, 403);
  }
  if (!body.to) return c.json({ error: 'to is required' }, 400);
  if (body.template !== undefined && !isTemplateType(body.template)) {
    return c.json({ error: `unknown template: ${body.template}` }, 400);
  }
  const templateType = body.template as TemplateType | undefined;

  const now = Date.now();
  if (now - lastTestEmailAt < TEST_EMAIL_MIN_INTERVAL_MS) {
    return c.json({ error: 'rate limited (1 test send every 5s)' }, 429);
  }
  lastTestEmailAt = now;

  if (!cfg.EMAIL_PROVIDER || !cfg.EMAIL_FROM) {
    return c.json({ error: 'email is not configured for this deployment' }, 412);
  }

  try {
    const emailCfg: EmailConfig = {
      provider: cfg.EMAIL_PROVIDER,
      from: cfg.EMAIL_FROM,
      resendApiKey: cfg.RESEND_API_KEY,
    };
    const provider = buildEmailProvider(emailCfg, c.env.EMAIL);

    let payload: { subject: string; html: string; text: string };
    if (templateType) {
      const appName = appNameFromOrigins(cfg.TRUSTED_ORIGINS);
      const workerUrl = new URL(c.req.url).origin;
      const tpl = render(
        effectiveTemplate(templateType, cfg.TEMPLATE_OVERRIDES[templateType]),
        previewUrl(templateType, cfg.TRUSTED_ORIGINS, workerUrl),
        appName
      );
      payload = {
        subject: `[preview] ${tpl.subject}`,
        html: tpl.html,
        text: tpl.text,
      };
    } else {
      payload = {
        subject: 'Flarelink test email',
        html: `<p>Hi! This is a test email from your Flarelink auth module (${FLARELINK_AUTH_VERSION}), sent via <strong>${provider.name}</strong>.</p><p>If you got this, your email module is wired up correctly.</p>`,
        text: `Hi! This is a test email from your Flarelink auth module (${FLARELINK_AUTH_VERSION}), sent via ${provider.name}. If you got this, your email module is wired up correctly.`,
      };
    }

    await provider.send({ from: cfg.EMAIL_FROM, to: body.to, ...payload });
    return c.json({ ok: true, provider: provider.name, template: templateType ?? 'generic' });
  } catch (err) {
    // Surface message; collapse upstream status to 500 so Hono's response
    // typing stays happy. Dashboard reads `error` field for the real reason.
    return c.json({ error: (err as Error).message }, 500);
  }
});

// --- v0.2 storage surface (gated by per-project service key) ----------------
//
// The customer's app server calls these via `@flarelink/client`'s
// `flarelink.storage.*` methods with `Authorization: Bearer <serviceKey>`. We
// hash the incoming key with SHA-256 and constant-time compare against
// SERVICE_KEY_HASH in flarelink_config. R2 credentials live in the same
// flarelink_config table — Flarelink writes them at provision time. With the keys
// and the project's service key, the Worker signs S3 requests via SigV4
// without ever needing to call back to Flarelink's dashboard.

type StorageReady = {
  cfg: Config;
  r2: R2Creds;
};

// Base service-key auth — extracts the Bearer token, hashes it, constant-time
// compares against SERVICE_KEY_HASH in flarelink_config. Used by both /api/db/*
// and (wrapped by requireStorageAuth) /api/storage/*. Returns the loaded
// Config on success or a 401/412 Response with a machine-readable `code`.
async function requireServiceKey(
  c: import('hono').Context<{ Bindings: Bindings }>,
): Promise<{ cfg: Config } | Response> {
  const cfg = await loadConfig(c.env.DB);
  if (!cfg.SERVICE_KEY_HASH) {
    return c.json(
      {
        error:
          'Service key not provisioned for this deployment. Click Redeploy on the Authentication page to mint one.',
        code: 'SERVICE_KEY_NOT_PROVISIONED',
      },
      412,
    );
  }
  const authz = c.req.header('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(authz.trim());
  if (!match) {
    return c.json(
      { error: 'Missing Authorization: Bearer <serviceKey> header.', code: 'MISSING_SERVICE_KEY' },
      401,
    );
  }
  const incoming = match[1].trim();
  const incomingHash = await hashServiceKey(incoming);
  if (!constantTimeEqual(incomingHash, cfg.SERVICE_KEY_HASH)) {
    return c.json({ error: 'Invalid service key.', code: 'INVALID_SERVICE_KEY' }, 401);
  }
  return { cfg };
}

// Storage adds an R2-credentials requirement on top of the base service-key
// check. If R2 isn't configured yet the customer's apps can still call the
// auth + db routes — only storage 412s.
async function requireStorageAuth(c: import('hono').Context<{ Bindings: Bindings }>): Promise<
  StorageReady | Response
> {
  const guard = await requireServiceKey(c);
  if (guard instanceof Response) return guard;
  const { cfg } = guard;
  if (!cfg.R2_ACCOUNT_ID || !cfg.R2_ACCESS_KEY_ID || !cfg.R2_SECRET_ACCESS_KEY) {
    return c.json(
      {
        error:
          'R2 credentials are not configured for this project. Generate them from the Flarelink dashboard Files page, then retry.',
        code: 'R2_NOT_CONFIGURED',
      },
      412,
    );
  }
  return {
    cfg,
    r2: {
      accountId: cfg.R2_ACCOUNT_ID,
      accessKeyId: cfg.R2_ACCESS_KEY_ID,
      secretAccessKey: cfg.R2_SECRET_ACCESS_KEY,
    },
  };
}

// Presign a PUT or GET URL. Body shape mirrors what `@flarelink/client`'s
// `storage.from(bucket).createSignedUploadUrl(key)` and
// `createSignedDownloadUrl(key)` send. expiresIn is clamped to [60, 3600]
// server-side so a bad SDK call can't mint a 7-day URL.
app.post('/api/storage/presign', async (c) => {
  const guard = await requireStorageAuth(c);
  if (guard instanceof Response) return guard;
  type Body = {
    bucket?: string;
    key?: string;
    op?: 'put' | 'get';
    contentType?: string;
    expiresIn?: number;
  };
  const body = await c.req.json<Body>().catch((): Body => ({}));
  if (!body.bucket || !body.key) {
    return c.json({ error: 'bucket and key are required' }, 400);
  }
  if (body.op !== 'put' && body.op !== 'get') {
    return c.json({ error: "op must be 'put' or 'get'" }, 400);
  }
  const expiresIn = clamp(body.expiresIn ?? 300, 60, 3600);
  const signedHeaders: Record<string, string> = {};
  if (body.op === 'put' && body.contentType) {
    signedHeaders['content-type'] = body.contentType;
  }
  const url = await presignUrl({
    creds: guard.r2,
    method: body.op === 'put' ? 'PUT' : 'GET',
    bucket: body.bucket,
    key: body.key,
    expiresIn,
    signedHeaders,
  });
  return c.json({ url, signedHeaders, expiresIn });
});

// Delete a single object via signedFetch — same code path the dashboard uses.
app.delete('/api/storage/object', async (c) => {
  const guard = await requireStorageAuth(c);
  if (guard instanceof Response) return guard;
  type Body = { bucket?: string; key?: string };
  const body = await c.req.json<Body>().catch((): Body => ({}));
  if (!body.bucket || !body.key) {
    return c.json({ error: 'bucket and key are required' }, 400);
  }
  const res = await signedFetch({
    creds: guard.r2,
    method: 'DELETE',
    path: `/${encodeS3(body.bucket)}/${encodeS3(body.key)}`,
  });
  if (!res.ok && res.status !== 404) {
    return c.json({ error: `R2 delete failed (${res.status})` }, 502);
  }
  return c.json({ ok: true });
});

// ListObjectsV2 against a bucket. Returns objects + CommonPrefixes parsed
// from the S3 XML response. Same regex extraction the dashboard uses.
app.get('/api/storage/list', async (c) => {
  const guard = await requireStorageAuth(c);
  if (guard instanceof Response) return guard;
  const bucket = c.req.query('bucket');
  if (!bucket) return c.json({ error: 'bucket is required' }, 400);
  const prefix = c.req.query('prefix') ?? '';
  const cursor = c.req.query('cursor') ?? '';
  const query: Record<string, string> = {
    'list-type': '2',
    delimiter: '/',
    'max-keys': '1000',
  };
  if (prefix) query.prefix = prefix;
  if (cursor) query['continuation-token'] = cursor;
  const res = await signedFetch({
    creds: guard.r2,
    method: 'GET',
    path: `/${encodeS3(bucket)}`,
    query,
  });
  if (!res.ok) {
    return c.json({ error: `R2 list failed (${res.status})` }, 502);
  }
  const xml = await res.text();
  return c.json(parseListXml(xml));
});

// ListBuckets across the customer's R2 account. The SDK call is the
// `flarelink.storage.listBuckets()` entry. No per-project allowlist — anyone
// with the service key sees the customer's whole R2 account. Same security
// model as raw R2 keys, just rebadged.
app.get('/api/storage/buckets', async (c) => {
  const guard = await requireStorageAuth(c);
  if (guard instanceof Response) return guard;
  const res = await signedFetch({ creds: guard.r2, method: 'GET', path: '/' });
  if (!res.ok) {
    return c.json({ error: `R2 list-buckets failed (${res.status})` }, 502);
  }
  const xml = await res.text();
  return c.json({ buckets: parseListBucketsXml(xml) });
});

// --- v0.2 database surface (gated by per-project service key) ---------------
//
// The customer's server-side code calls these via @flarelink/client's
// `flarelink.from(table).select()`/`.insert()`/`.update()`/`.delete()` or via
// `flarelink.sql\`...\``. Both translate to one of two HTTP shapes:
//
//   POST /api/db/query  { sql, params? }       — single statement
//   POST /api/db/batch  { statements: [...] }  — atomic batch (one round-trip)
//
// Queries run against the Worker's `DB` binding — the same D1 that holds
// the auth tables (user / account / verification / flarelink_config). Customer
// schemas coexist with auth tables in the same database. Schema management
// happens via the Flarelink dashboard Table editor (or `flarelink.sql\`CREATE
// TABLE...\``).
//
// No row-level security: anyone with the service key has full DB access.
// Service key is server-only by contract — leaking it is the same risk
// surface as leaking direct D1 credentials. RLS-style policies are v0.3+.

// Validates an identifier (table/column name) against SQLite's rules.
// The SDK pre-validates too; this is defence-in-depth. Anything that
// doesn't match here can't reach a SQL string interpolation.
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

type DbQueryBody = { sql?: string; params?: unknown[] };

async function execD1(
  db: D1Database,
  sql: string,
  params: unknown[],
): Promise<{ results: unknown[]; meta: D1Meta }> {
  // Bind takes spread args. D1 stringifies non-{string|number|boolean|null}
  // values implicitly — pass primitives through, JSON-stringify object/array
  // values so the caller doesn't have to remember which is which. NULL stays
  // null. Caller already validated identifiers, so no concat-string risk here.
  const stmt = db.prepare(sql);
  const bound = params.length > 0 ? stmt.bind(...params.map(coerceParam)) : stmt;
  const r = await bound.all();
  return { results: r.results, meta: r.meta as unknown as D1Meta };
}

function coerceParam(v: unknown): unknown {
  if (v === null || v === undefined) return null;
  const t = typeof v;
  if (t === 'string' || t === 'number' || t === 'boolean') return v;
  // Buffer/Uint8Array land here too. Customer's call.
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return v;
  // Stringify objects + arrays as JSON. Common when caller passes a
  // structured value into a TEXT/JSON column.
  return JSON.stringify(v);
}

type D1Meta = {
  duration: number;
  rows_read?: number;
  rows_written?: number;
  last_row_id?: number;
  changes?: number;
};

app.post('/api/db/query', async (c) => {
  const guard = await requireServiceKey(c);
  if (guard instanceof Response) return guard;
  const body = await c.req.json<DbQueryBody>().catch((): DbQueryBody => ({}));
  if (!body.sql || typeof body.sql !== 'string') {
    return c.json({ error: 'sql is required', code: 'INVALID_SQL' }, 400);
  }
  const params = Array.isArray(body.params) ? body.params : [];
  try {
    const out = await execD1(c.env.DB, body.sql, params);
    return c.json(out);
  } catch (err) {
    return c.json(
      { error: (err as Error).message, code: 'D1_QUERY_FAILED' },
      400,
    );
  }
});

app.post('/api/db/batch', async (c) => {
  const guard = await requireServiceKey(c);
  if (guard instanceof Response) return guard;
  type Body = { statements?: { sql?: string; params?: unknown[] }[] };
  const body = await c.req.json<Body>().catch((): Body => ({}));
  if (!Array.isArray(body.statements) || body.statements.length === 0) {
    return c.json({ error: 'statements[] is required', code: 'INVALID_BATCH' }, 400);
  }
  const stmts: D1PreparedStatement[] = [];
  for (let i = 0; i < body.statements.length; i++) {
    const s = body.statements[i];
    if (!s?.sql || typeof s.sql !== 'string') {
      return c.json(
        { error: `statements[${i}].sql is required`, code: 'INVALID_BATCH' },
        400,
      );
    }
    const params = Array.isArray(s.params) ? s.params : [];
    const stmt = c.env.DB.prepare(s.sql);
    stmts.push(params.length > 0 ? stmt.bind(...params.map(coerceParam)) : stmt);
  }
  try {
    const responses = await c.env.DB.batch(stmts);
    return c.json({
      responses: responses.map((r) => ({
        results: r.results,
        meta: r.meta as unknown as D1Meta,
      })),
    });
  } catch (err) {
    return c.json(
      { error: (err as Error).message, code: 'D1_BATCH_FAILED' },
      400,
    );
  }
});

// Exported for the SDK to mirror — identifier validation must match on
// both ends so the customer sees the same error whether the bad name is
// caught client-side or server-side. Kept inline rather than imported
// because the auth Worker bundles separately.
function isValidIdent(s: string): boolean {
  return typeof s === 'string' && IDENT_RE.test(s);
}
// Reference so the bundler keeps it; future routes that validate
// identifiers server-side (e.g. metadata read endpoints) will call it.
void isValidIdent;

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, Math.floor(n)));
}

function encodeS3(seg: string): string {
  return seg
    .split('/')
    .map((s) =>
      encodeURIComponent(s).replace(
        /[!'()*]/g,
        (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase(),
      ),
    )
    .join('/');
}

// Hand-rolled XML extraction — same approach as server/routes/r2.ts.
// S3's ListObjectsV2 shape is stable enough that a full parser would
// 2× the worker bundle for no gain.
function parseListXml(xml: string): {
  objects: { key: string; size: number; lastModified: string; etag: string }[];
  prefixes: string[];
  nextCursor?: string;
} {
  const objects: { key: string; size: number; lastModified: string; etag: string }[] = [];
  const contentRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  let m: RegExpExecArray | null;
  while ((m = contentRe.exec(xml))) {
    const body = m[1];
    const key = pluck(body, 'Key');
    const size = Number(pluck(body, 'Size') ?? '0');
    const lastModified = pluck(body, 'LastModified') ?? '';
    const etag = (pluck(body, 'ETag') ?? '').replace(/^"|"$/g, '');
    if (key !== undefined) objects.push({ key, size, lastModified, etag });
  }
  const prefixes: string[] = [];
  const prefRe = /<CommonPrefixes>([\s\S]*?)<\/CommonPrefixes>/g;
  while ((m = prefRe.exec(xml))) {
    const p = pluck(m[1], 'Prefix');
    if (p) prefixes.push(p);
  }
  const truncated = pluck(xml, 'IsTruncated') === 'true';
  const nextCursor = truncated ? pluck(xml, 'NextContinuationToken') ?? undefined : undefined;
  return { objects, prefixes, nextCursor };
}

function parseListBucketsXml(xml: string): { name: string; createdAt: string }[] {
  const out: { name: string; createdAt: string }[] = [];
  const re = /<Bucket>([\s\S]*?)<\/Bucket>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const name = pluck(m[1], 'Name');
    const createdAt = pluck(m[1], 'CreationDate') ?? '';
    if (name) out.push({ name, createdAt });
  }
  return out;
}

function pluck(xml: string, tag: string): string | undefined {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`);
  const m = re.exec(xml);
  return m ? m[1] : undefined;
}

// Called by Flarelink right after writing to flarelink_config so config changes
// propagate without waiting on the 60s TTL. Idempotent + cheap (no DB hit
// here — just nukes the in-memory cache; the next real request reloads).
//
// Endpoint is unauthenticated by design — it triggers no DB I/O itself —
// but rate-limited per-isolate to 1/sec so spam can't force a flood of D1
// reads on follow-up traffic. Real reload calls come from the dashboard
// after a config write (a handful per minute at most), well under the cap.
const RELOAD_MIN_INTERVAL_MS = 1000;
let lastReloadAt = 0;
app.post('/__flarelink/reload-config', (c) => {
  const now = Date.now();
  if (now - lastReloadAt < RELOAD_MIN_INTERVAL_MS) {
    return c.json({ ok: true, throttled: true });
  }
  lastReloadAt = now;
  invalidateConfigCache();
  return c.json({ ok: true });
});

app.notFound((c) => c.json({ error: 'not found' }, 404));

export default app;
