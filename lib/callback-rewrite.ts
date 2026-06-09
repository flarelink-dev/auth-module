// Rewrites the `callbackURL` param on BetterAuth-generated email links so it
// points back at the customer's app instead of the Flarelink-deployed auth Worker.
//
// The bug this fixes: BetterAuth builds verify / reset / magic-link URLs as
// `${baseURL}/verify-email?token=X&callbackURL=Y`. When the caller doesn't
// supply a `callbackURL` (e.g. the auto-send-on-signup path that we don't
// control), BetterAuth defaults Y to `/`. After the user clicks the link
// and the token is consumed, BetterAuth redirects to `/` — which resolves
// against the Worker's hostname (`https://auth.workers.dev/`), where there's
// no `/` route → 404.
//
// Architecturally the Worker should never be the user's final destination.
// The customer's app is; the Worker is just the auth backend. So we rewrite
// any relative callbackURL to an absolute URL pointing at the customer's
// origin (preferring the inbound request's `Origin` header when it's a
// trusted origin — that's the most accurate signal for "where the user
// just came from" — and falling back to the first entry of TRUSTED_ORIGINS).
//
// Security: BetterAuth's downstream `originCheck` re-validates the
// rewritten callbackURL against trustedOrigins, so we can't be tricked into
// generating a URL it would refuse. We additionally reject protocol-relative
// paths (//evil.com) here to fail closed before BetterAuth's check fires.

export function rewriteEmailLinkCallback(
  emailUrl: string,
  requestOrigin: string | null | undefined,
  trustedOrigins: string[]
): string {
  let parsed: URL;
  try {
    parsed = new URL(emailUrl);
  } catch {
    return emailUrl;
  }

  const cb = parsed.searchParams.get('callbackURL') ?? '';
  // Already an absolute URL — leave it. BetterAuth will originCheck downstream.
  if (/^https?:\/\//i.test(cb)) return emailUrl;

  // Pick a base origin for the relative path. Request Origin wins when it's
  // a trusted origin (the user came from there, send them back). Otherwise
  // fall back to the first TRUSTED_ORIGINS entry — arbitrary but the only
  // sane default.
  const base =
    requestOrigin && trustedOrigins.includes(requestOrigin)
      ? requestOrigin
      : trustedOrigins[0];
  if (!base) return emailUrl;

  // Defense in depth: a `//foo.com` callbackURL would resolve to a
  // different origin under `new URL`. Force protocol-relative + empty to
  // canonical `/`.
  const path = !cb || cb.startsWith('//') ? '/' : cb;

  let absolute: string;
  try {
    absolute = new URL(path, base).toString();
  } catch {
    absolute = base.endsWith('/') ? base : `${base}/`;
  }

  // Final sanity check — the rewritten absolute MUST sit on `base`. If
  // somehow the URL parser surprised us, fall back to the bare base.
  try {
    const out = new URL(absolute);
    const baseUrl = new URL(base);
    if (out.origin !== baseUrl.origin) {
      absolute = baseUrl.origin + '/';
    }
  } catch {
    absolute = base.endsWith('/') ? base : `${base}/`;
  }

  parsed.searchParams.set('callbackURL', absolute);
  return parsed.toString();
}
