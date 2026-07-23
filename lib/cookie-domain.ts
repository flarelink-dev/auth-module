// Decides whether the auth Worker should issue Domain-scoped cookies so the
// session + OAuth-state cookies are shared across the app and auth subdomains.
//
// The bug this fixes: BetterAuth's cookies default to host-only (no `Domain`
// attribute). In the recommended production topology the app lives on one
// subdomain and the auth Worker's custom domain on a sibling subdomain of the
// same registrable domain — e.g. app on `editor.gridsnap.app`, auth on
// `auth.gridsnap.app`. Two failures follow from host-only cookies:
//
//   1. OAuth state mismatch. The app proxies `/api/auth/*`, so the state
//      cookie is set for the *app* host (editor.gridsnap.app). But the OAuth
//      `redirect_uri` is pinned to the *auth* host — Google redirects the
//      browser straight to `auth.gridsnap.app/api/auth/callback/google`, where
//      a host-only editor cookie is not sent. State check fails → sign-in dies.
//   2. Invisible session. Even starting the flow directly on the auth host,
//      the session cookie ends up host-only on `auth.gridsnap.app`, so the
//      app's own server routes (reading the cookie off editor-origin requests)
//      never see it → 401 for every OAuth user.
//
// Setting `Domain=gridsnap.app` makes the cookie valid for every
// `*.gridsnap.app` host, so both problems vanish and the same cookie works for
// the proxied password flow, the direct OAuth callback, and the app's SSR
// routes alike. This is exactly the topology Flarelink's own docs recommend,
// so any Flarelink app with server-side API routes benefits.
//
// We derive the shared domain as the longest common domain suffix between the
// auth host and a trusted app origin, rather than stripping a label or
// consulting the Public Suffix List. That is inherently correct (the value we
// want is precisely the domain covering both hosts) and needs no PSL data. We
// still guard against the multi-tenant CF suffixes (`*.workers.dev`,
// `*.pages.dev`), where two hosts on the same account would otherwise share a
// suffix like `acme.workers.dev` and leak cookies across unrelated Workers.
// When there is no safe shared domain (genuinely cross-site topology, or the
// workers.dev fallback URL), we return null and BetterAuth keeps its host-only
// + `Partitioned` cookies, which is correct for the cross-site case.

const MULTI_TENANT_SUFFIXES = ['workers.dev', 'pages.dev'];

function labelCount(host: string): number {
  return host.split('.').filter(Boolean).length;
}

// Longest suffix of whole domain labels shared by two hostnames.
// ("auth.gridsnap.app", "editor.gridsnap.app") -> "gridsnap.app"
// ("a.workers.dev", "b.gridsnap.app")          -> null (TLDs differ)
export function longestCommonDomainSuffix(a: string, b: string): string | null {
  const A = a.toLowerCase().split('.');
  const B = b.toLowerCase().split('.');
  const out: string[] = [];
  let i = A.length - 1;
  let j = B.length - 1;
  while (i >= 0 && j >= 0 && A[i] === B[j]) {
    out.unshift(A[i]);
    i--;
    j--;
  }
  return out.length ? out.join('.') : null;
}

function isUnsafeCookieDomain(d: string): boolean {
  // Need at least a registrable-shape domain (label + TLD). A bare TLD
  // ("app", "com") or single label can never be a valid cookie Domain.
  if (labelCount(d) < 2) return true;
  // Never Domain-scope across a multi-tenant CF suffix — that would share
  // cookies across every Worker/Pages project on the same account subdomain.
  return MULTI_TENANT_SUFFIXES.some((s) => d === s || d.endsWith(`.${s}`));
}

/**
 * Returns the domain to scope auth cookies to (e.g. `gridsnap.app`), or null
 * when host-only cookies should be kept (workers.dev fallback, or a genuinely
 * cross-site app/auth topology on different registrable domains).
 *
 * @param authHost      the host the auth Worker is currently serving (from the
 *                      request origin — a custom domain, or the workers.dev URL)
 * @param trustedOrigins the app origins configured for this deployment
 */
export function sharedCookieDomain(authHost: string, trustedOrigins: string[]): string | null {
  if (!authHost || authHost === 'localhost' || authHost === '127.0.0.1') return null;

  let best: string | null = null;
  for (const origin of trustedOrigins) {
    let appHost: string;
    try {
      appHost = new URL(origin).hostname;
    } catch {
      continue;
    }
    if (appHost === 'localhost' || appHost === '127.0.0.1') continue;

    const common = longestCommonDomainSuffix(authHost, appHost);
    if (!common || isUnsafeCookieDomain(common)) continue;

    // Prefer the shortest (most-covering) safe shared domain across all origins.
    if (!best || labelCount(common) < labelCount(best)) best = common;
  }
  return best;
}
