import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sharedCookieDomain, longestCommonDomainSuffix } from '../lib/cookie-domain.ts';

test('longestCommonDomainSuffix matches whole labels from the right', () => {
  assert.equal(longestCommonDomainSuffix('auth.gridsnap.app', 'editor.gridsnap.app'), 'gridsnap.app');
  assert.equal(longestCommonDomainSuffix('auth.gridsnap.app', 'gridsnap.app'), 'gridsnap.app');
  // Different TLDs share nothing.
  assert.equal(longestCommonDomainSuffix('a.workers.dev', 'b.gridsnap.app'), null);
  // Must not partial-match within a label (…snap.app vs …grid.app).
  assert.equal(longestCommonDomainSuffix('x.foosnap.app', 'y.barsnap.app'), 'app');
});

test('scopes cookies to the shared registrable domain for a custom auth domain', () => {
  assert.equal(sharedCookieDomain('auth.gridsnap.app', ['https://editor.gridsnap.app']), 'gridsnap.app');
  // App at the apex.
  assert.equal(sharedCookieDomain('auth.gridsnap.app', ['https://gridsnap.app']), 'gridsnap.app');
  // Deeper auth host still resolves to the covering registrable domain.
  assert.equal(sharedCookieDomain('auth.foo.gridsnap.app', ['https://editor.gridsnap.app']), 'gridsnap.app');
  // localhost origins are ignored; the real origin wins.
  assert.equal(
    sharedCookieDomain('auth.gridsnap.app', ['http://localhost:5174', 'https://editor.gridsnap.app']),
    'gridsnap.app'
  );
});

test('keeps host-only cookies (null) when there is no safe shared domain', () => {
  // workers.dev fallback URL — different TLD from the app.
  assert.equal(sharedCookieDomain('gridsnap-auth.jaan-f97.workers.dev', ['https://editor.gridsnap.app']), null);
  // Genuinely cross-site: different registrable domains.
  assert.equal(sharedCookieDomain('auth.mycompany.com', ['https://app.myapp.io']), null);
  // localhost only.
  assert.equal(sharedCookieDomain('localhost', ['http://localhost:5174']), null);
});

test('never Domain-scopes across a multi-tenant CF suffix (cross-Worker leak guard)', () => {
  // Two Workers on the same account subdomain share `jaan-f97.workers.dev`,
  // which must NOT become a cookie Domain (would leak across unrelated Workers).
  assert.equal(
    sharedCookieDomain('gridsnap-auth.jaan-f97.workers.dev', ['https://gridsnap-app.jaan-f97.workers.dev']),
    null
  );
  // Same for pages.dev.
  assert.equal(sharedCookieDomain('auth.acme.pages.dev', ['https://app.acme.pages.dev']), null);
});
