// Default email templates baked into the customer Worker + the per-customer
// override path. v0.1.10 made these editable from the dashboard.
//
// Shape: a template is a `{ subject, html, text }` triple where each string
// may contain `{{url}}` and `{{appName}}` placeholders. The Worker renders
// at send-time via `render()` below.
//
// Storage:
//   Default → these constants, baked into the bundle.
//   Override → 9 flarelink_config rows (3 types × subject/html/text).
//              Override wins per-field — customizing subject doesn't force
//              you to override html/text.
//
// Style philosophy: plain, scannable, no marketing chrome. Inline styles
// only (Gmail strips <head>). One CTA button. App name derives from the
// first TRUSTED_ORIGIN's hostname so subjects don't look like spam from
// "auth-worker.workers.dev".

export type Template = {
  subject: string;
  html: string;
  text: string;
};

export type TemplateType = 'reset' | 'verify' | 'magic-link';

export const TEMPLATE_TYPES: TemplateType[] = ['reset', 'verify', 'magic-link'];

export function isTemplateType(s: string): s is TemplateType {
  return (TEMPLATE_TYPES as string[]).includes(s);
}

// Pick a human-readable app name from the trusted origins list. The Worker
// has no other notion of "what app is this?", so the first origin is the
// best signal. Returns "your app" as the universal fallback so we never
// blank out a template.
export function appNameFromOrigins(origins: string[]): string {
  for (const o of origins) {
    try {
      return new URL(o).hostname.replace(/^www\./, '');
    } catch {
      // Skip malformed entries; trustedOrigins is validated upstream but
      // belt-and-braces here keeps templates from throwing on a bad row.
    }
  }
  return 'your app';
}

// --- substitution ---------------------------------------------------------

// HTML-escape so a weird trusted origin (e.g. one with `<` in it, hypothetical)
// can't inject markup into the rendered email body. URLs are passed through
// raw because they're already URL-encoded by BetterAuth and need to remain
// clickable in href context.
function htmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fillSubject(tpl: string, url: string, appName: string): string {
  // Subject is plain text — no HTML escaping needed; substituting the URL
  // into a subject line is unusual but technically allowed.
  return tpl.replaceAll('{{url}}', url).replaceAll('{{appName}}', appName);
}

function fillHtml(tpl: string, url: string, appName: string): string {
  // appName escaped because it lands in HTML context. URL stays raw — it's
  // an absolute URL that BetterAuth has already constructed; double-encoding
  // would break it.
  return tpl.replaceAll('{{url}}', url).replaceAll('{{appName}}', htmlEscape(appName));
}

function fillText(tpl: string, url: string, appName: string): string {
  return tpl.replaceAll('{{url}}', url).replaceAll('{{appName}}', appName);
}

export function render(tpl: Template, url: string, appName: string): Template {
  return {
    subject: fillSubject(tpl.subject, url, appName),
    html: fillHtml(tpl.html, url, appName),
    text: fillText(tpl.text, url, appName),
  };
}

// --- defaults (in storable / editable form) -------------------------------
//
// These constants are what gets shown in the dashboard editor as the
// starting point. Same `{{url}}` / `{{appName}}` placeholders the Worker
// substitutes at send time.

const HTML_SHELL_OPEN =
  '<!doctype html><html><body style="font-family:-apple-system,system-ui,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:0 auto;padding:24px;">';
const HTML_SHELL_CLOSE =
  '<p style="color:#666;font-size:12px;margin-top:32px;">If you did not request this, you can safely ignore this email.</p></body></html>';

function defaultHtml(title: string, body: string): string {
  return [
    HTML_SHELL_OPEN,
    `<h1 style="font-size:18px;font-weight:600;margin:0 0 16px;">${title}</h1>`,
    body,
    HTML_SHELL_CLOSE,
  ].join('');
}

function defaultButton(url: string, label: string): string {
  return `<p style="margin:24px 0;"><a href="${url}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:10px 16px;border-radius:6px;font-weight:500;">${label}</a></p>`;
}

function defaultFallback(url: string): string {
  return `<p style="color:#666;font-size:13px;">Or paste this link into your browser:<br><span style="word-break:break-all;color:#444;">${url}</span></p>`;
}

export const DEFAULT_TEMPLATES: Record<TemplateType, Template> = {
  reset: {
    subject: 'Reset your password for {{appName}}',
    html: defaultHtml(
      'Reset your password for {{appName}}',
      `<p>We got a request to reset your password. Click the button below — the link expires in 1 hour.</p>${defaultButton('{{url}}', 'Reset password')}${defaultFallback('{{url}}')}`
    ),
    text: 'Reset your password for {{appName}}\n\nWe got a request to reset your password. Open this link — it expires in 1 hour:\n\n{{url}}\n\nIf you did not request this, ignore this email.',
  },
  verify: {
    subject: 'Verify your email for {{appName}}',
    html: defaultHtml(
      'Verify your email for {{appName}}',
      `<p>Confirm this is your email address by clicking the button below.</p>${defaultButton('{{url}}', 'Verify email')}${defaultFallback('{{url}}')}`
    ),
    text: 'Verify your email for {{appName}}\n\nConfirm this is your email address by opening this link:\n\n{{url}}\n\nIf you did not sign up, ignore this email.',
  },
  'magic-link': {
    subject: 'Sign in to {{appName}}',
    html: defaultHtml(
      'Sign in to {{appName}}',
      `<p>Click the button below to sign in. The link expires in 5 minutes and can only be used once.</p>${defaultButton('{{url}}', 'Sign in')}${defaultFallback('{{url}}')}`
    ),
    text: 'Sign in to {{appName}}\n\nOpen this link to sign in — it expires in 5 minutes and can only be used once:\n\n{{url}}\n\nIf you did not request this, ignore this email.',
  },
};

// Compose a template by overlaying per-field overrides onto defaults. Used
// by the Worker — pass in whatever subset the customer has customised and
// get back a complete `{ subject, html, text }`.
export function effectiveTemplate(
  type: TemplateType,
  overrides: Partial<Template>
): Template {
  const base = DEFAULT_TEMPLATES[type];
  return {
    subject: overrides.subject ?? base.subject,
    html: overrides.html ?? base.html,
    text: overrides.text ?? base.text,
  };
}

// --- preview URL (for the dashboard preview + /__flarelink/preview-email) ----

export function previewUrl(
  type: TemplateType,
  trustedOrigins: string[],
  workerUrl: string
): string {
  const appOrigin = trustedOrigins[0] ?? workerUrl;
  const fakeToken = 'preview-token-not-a-real-verification';
  const callback = encodeURIComponent(appOrigin + '/');
  switch (type) {
    case 'reset':
      return `${workerUrl}/api/auth/reset-password/${fakeToken}?callbackURL=${callback}`;
    case 'verify':
      return `${workerUrl}/api/auth/verify-email?token=${fakeToken}&callbackURL=${callback}`;
    case 'magic-link':
      return `${workerUrl}/api/auth/magic-link/verify?token=${fakeToken}&callbackURL=${callback}`;
  }
}
