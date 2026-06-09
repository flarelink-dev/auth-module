// flarelinkAuth.ts — typed client for a Flarelink auth-module deployment.
//
// Generated for: __FLARELINK_AUTH_URL__
// Flarelink auth module: v__FLARELINK_AUTH_VERSION__
//
// One file, zero dependencies. Paste into your project, import what you
// need. Every method sends `credentials: 'include'` so the browser carries
// the session cookie automatically — your app must be on an origin in the
// deployment's trustedOrigins list, or requests come back as 403.
//
// Single-deployment usage:
//   import { signIn, signUp, signOut, getMe } from './flarelinkAuth';
//
// Multi-deployment (or SSR with a custom fetch):
//   import { createAuth } from './flarelinkAuth';
//   const auth = createAuth({ url: process.env.AUTH_URL, fetch: myFetch });

const AUTH_URL = '__FLARELINK_AUTH_URL__';

export type User = {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  image: string | null;
  createdAt: string;
  updatedAt: string;
};

export type Session = {
  id: string;
  userId: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
  ipAddress?: string | null;
  userAgent?: string | null;
};

export type SignUpInput = {
  email: string;
  password: string;
  name: string;
  /**
   * URL the user lands on after clicking the verification email link
   * (only relevant when email verification is enabled on this deployment).
   * Defaults to the current page URL (`location.href`) when called from a
   * browser. The auth Worker itself has no `/` route, so leaving this blank
   * on a non-browser caller will redirect to the first trusted origin.
   */
  callbackURL?: string;
};
export type SignInInput = { email: string; password: string };
export type SocialProvider = 'google' | 'github';
export type SignInWithSocialOptions = {
  /** Where to send the user after the OAuth dance finishes. Default: current URL. */
  callbackURL?: string;
  /** If true, return the provider URL instead of navigating. Useful for SSR. */
  noRedirect?: boolean;
};
export type RequestPasswordResetInput = {
  email: string;
  /**
   * Page on your app the user lands on after clicking the link in the email.
   * BetterAuth appends `?token=...` to it; your page reads the token and
   * calls resetPassword({ newPassword, token }).
   */
  redirectTo: string;
};
export type ResetPasswordInput = { newPassword: string; token: string };
export type SendVerificationEmailInput = {
  email: string;
  /** URL the user lands on after the email is verified. Default: current URL. */
  callbackURL?: string;
};
export type SignInWithMagicLinkOptions = {
  /** URL the user lands on after the magic-link sign-in succeeds. Default: current URL. */
  callbackURL?: string;
};

// Auth failures keep BetterAuth's status + machine-readable code so callers
// can branch on "INVALID_PASSWORD" vs "USER_NOT_FOUND" vs "TOO_MANY_REQUESTS"
// without string-matching the message.
export class AuthError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

export type AuthOptions = {
  /** Override the URL baked in at generation time. Useful for dev/prod splits. */
  url?: string;
  /** Replace fetch — for SSR, tests, or runtimes without a global. */
  fetch?: typeof fetch;
};

export type Auth = {
  signUp(input: SignUpInput): Promise<{ user: User }>;
  signIn(input: SignInInput): Promise<{ user: User }>;
  signInWithSocial(provider: SocialProvider, opts?: SignInWithSocialOptions): Promise<{ url: string }>;
  signInWithMagicLink(email: string, opts?: SignInWithMagicLinkOptions): Promise<{ status: boolean }>;
  signOut(): Promise<void>;
  /**
   * Triggers a password-reset email. Always resolves with `{ status: true }`
   * even when the email is unknown — that's deliberate, BetterAuth doesn't
   * leak account existence on this endpoint.
   */
  requestPasswordReset(input: RequestPasswordResetInput): Promise<{ status: boolean }>;
  /**
   * Completes the reset using the token from the email link. Your reset
   * page reads `?token=` from the URL and passes it here alongside the
   * new password.
   */
  resetPassword(input: ResetPasswordInput): Promise<{ status: boolean }>;
  /**
   * Sends a verification email to the address. The link in the email lands
   * the user on `callbackURL` after the email is marked verified.
   */
  sendVerificationEmail(input: SendVerificationEmailInput): Promise<{ status: boolean }>;
  getMe(): Promise<User | null>;
  getSession(): Promise<Session | null>;
};

export function createAuth(opts: AuthOptions = {}): Auth {
  const base = (opts.url ?? AUTH_URL).replace(/\/$/, '');
  const f = opts.fetch ?? fetch;

  async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
    // BetterAuth is strict on two fronts: state-changing requests must declare
    // Content-Type: application/json (else 415), AND if Content-Type is JSON
    // the body has to actually parse as JSON (empty body throws). For POSTs
    // like sign-out that semantically have nothing to send, we default the
    // body to "{}" so both checks pass.
    const method = (init.method ?? 'GET').toUpperCase();
    const bodyBearing = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
    const headers: Record<string, string> = {
      ...((init.headers as Record<string, string> | undefined) ?? {}),
    };
    let body = init.body;
    if (bodyBearing) {
      if (body === undefined || body === null) body = '{}';
      if (headers['Content-Type'] === undefined) headers['Content-Type'] = 'application/json';
    }
    const res = await f(`${base}${path}`, { ...init, credentials: 'include', headers, body });
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as {
        message?: string;
        error?: string;
        code?: string;
      };
      throw new AuthError(
        body.message ?? body.error ?? res.statusText,
        res.status,
        body.code
      );
    }
    return (await res.json()) as T;
  }

  const me = async (): Promise<{ user: User; session: Session } | null> => {
    try {
      return await call<{ user: User; session: Session }>('/api/me');
    } catch (err) {
      if (err instanceof AuthError && err.status === 401) return null;
      throw err;
    }
  };

  // Default a missing browser-side callbackURL to the current page so the
  // auto-send-on-signup verification email lands the user back where they
  // started. Without this, BetterAuth defaults to `/` which resolves against
  // the auth Worker's hostname → 404. Non-browser callers (SSR, tests) pass
  // explicit values or accept the Worker's first-trusted-origin fallback.
  const browserDefault = () =>
    typeof location !== 'undefined' ? location.href : undefined;

  return {
    signUp: (input) =>
      call<{ user: User }>('/api/auth/sign-up/email', {
        method: 'POST',
        body: JSON.stringify({
          ...input,
          callbackURL: input.callbackURL ?? browserDefault(),
        }),
      }),
    signIn: (input) =>
      call<{ user: User }>('/api/auth/sign-in/email', {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    signInWithSocial: async (provider, opts = {}) => {
      const callbackURL =
        opts.callbackURL ??
        (typeof location !== 'undefined' ? location.href : undefined);
      const r = await call<{ url: string }>('/api/auth/sign-in/social', {
        method: 'POST',
        body: JSON.stringify({ provider, callbackURL }),
      });
      if (!opts.noRedirect && typeof location !== 'undefined') {
        location.href = r.url;
      }
      return r;
    },
    signInWithMagicLink: (email, opts = {}) => {
      const callbackURL =
        opts.callbackURL ??
        (typeof location !== 'undefined' ? location.href : undefined);
      return call<{ status: boolean }>('/api/auth/sign-in/magic-link', {
        method: 'POST',
        body: JSON.stringify({ email, callbackURL }),
      });
    },
    signOut: async () => {
      await call<{ success: true }>('/api/auth/sign-out', { method: 'POST' });
    },
    requestPasswordReset: (input) =>
      call<{ status: boolean }>('/api/auth/request-password-reset', {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    resetPassword: (input) =>
      call<{ status: boolean }>('/api/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    sendVerificationEmail: (input) =>
      call<{ status: boolean }>('/api/auth/send-verification-email', {
        method: 'POST',
        body: JSON.stringify({
          ...input,
          callbackURL: input.callbackURL ?? browserDefault(),
        }),
      }),
    getMe: async () => (await me())?.user ?? null,
    getSession: async () => (await me())?.session ?? null,
  };
}

// Convenience: a default instance for projects with one deployment.
const auth = createAuth();
export const signUp = (input: SignUpInput) => auth.signUp(input);
export const signIn = (input: SignInInput) => auth.signIn(input);
export const signInWithSocial = (provider: SocialProvider, opts?: SignInWithSocialOptions) =>
  auth.signInWithSocial(provider, opts);
export const signInWithMagicLink = (email: string, opts?: SignInWithMagicLinkOptions) =>
  auth.signInWithMagicLink(email, opts);
export const signOut = () => auth.signOut();
export const requestPasswordReset = (input: RequestPasswordResetInput) =>
  auth.requestPasswordReset(input);
export const resetPassword = (input: ResetPasswordInput) => auth.resetPassword(input);
export const sendVerificationEmail = (input: SendVerificationEmailInput) =>
  auth.sendVerificationEmail(input);
export const getMe = () => auth.getMe();
export const getSession = () => auth.getSession();
