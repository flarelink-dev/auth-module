/// <reference types="@cloudflare/workers-types" />
// Provider-pluggable email sender for the project Worker.
//
// Two providers in v0.1.2 — Cloudflare Email Sending (native binding, no
// account beyond CF) and Resend (HTTP API, free tier 3K/mo). Same interface
// either way; the worker picks based on EMAIL_PROVIDER in flarelink_config.
//
// Future consumers (Files "upload complete," SQL editor "shared query") will
// import this same module. No standalone email Worker until a second module
// actually needs it — when that happens we extract into its own Worker
// without changing this file's interface.

import { EmailMessage } from 'cloudflare:email';

export type EmailPayload = {
  from: string;
  to: string;
  subject: string;
  html: string;
  text?: string;
};

export type EmailProvider = {
  name: 'cloudflare' | 'resend';
  send(msg: EmailPayload): Promise<void>;
};

export class EmailError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'EmailError';
    this.status = status;
  }
}

// Build a minimal RFC 822 message body. multipart/alternative when both
// text + html are present, otherwise just text/html. CF Email Sending takes
// raw RFC 822 — we build it here instead of pulling in a heavyweight MIME
// library.
function rfc822(msg: EmailPayload): string {
  const lines: string[] = [
    `From: ${msg.from}`,
    `To: ${msg.to}`,
    `Subject: ${msg.subject}`,
    'MIME-Version: 1.0',
  ];
  if (msg.text) {
    const boundary = `flarelink-${crypto.randomUUID()}`;
    lines.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    lines.push('');
    lines.push(`--${boundary}`);
    lines.push('Content-Type: text/plain; charset=utf-8');
    lines.push('');
    lines.push(msg.text);
    lines.push('');
    lines.push(`--${boundary}`);
    lines.push('Content-Type: text/html; charset=utf-8');
    lines.push('');
    lines.push(msg.html);
    lines.push('');
    lines.push(`--${boundary}--`);
  } else {
    lines.push('Content-Type: text/html; charset=utf-8');
    lines.push('');
    lines.push(msg.html);
  }
  return lines.join('\r\n');
}

export function cloudflareProvider(binding: SendEmail): EmailProvider {
  return {
    name: 'cloudflare',
    async send(msg) {
      const raw = rfc822(msg);
      const message = new EmailMessage(msg.from, msg.to, raw);
      try {
        await binding.send(message);
      } catch (err) {
        throw new EmailError(
          `Cloudflare Email send failed: ${(err as Error).message}. Verify that Email Sending is enabled on your CF account and your sender domain is configured with SPF/DKIM.`
        );
      }
    },
  };
}

export function resendProvider(apiKey: string): EmailProvider {
  return {
    name: 'resend',
    async send(msg) {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: msg.from,
          to: msg.to,
          subject: msg.subject,
          html: msg.html,
          text: msg.text,
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { message?: string; name?: string };
        throw new EmailError(
          `Resend send failed (${res.status}): ${body.message ?? body.name ?? 'unknown error'}`,
          res.status
        );
      }
    },
  };
}

export type EmailConfig = {
  provider: 'cloudflare' | 'resend';
  from: string;
  resendApiKey?: string;
};

// Factory: pick the right provider based on config + available bindings.
// Throws EmailError with an actionable message when config is incoherent
// (e.g., Resend selected but no API key, CF selected but binding missing).
export function buildEmailProvider(
  cfg: EmailConfig,
  cfEmailBinding: SendEmail | undefined
): EmailProvider {
  if (cfg.provider === 'resend') {
    if (!cfg.resendApiKey) {
      throw new EmailError('Resend selected but RESEND_API_KEY is not set in flarelink_config');
    }
    return resendProvider(cfg.resendApiKey);
  }
  if (cfg.provider === 'cloudflare') {
    if (!cfEmailBinding) {
      throw new EmailError(
        'Cloudflare Email selected but the EMAIL binding is missing on this Worker. Redeploy from the Flarelink dashboard so the send_email binding gets attached.'
      );
    }
    return cloudflareProvider(cfEmailBinding);
  }
  throw new EmailError(`Unknown email provider: ${cfg.provider}`);
}
