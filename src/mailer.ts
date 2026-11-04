/**
 * Outbound email. Only one kind of email is sent: a sign-in code.
 *
 * Production uses Resend (https://resend.com) over HTTPS. Development without
 * a key prints the code to the server log; tests inject a capturing mailer.
 */
export interface Mail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface Mailer {
  /** True if real delivery is possible. */
  readonly configured: boolean;
  send(mail: Mail): Promise<void>;
}

export class ResendMailer implements Mailer {
  readonly configured = true;
  private readonly apiKey: string;
  private readonly from: string;
  constructor(apiKey: string, from: string) {
    this.apiKey = apiKey;
    this.from = from;
  }
  async send(mail: Mail): Promise<void> {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: this.from, to: [mail.to], subject: mail.subject, text: mail.text, html: mail.html }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      // Resend's error body says what is wrong (e.g. unverified domain); it never contains the code.
      throw new Error(`Resend responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
  }
}

/** Development only: writes the code to stdout. Never used when NODE_ENV=production. */
export class LogMailer implements Mailer {
  readonly configured = true;
  async send(mail: Mail): Promise<void> {
    console.log(JSON.stringify({ type: 'dev_mail', to: mail.to, subject: mail.subject, text: mail.text }));
  }
}

/** Production without RESEND_API_KEY: refuses, so real users get a clear error instead of silence. */
export class UnconfiguredMailer implements Mailer {
  readonly configured = false;
  async send(): Promise<void> {
    throw new Error('email delivery is not configured (set RESEND_API_KEY and TV_EMAIL_FROM)');
  }
}

/** Test mailer: keeps every message so tests can read the code like a user reading their inbox. */
export class MemoryMailer implements Mailer {
  readonly configured = true;
  readonly sent: Mail[] = [];
  async send(mail: Mail): Promise<void> {
    this.sent.push(mail);
  }
  lastCodeFor(email: string): string | null {
    for (let i = this.sent.length - 1; i >= 0; i--) {
      const m = this.sent[i]!;
      if (m.to.toLowerCase() === email.toLowerCase()) return /\b(\d{6})\b/.exec(m.text)?.[1] ?? null;
    }
    return null;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export function signInCodeMail(to: string, code: string, purpose: 'login' | 'signup', appName = 'TrustVault'): Mail {
  const action = purpose === 'signup' ? 'finish creating your account' : 'sign in';
  const text =
    `Your ${appName} code is ${code}\n\n` +
    `Enter it to ${action}. It expires in 10 minutes and works once.\n\n` +
    `If you did not ask for this, ignore this email. Nobody can sign in without the code.`;
  const html = `<div style="font-family:system-ui,sans-serif;max-width:460px;margin:auto;padding:24px;color:#0f172a">
  <h2 style="margin:0 0 8px;color:#0d9488">${escapeHtml(appName)}</h2>
  <p>Your code to ${escapeHtml(action)}:</p>
  <p style="font-size:32px;letter-spacing:8px;font-weight:700;margin:16px 0">${escapeHtml(code)}</p>
  <p style="color:#475569;font-size:14px">It expires in 10 minutes and works once. If you did not ask for this, ignore this email.</p>
</div>`;
  return { to, subject: `${code} is your ${appName} code`, text, html };
}
