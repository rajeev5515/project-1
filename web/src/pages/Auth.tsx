import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ClipboardEvent } from 'react';
import { ArrowLeft, FileLock2, History, KeyRound, Mail, ShieldCheck, UserPlus, Users } from 'lucide-react';
import { api, ApiError, type User } from '../api';
import { useSession } from '../session';
import { Spinner } from '../ui';

const DEMO = [
  { email: 'olivia@trustvault.demo', name: 'Olivia', role: 'Owner · HR' },
  { email: 'oscar@trustvault.demo', name: 'Oscar', role: 'Owner · Legal' },
  { email: 'vera@trustvault.demo', name: 'Vera', role: 'Viewer' },
  { email: 'victor@trustvault.demo', name: 'Victor', role: 'Viewer (edits handbook)' },
  { email: 'pat@partner.example', name: 'Pat', role: 'External partner' },
  { email: 'admin@trustvault.demo', name: 'Ada', role: 'Administrator' },
];

type Step = { kind: 'email' } | { kind: 'code'; challengeId: string; email: string; demoCode?: string; message: string };

export default function AuthPage() {
  const { setUser } = useSession();
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [step, setStep] = useState<Step>({ kind: 'email' });
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailEnabled, setEmailEnabled] = useState(true);

  useEffect(() => {
    api<{ emailEnabled: boolean }>('GET', '/api/auth/config').then((c) => setEmailEnabled(c.emailEnabled)).catch(() => {});
  }, []);

  async function requestCode(targetEmail: string, e?: FormEvent) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r =
        mode === 'signup'
          ? await api<{ challengeId: string; message: string }>('POST', '/api/auth/signup', { email: targetEmail, name })
          : await api<{ challengeId: string; message: string; demoCode?: string }>('POST', '/api/auth/start', { email: targetEmail });
      setStep({ kind: 'code', challengeId: r.challengeId, email: targetEmail, demoCode: (r as { demoCode?: string }).demoCode, message: r.message });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verify(code: string) {
    if (step.kind !== 'code') return;
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ user: User }>('POST', '/api/auth/verify', { challengeId: step.challengeId, code });
      setUser(r.user);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? 'That code is wrong or has expired.' : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-full lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden overflow-hidden bg-gradient-to-br from-brand-700 via-brand-800 to-ink-950 p-12 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="pointer-events-none absolute -right-24 -top-24 h-96 w-96 rounded-full bg-brand-400/20 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-32 -left-16 h-96 w-96 rounded-full bg-amber-400/10 blur-3xl" />
        <Logo light />
        <div className="relative space-y-8">
          <h1 className="text-4xl font-bold leading-tight">
            Share confidential documents.
            <br />
            <span className="text-brand-200">Prove who opened them.</span>
          </h1>
          <ul className="space-y-4 text-brand-50/90">
            <Feature icon={<FileLock2 />} title="Only the people you name">Per-document access, revocable instantly.</Feature>
            <Feature icon={<History />} title="Tamper-evident audit trail">Every view, download and refusal, hash-chained.</Feature>
            <Feature icon={<KeyRound />} title="No passwords to leak">Sign in with a one-time code sent to your email.</Feature>
          </ul>
        </div>
        <p className="relative text-xs text-brand-100/70">Files are encrypted at rest with a unique key per version.</p>
      </div>

      {/* Form */}
      <div className="flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-md">
          <div className="mb-8 lg:hidden">
            <Logo />
          </div>

          {step.kind === 'email' ? (
            <>
              <div className="mb-6 grid grid-cols-2 rounded-xl bg-slate-100 p-1 dark:bg-slate-800/60">
                {(['signin', 'signup'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => {
                      setMode(m);
                      setError(null);
                    }}
                    className={`rounded-lg py-2 text-sm font-semibold transition ${mode === m ? 'bg-white text-slate-900 shadow dark:bg-slate-900 dark:text-white' : 'text-slate-500'}`}
                  >
                    {m === 'signin' ? 'Sign in' : 'Create account'}
                  </button>
                ))}
              </div>
              <h2 className="text-2xl font-bold">{mode === 'signin' ? 'Welcome back' : 'Create your vault'}</h2>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                {mode === 'signin' ? 'We will email you a 6-digit code.' : 'Upload, share and track your documents. We will email you a code to confirm it is you.'}
              </p>
              {!emailEnabled && (
                <p className="mt-4 rounded-xl bg-amber-50 p-3 text-sm text-amber-800 ring-1 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-200 dark:ring-amber-900">
                  Email delivery is not configured on this server yet. You can still explore with a demo account below.
                </p>
              )}
              <form className="mt-6 space-y-4" onSubmit={(e) => requestCode(email.trim(), e)}>
                {mode === 'signup' && (
                  <div>
                    <label className="label" htmlFor="name">Your name</label>
                    <input id="name" className="input" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} autoComplete="name" />
                  </div>
                )}
                <div>
                  <label className="label" htmlFor="email">Work email</label>
                  <div className="relative">
                    <Mail className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                    <input id="email" type="email" className="input pl-9" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" placeholder="you@company.com" />
                  </div>
                </div>
                {error && <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>}
                <button className="btn-primary w-full py-2.5" disabled={busy}>
                  {busy ? <Spinner className="h-4 w-4 border-white border-t-transparent" /> : mode === 'signin' ? <ShieldCheck className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
                  {mode === 'signin' ? 'Email me a code' : 'Create account'}
                </button>
              </form>

              {mode === 'signin' && (
                <div className="mt-10">
                  <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                    <Users className="h-3.5 w-3.5" /> Try a demo account
                  </div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                    {DEMO.map((d) => (
                      <button
                        key={d.email}
                        disabled={busy}
                        onClick={() => {
                          setEmail(d.email);
                          void requestCode(d.email);
                        }}
                        className="rounded-xl border border-slate-200 p-2.5 text-left transition hover:border-brand-400 hover:bg-brand-50/50 dark:border-slate-800 dark:hover:border-brand-700 dark:hover:bg-brand-900/20"
                      >
                        <div className="text-sm font-semibold">{d.name}</div>
                        <div className="truncate text-[11px] text-slate-500">{d.role}</div>
                      </button>
                    ))}
                  </div>
                  <p className="mt-2 text-xs text-slate-400">Demo accounts cannot receive email, so their code is shown on screen. They can never see real accounts.</p>
                </div>
              )}
            </>
          ) : (
            <CodeStep
              email={step.email}
              message={step.message}
              demoCode={step.demoCode}
              busy={busy}
              error={error}
              onBack={() => {
                setStep({ kind: 'email' });
                setError(null);
              }}
              onResend={() => requestCode(step.email)}
              onSubmit={verify}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function CodeStep(props: { email: string; message: string; demoCode?: string; busy: boolean; error: string | null; onBack: () => void; onResend: () => void; onSubmit: (code: string) => void }) {
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''));
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const [cooldown, setCooldown] = useState(30);

  useEffect(() => {
    refs.current[0]?.focus();
  }, []);
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const setAll = (code: string) => {
    const d = code.replace(/\D/g, '').slice(0, 6).split('');
    const next = Array(6).fill('').map((_, i) => d[i] ?? '');
    setDigits(next);
    if (d.length === 6) props.onSubmit(d.join(''));
    else refs.current[Math.min(d.length, 5)]?.focus();
  };
  const onChange = (i: number, v: string) => {
    if (v.length > 1) return setAll(v);
    const next = [...digits];
    next[i] = v.replace(/\D/g, '');
    setDigits(next);
    if (next[i] && i < 5) refs.current[i + 1]?.focus();
    if (next.every((x) => x)) props.onSubmit(next.join(''));
  };
  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) refs.current[i - 1]?.focus();
  };
  const onPaste = (e: ClipboardEvent) => {
    e.preventDefault();
    setAll(e.clipboardData.getData('text'));
  };

  return (
    <div>
      <button className="btn-ghost -ml-3 mb-6 px-3" onClick={props.onBack}>
        <ArrowLeft className="h-4 w-4" /> Back
      </button>
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-100 text-brand-700 dark:bg-brand-900/50 dark:text-brand-300">
        <Mail className="h-6 w-6" />
      </div>
      <h2 className="text-2xl font-bold">Check your email</h2>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
        {props.demoCode ? props.message : <>If <strong className="text-slate-700 dark:text-slate-200">{props.email}</strong> can sign in, a 6-digit code is on its way. It expires in 10 minutes.</>}
      </p>
      {props.demoCode && (
        <div className="mt-4 rounded-xl border border-dashed border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-800 dark:bg-amber-950/30">
          Demo code: <button className="font-mono text-lg font-bold tracking-widest text-amber-800 underline decoration-dotted dark:text-amber-200" onClick={() => setAll(props.demoCode!)}>{props.demoCode}</button>
          <span className="ml-2 text-xs text-amber-700/80 dark:text-amber-300/70">tap to fill</span>
        </div>
      )}
      <div className="mt-6 flex justify-between gap-2" onPaste={onPaste}>
        {digits.map((d, i) => (
          <input
            key={i}
            ref={(el) => {
              refs.current[i] = el;
            }}
            value={d}
            inputMode="numeric"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            maxLength={6}
            aria-label={`Digit ${i + 1}`}
            onChange={(e) => onChange(i, e.target.value)}
            onKeyDown={(e) => onKey(i, e)}
            className="h-14 w-full rounded-xl border border-slate-300 bg-white text-center font-mono text-2xl font-semibold focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/30 dark:border-slate-700 dark:bg-slate-950"
          />
        ))}
      </div>
      {props.error && <p className="mt-3 text-sm text-rose-600 dark:text-rose-400">{props.error}</p>}
      <button className="btn-primary mt-6 w-full py-2.5" disabled={props.busy || digits.some((x) => !x)} onClick={() => props.onSubmit(digits.join(''))}>
        {props.busy && <Spinner className="h-4 w-4 border-white border-t-transparent" />} Verify and continue
      </button>
      <p className="mt-4 text-center text-sm text-slate-500">
        Didn't get it?{' '}
        <button
          className="font-semibold text-brand-700 disabled:text-slate-400 dark:text-brand-300"
          disabled={cooldown > 0}
          onClick={() => {
            setCooldown(30);
            setDigits(Array(6).fill(''));
            props.onResend();
          }}
        >
          {cooldown > 0 ? `Resend in ${cooldown}s` : 'Send a new code'}
        </button>
      </p>
    </div>
  );
}

function Feature({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 [&>svg]:h-5 [&>svg]:w-5">{icon}</span>
      <div>
        <div className="font-semibold text-white">{title}</div>
        <div className="text-sm">{children}</div>
      </div>
    </li>
  );
}

export function Logo({ light }: { light?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-600 text-white shadow-lg shadow-brand-600/30">
        <ShieldCheck className="h-5 w-5" />
      </span>
      <span className={`text-lg font-bold tracking-tight ${light ? 'text-white' : ''}`}>TrustVault</span>
    </div>
  );
}
