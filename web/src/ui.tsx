import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { CheckCircle2, File, FileImage, FileSpreadsheet, FileText, Presentation, X, XCircle } from 'lucide-react';
import type { Access } from './api';

// ------------------------------------------------------------------ toasts
type Toast = { id: number; kind: 'ok' | 'error'; text: string };
const ToastCtx = createContext<(text: string, kind?: 'ok' | 'error') => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: 'ok' | 'error' = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-50 flex flex-col items-center gap-2 px-4 sm:items-end sm:pr-6">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`pointer-events-auto flex max-w-md items-start gap-2 rounded-xl px-4 py-3 text-sm shadow-lg ring-1 ${
              t.kind === 'ok'
                ? 'bg-white text-slate-800 ring-brand-200 dark:bg-slate-900 dark:text-slate-100 dark:ring-brand-800'
                : 'bg-rose-50 text-rose-800 ring-rose-200 dark:bg-rose-950 dark:text-rose-100 dark:ring-rose-900'
            }`}
          >
            {t.kind === 'ok' ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-brand-600" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" />}
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** Wrap an async action: show its error as a toast instead of throwing. */
export function useAction() {
  const toast = useToast();
  return useCallback(
    (fn: () => Promise<unknown>) => async () => {
      try {
        await fn();
      } catch (e) {
        toast((e as Error).message, 'error');
      }
    },
    [toast],
  );
}

// ------------------------------------------------------------------- bits
const PALETTE = ['bg-teal-500', 'bg-amber-500', 'bg-indigo-500', 'bg-rose-500', 'bg-emerald-500', 'bg-sky-500', 'bg-fuchsia-500', 'bg-orange-500'];
export function Avatar({ name, size = 'md' }: { name: string; size?: 'sm' | 'md' | 'lg' }) {
  const initials = name
    .replace(/\(.*?\)/g, '')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join('');
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const cls = { sm: 'h-6 w-6 text-[10px]', md: 'h-8 w-8 text-xs', lg: 'h-11 w-11 text-sm' }[size];
  return <span className={`inline-flex shrink-0 items-center justify-center rounded-full font-semibold text-white ${PALETTE[h % PALETTE.length]} ${cls}`}>{initials || '?'}</span>;
}

export function AccessBadge({ access }: { access: Access | 'read' | 'edit' }) {
  const map = {
    owner: 'bg-brand-100 text-brand-800 dark:bg-brand-900/60 dark:text-brand-200',
    edit: 'bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200',
    read: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  } as const;
  const label = { owner: 'Owner', edit: 'Can edit', read: 'Can view' } as const;
  return <span className={`badge ${map[access]}`}>{label[access]}</span>;
}

export function OutcomeBadge({ outcome }: { outcome: string }) {
  const cls =
    outcome === 'denied'
      ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/50 dark:text-rose-200'
      : outcome === 'failure'
        ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200'
        : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-200';
  return <span className={`badge ${cls}`}>{outcome}</span>;
}

export function FileIcon({ name, mime, className = 'h-10 w-10' }: { name?: string; mime?: string; className?: string }) {
  const ext = (name ?? '').split('.').pop()?.toLowerCase() ?? '';
  const m = mime ?? '';
  if (m.startsWith('image/') || ['png', 'jpg', 'jpeg'].includes(ext)) return <Tile className={className} color="bg-sky-100 text-sky-600 dark:bg-sky-900/40 dark:text-sky-300"><FileImage className="h-1/2 w-1/2" /></Tile>;
  if (m === 'application/pdf' || ext === 'pdf') return <Tile className={className} color="bg-rose-100 text-rose-600 dark:bg-rose-900/40 dark:text-rose-300"><FileText className="h-1/2 w-1/2" /></Tile>;
  if (m.includes('spreadsheet') || ['xlsx', 'csv'].includes(ext)) return <Tile className={className} color="bg-emerald-100 text-emerald-600 dark:bg-emerald-900/40 dark:text-emerald-300"><FileSpreadsheet className="h-1/2 w-1/2" /></Tile>;
  if (m.includes('presentation') || ext === 'pptx') return <Tile className={className} color="bg-orange-100 text-orange-600 dark:bg-orange-900/40 dark:text-orange-300"><Presentation className="h-1/2 w-1/2" /></Tile>;
  if (m.includes('word') || ext === 'docx' || ext === 'txt') return <Tile className={className} color="bg-indigo-100 text-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-300"><FileText className="h-1/2 w-1/2" /></Tile>;
  return <Tile className={className} color="bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300"><File className="h-1/2 w-1/2" /></Tile>;
}
function Tile({ children, className, color }: { children: ReactNode; className: string; color: string }) {
  return <span className={`inline-flex shrink-0 items-center justify-center rounded-xl ${color} ${className}`}>{children}</span>;
}

export function Spinner({ className = 'h-5 w-5' }: { className?: string }) {
  return <span className={`inline-block animate-spin rounded-full border-2 border-brand-500 border-t-transparent ${className}`} aria-label="Loading" />;
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50 text-brand-600 dark:bg-brand-900/40 dark:text-brand-300">{icon}</div>
      <h3 className="text-base font-semibold">{title}</h3>
      {children && <div className="mt-1 max-w-sm text-sm text-slate-500 dark:text-slate-400">{children}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex items-end justify-center bg-slate-950/50 p-0 backdrop-blur-sm sm:items-center sm:p-4" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`card max-h-[92vh] w-full overflow-y-auto rounded-b-none p-5 sm:rounded-2xl ${wide ? 'sm:max-w-3xl' : 'sm:max-w-lg'}`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button className="btn-ghost p-1.5" onClick={onClose} aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}
