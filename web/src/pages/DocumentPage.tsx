import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Ban,
  Clock,
  Download,
  Eye,
  FileClock,
  History,
  Pencil,
  Share2,
  ShieldCheck,
  Sparkles,
  Trash2,
  UploadCloud,
  UserPlus,
  X,
} from 'lucide-react';
import { api, ApiError, fmtBytes, fmtDate, relTime, uploadWithProgress, type AuditEvent, type DocDetail, type Grant, type Suggestion, type Version } from '../api';
import { AccessBadge, Avatar, Empty, FileIcon, Modal, OutcomeBadge, Spinner, useAction, useToast } from '../ui';
import { CategoryBadge } from './Documents';
import Preview, { canPreview, NoPreview } from './Preview';
import { DropZone, useCategories } from './UploadDialog';

type Tab = 'preview' | 'sharing' | 'versions' | 'activity' | 'details';

export default function DocumentPage() {
  const { id = '' } = useParams();
  const [doc, setDoc] = useState<DocDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('preview');
  const [versionOpen, setVersionOpen] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();
  const act = useAction();

  const load = useCallback(() => {
    api<{ document: DocDetail }>('GET', `/api/documents/${id}`)
      .then((r) => setDoc(r.document))
      .catch((e: ApiError) => setError(e.status === 404 ? 'This document does not exist, or you do not have access to it.' : e.message));
  }, [id]);
  useEffect(load, [load]);

  if (error)
    return (
      <div className="card">
        <Empty icon={<Ban className="h-7 w-7" />} title="Not available">
          {error}
          <div className="mt-4">
            <Link className="btn-outline" to="/">Back to documents</Link>
          </div>
        </Empty>
      </div>
    );
  if (!doc)
    return (
      <div className="flex justify-center py-20">
        <Spinner className="h-8 w-8" />
      </div>
    );

  const can = (a: string) => doc.allowedActions.includes(a);
  const v = doc.currentVersion;
  const tabs: { key: Tab; label: string; icon: React.ReactNode; show: boolean }[] = [
    { key: 'preview', label: 'Preview', icon: <Eye className="h-4 w-4" />, show: true },
    { key: 'sharing', label: 'Sharing', icon: <Share2 className="h-4 w-4" />, show: can('share') },
    { key: 'versions', label: 'Versions', icon: <History className="h-4 w-4" />, show: can('list_versions') },
    { key: 'activity', label: 'Activity', icon: <FileClock className="h-4 w-4" />, show: can('view_activity') },
    { key: 'details', label: 'Details', icon: <Pencil className="h-4 w-4" />, show: true },
  ];

  return (
    <>
      <button className="btn-ghost -ml-3 mb-4 px-3" onClick={() => navigate(-1)}>
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      <div className="card mb-6 p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
          <FileIcon name={v?.filename} mime={v?.mimeType} className="h-14 w-14" />
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-bold leading-snug sm:text-2xl">{doc.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-500">
              <CategoryBadge c={doc.category} />
              <AccessBadge access={doc.access} />
              <span className="flex items-center gap-1.5">
                <Avatar name={doc.owner.name} size="sm" /> {doc.owner.name}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" /> {relTime(doc.updatedAt)}
              </span>
            </div>
            {v && (
              <div className="mt-2 text-xs text-slate-500">
                {v.filename} · v{v.versionNo} · {fmtBytes(v.sizeBytes)}
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {v && (
              <a className="btn-primary" href={`/api/documents/${doc.id}/download`}>
                <Download className="h-4 w-4" /> Download
              </a>
            )}
            {can('upload_version') && (
              <button className="btn-outline" onClick={() => setVersionOpen(true)}>
                <UploadCloud className="h-4 w-4" /> New version
              </button>
            )}
            {can('delete') && (
              <button
                className="btn-outline text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/40"
                onClick={act(async () => {
                  if (!confirm('Move this document to the trash? Everyone you shared it with loses access immediately.')) return;
                  await api('DELETE', `/api/documents/${doc.id}`);
                  toast('Moved to trash. Shared access stopped immediately.');
                  navigate('/mine');
                })}
              >
                <Trash2 className="h-4 w-4" />
                <span className="sm:hidden lg:inline">Delete</span>
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800">
        {tabs
          .filter((t) => t.show)
          .map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-4 py-2.5 text-sm font-medium transition ${
                tab === t.key ? 'border-brand-600 text-brand-700 dark:text-brand-300' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
      </div>

      <div className="card p-4 sm:p-5">
        {tab === 'preview' &&
          (v && canPreview(v.mimeType) ? <Preview docId={doc.id} mime={v.mimeType} filename={v.filename} /> : <NoPreview href={`/api/documents/${doc.id}/download`} />)}
        {tab === 'sharing' && <Sharing doc={doc} />}
        {tab === 'versions' && <Versions doc={doc} />}
        {tab === 'activity' && <Activity doc={doc} />}
        {tab === 'details' && <Details doc={doc} onSaved={load} />}
      </div>

      <NewVersionDialog open={versionOpen} docId={doc.id} onClose={() => setVersionOpen(false)} onDone={load} />
    </>
  );
}

// ----------------------------------------------------------------- sharing
function Sharing({ doc }: { doc: DocDetail }) {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [query, setQuery] = useState('');
  const [matches, setMatches] = useState<{ id: string; name: string; email: string; role: string }[]>([]);
  const [picked, setPicked] = useState<{ id: string; name: string; email: string } | null>(null);
  const [permission, setPermission] = useState<'read' | 'edit'>('read');
  const [expires, setExpires] = useState('');
  const [sugg, setSugg] = useState<{ id: string; source: string; note: string | null; items: Suggestion[] } | null>(null);
  const [suggBusy, setSuggBusy] = useState(false);
  const toast = useToast();
  const act = useAction();

  const load = useCallback(() => {
    api<{ grants: Grant[] }>('GET', `/api/documents/${doc.id}/grants`).then((r) => setGrants(r.grants));
  }, [doc.id]);
  useEffect(load, [load]);

  useEffect(() => {
    if (picked || query.trim().length < 2) return setMatches([]);
    const t = setTimeout(() => {
      api<{ users: typeof matches }>('GET', `/api/users/directory?q=${encodeURIComponent(query.trim())}`).then((r) => setMatches(r.users)).catch(() => setMatches([]));
    }, 200);
    return () => clearTimeout(t);
  }, [query, picked]);

  const grant = async (body: Record<string, unknown>, who: string) => {
    await api('POST', `/api/documents/${doc.id}/grants`, body);
    toast(`${who} can now ${body.permission === 'edit' ? 'edit' : 'view'} this document.`);
    load();
  };

  return (
    <div className="space-y-8">
      <section>
        <h3 className="mb-1 font-semibold">People with access</h3>
        <p className="mb-4 text-sm text-slate-500">Only the people listed here can open this document. Changes take effect on their very next click.</p>
        <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          <li className="flex items-center gap-3 p-3">
            <Avatar name={doc.owner.name} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-semibold">{doc.owner.name} <span className="font-normal text-slate-400">(you)</span></div>
              <div className="truncate text-xs text-slate-500">{doc.owner.email}</div>
            </div>
            <AccessBadge access="owner" />
          </li>
          {grants?.map((g) => (
            <li key={g.id} className="flex flex-wrap items-center gap-3 p-3">
              <Avatar name={g.user.name} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-semibold">
                  {g.user.name} {!g.user.active && <span className="badge ml-1 bg-slate-200 text-slate-600 dark:bg-slate-800">deactivated</span>}
                </div>
                <div className="truncate text-xs text-slate-500">
                  {g.user.email} · {g.expiresAt ? (g.expired ? <span className="text-rose-500">expired {fmtDate(g.expiresAt)}</span> : <>until {fmtDate(g.expiresAt)}</>) : 'no expiry'}
                </div>
              </div>
              <select
                className="input w-auto py-1"
                value={g.permission}
                aria-label={`Access for ${g.user.name}`}
                onChange={(e) => act(() => grant({ userId: g.user.id, permission: e.target.value, expiresAt: g.expiresAt && !g.expired ? g.expiresAt : undefined }, g.user.name))()}
              >
                <option value="read">Can view</option>
                <option value="edit">Can edit</option>
              </select>
              <button
                className="btn-ghost p-2 text-rose-600"
                aria-label={`Remove ${g.user.name}`}
                title="Remove access"
                onClick={act(async () => {
                  await api('DELETE', `/api/documents/${doc.id}/grants/${g.id}`);
                  toast(`${g.user.name} lost access. It stopped working immediately.`);
                  load();
                })}
              >
                <X className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3 className="mb-3 flex items-center gap-2 font-semibold"><UserPlus className="h-4 w-4" /> Share with someone</h3>
        <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto_auto]">
          <div className="relative">
            {picked ? (
              <div className="input flex items-center gap-2">
                <Avatar name={picked.name} size="sm" />
                <span className="truncate">{picked.name}</span>
                <span className="truncate text-xs text-slate-400">{picked.email}</span>
                <button className="ml-auto" onClick={() => setPicked(null)} aria-label="Clear"><X className="h-4 w-4" /></button>
              </div>
            ) : (
              <input className="input" placeholder="Name or email" value={query} onChange={(e) => setQuery(e.target.value)} />
            )}
            {matches.length > 0 && !picked && (
              <ul className="absolute z-10 mt-1 w-full overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-900">
                {matches.map((m) => (
                  <li key={m.id}>
                    <button
                      className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800"
                      onClick={() => {
                        setPicked(m);
                        setMatches([]);
                        setQuery('');
                      }}
                    >
                      <Avatar name={m.name} size="sm" />
                      <span className="truncate font-medium">{m.name}</span>
                      <span className="truncate text-xs text-slate-400">{m.email}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <select className="input" value={permission} onChange={(e) => setPermission(e.target.value as 'read' | 'edit')}>
            <option value="read">Can view</option>
            <option value="edit">Can edit</option>
          </select>
          <input type="date" className="input" value={expires} onChange={(e) => setExpires(e.target.value)} title="Access expires (optional)" aria-label="Expires" />
          <button
            className="btn-primary"
            disabled={!picked && !query.includes('@')}
            onClick={act(async () => {
              const target = picked ? { userId: picked.id } : { email: query.trim() };
              await grant({ ...target, permission, expiresAt: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined }, picked?.name ?? query.trim());
              setPicked(null);
              setQuery('');
              setExpires('');
            })}
          >
            Share
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500"><strong>Can view</strong>: open and download the current version. <strong>Can edit</strong>: also change details and upload new versions. Only you can share or delete.</p>
      </section>

      <section className="rounded-2xl bg-gradient-to-br from-brand-50 to-amber-50 p-4 ring-1 ring-brand-100 dark:from-brand-950/40 dark:to-amber-950/20 dark:ring-brand-900">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="flex items-center gap-2 font-semibold"><Sparkles className="h-4 w-4 text-amber-500" /> Suggested people</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400">Based on who you share similar team documents with. Nothing is shared until you confirm, and both are recorded.</p>
          </div>
          <button
            className="btn-outline"
            disabled={suggBusy}
            onClick={act(async () => {
              setSuggBusy(true);
              try {
                const r = await api<{ suggestionId: string; source: string; note: string | null; suggestions: Suggestion[] }>('POST', `/api/documents/${doc.id}/suggestions`);
                setSugg({ id: r.suggestionId, source: r.source, note: r.note, items: r.suggestions });
              } finally {
                setSuggBusy(false);
              }
            })}
          >
            {suggBusy ? <Spinner className="h-4 w-4" /> : <Sparkles className="h-4 w-4" />} Suggest
          </button>
        </div>
        {sugg && (
          <div className="mt-4 space-y-2">
            {sugg.items.length === 0 && <p className="text-sm text-slate-500">No suggestions for this document.</p>}
            {sugg.items.map((s) => (
              <div key={s.userId} className="flex flex-wrap items-center gap-3 rounded-xl bg-white/80 p-3 dark:bg-slate-900/70">
                <Avatar name={s.name} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{s.name} <AccessBadge access={s.permission} /></div>
                  <div className="text-xs text-slate-500">{s.reason}</div>
                </div>
                <button className="btn-primary px-3 py-1.5" onClick={act(async () => {
                  await grant({ userId: s.userId, permission: s.permission, suggestionId: sugg.id }, s.name);
                  setSugg({ ...sugg, items: sugg.items.filter((x) => x.userId !== s.userId) });
                })}>Confirm</button>
                <button className="btn-ghost px-3 py-1.5" onClick={act(async () => {
                  await api('POST', `/api/documents/${doc.id}/suggestions/${sugg.id}/dismiss`, { userId: s.userId });
                  setSugg({ ...sugg, items: sugg.items.filter((x) => x.userId !== s.userId) });
                })}>Dismiss</button>
              </div>
            ))}
            <p className="text-[11px] text-slate-400">Source: {sugg.source}{sugg.note ? ` · ${sugg.note}` : ''}</p>
          </div>
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- versions
function Versions({ doc }: { doc: DocDetail }) {
  const [versions, setVersions] = useState<Version[] | null>(null);
  useEffect(() => {
    api<{ versions: Version[] }>('GET', `/api/documents/${doc.id}/versions`).then((r) => setVersions(r.versions));
  }, [doc.id, doc.updatedAt]);
  if (!versions) return <Spinner />;
  return (
    <ol className="relative space-y-4 border-l border-slate-200 pl-6 dark:border-slate-800">
      {versions.map((v) => (
        <li key={v.id} className="relative">
          <span className={`absolute -left-[31px] top-1 h-3.5 w-3.5 rounded-full ring-4 ring-white dark:ring-slate-900 ${v.current ? 'bg-brand-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-sm font-semibold">
                Version {v.versionNo} {v.current && <span className="badge ml-1 bg-brand-100 text-brand-800 dark:bg-brand-900/50 dark:text-brand-200">current</span>}
              </div>
              <div className="text-xs text-slate-500">{v.filename} · {fmtBytes(v.sizeBytes)} · {v.uploadedBy} · {fmtDate(v.createdAt)}</div>
              <div className="mt-0.5 font-mono text-[10px] text-slate-400">sha256 {v.sha256.slice(0, 16)}…</div>
            </div>
            <a className="btn-outline px-3 py-1.5" href={`/api/documents/${doc.id}/versions/${v.id}/download`}><Download className="h-4 w-4" /> Download</a>
          </div>
        </li>
      ))}
    </ol>
  );
}

// ---------------------------------------------------------------- activity
const ACTION_LABEL: Record<string, string> = {
  'document.view': 'opened the details',
  'document.preview': 'previewed',
  'document.download': 'downloaded',
  'document.upload': 'uploaded',
  'document.upload_version': 'uploaded a new version',
  'document.update_metadata': 'edited the details',
  'document.delete': 'moved to trash',
  'document.restore': 'restored',
  'grant.create': 'shared',
  'grant.update': 'changed access',
  'grant.revoke': 'removed access',
  'ai.suggestion.generated': 'asked for suggestions',
  'ai.suggestion.accepted': 'accepted a suggestion',
  'ai.suggestion.dismissed': 'dismissed a suggestion',
};

function Activity({ doc }: { doc: DocDetail }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [onlyDenied, setOnlyDenied] = useState(false);
  useEffect(() => {
    api<{ events: AuditEvent[] }>('GET', `/api/documents/${doc.id}/activity`).then((r) => setEvents(r.events));
  }, [doc.id]);
  if (!events) return <Spinner />;
  const shown = onlyDenied ? events.filter((e) => e.outcome !== 'success') : events;
  const denied = events.filter((e) => e.outcome === 'denied').length;
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-slate-500">Every view, download, change and permission change, including attempts that were refused.</p>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={onlyDenied} onChange={(e) => setOnlyDenied(e.target.checked)} className="accent-brand-600" />
          Only refused ({denied})
        </label>
      </div>
      <ul className="space-y-2">
        {shown.map((e) => (
          <li key={e.seq} className={`flex items-start gap-3 rounded-xl p-3 ${e.outcome === 'denied' ? 'bg-rose-50 dark:bg-rose-950/30' : 'bg-slate-50 dark:bg-slate-800/40'}`}>
            {e.outcome === 'denied' ? <Ban className="mt-0.5 h-4 w-4 text-rose-500" /> : <ShieldCheck className="mt-0.5 h-4 w-4 text-brand-500" />}
            <div className="min-w-0 flex-1 text-sm">
              <span className="font-semibold">{e.actor_email ?? 'someone'}</span>{' '}
              {e.outcome === 'denied' ? <span className="text-rose-700 dark:text-rose-300">was refused ({e.action.replace('document.', '')})</span> : ACTION_LABEL[e.action] ?? e.action}
              <div className="text-xs text-slate-500">{fmtDate(e.ts)} · #{e.seq}</div>
            </div>
            <OutcomeBadge outcome={e.outcome} />
          </li>
        ))}
      </ul>
    </div>
  );
}

// ----------------------------------------------------------------- details
function Details({ doc, onSaved }: { doc: DocDetail; onSaved: () => void }) {
  const cats = useCategories();
  const editable = doc.allowedActions.includes('update_metadata');
  const [title, setTitle] = useState(doc.title);
  const [category, setCategory] = useState(doc.category);
  const [description, setDescription] = useState(doc.description);
  const toast = useToast();
  const act = useAction();
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-4">
        <div>
          <label className="label">Title</label>
          <input className="input" disabled={!editable} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </div>
        <div>
          <label className="label">Category</label>
          <select className="input" disabled={!editable} value={category} onChange={(e) => setCategory(e.target.value)}>
            {cats.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label">Description</label>
          <textarea className="input" rows={4} disabled={!editable} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} />
        </div>
        {editable && (
          <button className="btn-primary" onClick={act(async () => {
            await api('PATCH', `/api/documents/${doc.id}`, { title, category, description });
            toast('Saved.');
            onSaved();
          })}>Save changes</button>
        )}
      </div>
      <dl className="space-y-3 text-sm">
        {[
          ['Owner', `${doc.owner.name} <${doc.owner.email}>`],
          ['Created', fmtDate(doc.createdAt)],
          ['Last updated', fmtDate(doc.updatedAt)],
          ['Current file', doc.currentVersion ? `${doc.currentVersion.filename} (${fmtBytes(doc.currentVersion.sizeBytes)})` : '—'],
          ['SHA-256', doc.currentVersion?.sha256 ?? '—'],
          ['Your access', doc.access],
        ].map(([k, v]) => (
          <div key={k}>
            <dt className="text-xs text-slate-500">{k}</dt>
            <dd className={`break-all ${k === 'SHA-256' ? 'font-mono text-xs' : ''}`}>{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function NewVersionDialog({ open, docId, onClose, onDone }: { open: boolean; docId: string; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  return (
    <Modal open={open} onClose={onClose} title="Upload a new version">
      <div className="space-y-4">
        <DropZone file={file} onFile={setFile} />
        {progress !== null && (
          <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
            <div className="h-full bg-brand-500 transition-all" style={{ width: `${progress}%` }} />
          </div>
        )}
        {error && <p className="text-sm text-rose-600">{error}</p>}
        <div className="flex justify-end gap-2">
          <button className="btn-outline" onClick={onClose}>Cancel</button>
          <button
            className="btn-primary"
            disabled={!file || progress !== null}
            onClick={async () => {
              const form = new FormData();
              form.append('file', file!);
              setProgress(0);
              setError(null);
              try {
                await uploadWithProgress(`/api/documents/${docId}/versions`, form, setProgress);
                toast('New version uploaded.');
                setFile(null);
                onClose();
                onDone();
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setProgress(null);
              }
            }}
          >
            Upload
          </button>
        </div>
      </div>
    </Modal>
  );
}
