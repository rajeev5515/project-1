import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { CalendarDays, FileSearch, Filter, Inbox, LayoutGrid, List, Search, Upload } from 'lucide-react';
import { api, relTime, type DocSummary } from '../api';
import { useSession } from '../session';
import { AccessBadge, Avatar, Empty, FileIcon, PageHeader, Spinner } from '../ui';
import { useCategories } from './UploadDialog';

const CAT_COLORS: Record<string, string> = {
  HR: 'bg-pink-100 text-pink-700 dark:bg-pink-900/40 dark:text-pink-200',
  Legal: 'bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-200',
  Finance: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-200',
  Engineering: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-200',
  Audit: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200',
  Contracts: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-200',
  Other: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
};
export const CategoryBadge = ({ c }: { c: string }) => <span className={`badge ${CAT_COLORS[c] ?? CAT_COLORS.Other}`}>{c}</span>;

export default function Documents({ scope }: { scope: 'all' | 'mine' | 'shared' }) {
  const { user } = useSession();
  const cats = useCategories();
  const [q, setQ] = useState('');
  const [owner, setOwner] = useState('');
  const [category, setCategory] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [view, setView] = useState<'grid' | 'list'>('grid');
  const [docs, setDocs] = useState<DocSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const params = useMemo(() => {
    const p = new URLSearchParams({ scope });
    if (q.trim()) p.set('q', q.trim());
    if (owner.trim()) p.set('owner', owner.trim());
    if (category) p.set('category', category);
    if (from) p.set('from', from);
    if (to) p.set('to', to);
    return p.toString();
  }, [scope, q, owner, category, from, to]);

  useEffect(() => {
    const t = setTimeout(() => {
      api<{ documents: DocSummary[] }>('GET', `/api/documents?${params}`)
        .then((r) => {
          setDocs(r.documents);
          setError(null);
        })
        .catch((e) => setError(e.message));
    }, 200);
    return () => clearTimeout(t);
  }, [params]);

  const title = { all: 'All documents', mine: 'My documents', shared: 'Shared with me' }[scope];
  const subtitle = {
    all: 'Everything you own or that someone shared with you.',
    mine: 'Documents you uploaded. Only you decide who sees them.',
    shared: 'Documents other people gave you access to.',
  }[scope];
  const filtersOn = [owner, category, from, to].filter(Boolean).length;

  return (
    <>
      <PageHeader
        title={title}
        subtitle={subtitle}
        actions={
          <div className="flex rounded-xl border border-slate-200 p-0.5 dark:border-slate-800">
            <button className={`rounded-lg p-1.5 ${view === 'grid' ? 'bg-slate-100 dark:bg-slate-800' : ''}`} onClick={() => setView('grid')} aria-label="Grid view">
              <LayoutGrid className="h-4 w-4" />
            </button>
            <button className={`rounded-lg p-1.5 ${view === 'list' ? 'bg-slate-100 dark:bg-slate-800' : ''}`} onClick={() => setView('list')} aria-label="List view">
              <List className="h-4 w-4" />
            </button>
          </div>
        }
      />

      <div className="card mb-6 p-3">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input className="input pl-9" placeholder="Search by title or description" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <button className={`btn-outline ${filtersOn ? 'border-brand-400 text-brand-700 dark:text-brand-300' : ''}`} onClick={() => setShowFilters((s) => !s)}>
            <Filter className="h-4 w-4" /> <span className="hidden sm:inline">Filters</span>
            {filtersOn > 0 && <span className="rounded-full bg-brand-600 px-1.5 text-[10px] text-white">{filtersOn}</span>}
          </button>
        </div>
        {showFilters && (
          <div className="mt-3 grid gap-3 sm:grid-cols-4">
            <div>
              <label className="label">Owner</label>
              <input className="input" placeholder="Name or email" value={owner} onChange={(e) => setOwner(e.target.value)} />
            </div>
            <div>
              <label className="label">Category</label>
              <select className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="">Any</option>
                {cats.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label">Updated from</label>
              <input type="date" className="input" value={from} onChange={(e) => setFrom(e.target.value)} />
            </div>
            <div>
              <label className="label">Updated to</label>
              <input type="date" className="input" value={to} onChange={(e) => setTo(e.target.value)} />
            </div>
            {filtersOn > 0 && (
              <button
                className="btn-ghost justify-start px-0 text-xs sm:col-span-4"
                onClick={() => {
                  setOwner('');
                  setCategory('');
                  setFrom('');
                  setTo('');
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>

      {error && <p className="text-sm text-rose-600">{error}</p>}
      {!docs && !error && (
        <div className="flex justify-center py-16">
          <Spinner className="h-8 w-8" />
        </div>
      )}
      {docs && docs.length === 0 && (
        <div className="card">
          {q || filtersOn ? (
            <Empty icon={<FileSearch className="h-7 w-7" />} title="No matches">Nothing you can access matches those filters.</Empty>
          ) : scope === 'shared' ? (
            <Empty icon={<Inbox className="h-7 w-7" />} title="Nothing shared with you yet">When someone gives you access to a document, it appears here.</Empty>
          ) : (
            <Empty icon={<Upload className="h-7 w-7" />} title="No documents yet">
              {user?.role === 'owner' ? 'Upload your first document. Nobody else can see it until you share it.' : 'You only see documents that are shared with you.'}
            </Empty>
          )}
        </div>
      )}

      {docs && docs.length > 0 && view === 'grid' && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {docs.map((d) => (
            <Link key={d.id} to={`/doc/${d.id}`} className="card group flex flex-col p-4 transition hover:-translate-y-0.5 hover:border-brand-300 hover:shadow-md dark:hover:border-brand-800">
              <div className="flex items-start gap-3">
                <FileIcon name={d.filename ?? d.title} mime={d.mimeType ?? undefined} />
                <div className="min-w-0 flex-1">
                  <div className="line-clamp-2 font-semibold group-hover:text-brand-700 dark:group-hover:text-brand-300">{d.title}</div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    <CategoryBadge c={d.category} />
                    <AccessBadge access={d.access} />
                  </div>
                </div>
              </div>
              <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 text-xs text-slate-500 dark:border-slate-800">
                <span className="flex min-w-0 items-center gap-2">
                  <Avatar name={d.owner.name} size="sm" />
                  <span className="truncate">{d.owner.id === user?.id ? 'You' : d.owner.name}</span>
                </span>
                <span className="flex shrink-0 items-center gap-1">
                  <CalendarDays className="h-3.5 w-3.5" /> {relTime(d.updatedAt)}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}

      {docs && docs.length > 0 && view === 'list' && (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900">
                <tr>
                  <th className="px-4 py-3">Title</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Owner</th>
                  <th className="px-4 py-3">Access</th>
                  <th className="px-4 py-3">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {docs.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="px-4 py-3">
                      <Link to={`/doc/${d.id}`} className="font-medium hover:text-brand-700 dark:hover:text-brand-300">{d.title}</Link>
                    </td>
                    <td className="px-4 py-3"><CategoryBadge c={d.category} /></td>
                    <td className="px-4 py-3">{d.owner.id === user?.id ? 'You' : d.owner.name}</td>
                    <td className="px-4 py-3"><AccessBadge access={d.access} /></td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-500">{relTime(d.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
