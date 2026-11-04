import { useCallback, useEffect, useState } from 'react';
import { RotateCcw, Trash2 } from 'lucide-react';
import { api, relTime } from '../api';
import { Empty, FileIcon, PageHeader, Spinner, useAction, useToast } from '../ui';
import { CategoryBadge } from './Documents';

interface TrashDoc {
  id: string;
  title: string;
  category: string;
  deletedAt: number;
}

export default function Trash() {
  const [docs, setDocs] = useState<TrashDoc[] | null>(null);
  const toast = useToast();
  const act = useAction();
  const load = useCallback(() => {
    api<{ documents: TrashDoc[] }>('GET', '/api/documents/trash').then((r) => setDocs(r.documents));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <PageHeader title="Trash" subtitle="Deleted documents are unreachable for everyone you shared them with. Restore brings their access back; delete forever destroys the file (its history stays in the audit trail)." />
      {!docs ? (
        <Spinner />
      ) : docs.length === 0 ? (
        <div className="card">
          <Empty icon={<Trash2 className="h-7 w-7" />} title="Trash is empty" />
        </div>
      ) : (
        <ul className="card divide-y divide-slate-100 dark:divide-slate-800">
          {docs.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center gap-3 p-4">
              <FileIcon name={d.title} className="h-9 w-9" />
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium">{d.title}</div>
                <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                  <CategoryBadge c={d.category} /> deleted {relTime(d.deletedAt)}
                </div>
              </div>
              <button className="btn-outline px-3 py-1.5" onClick={act(async () => {
                await api('POST', `/api/documents/${d.id}/restore`);
                toast('Restored. Existing shares work again.');
                load();
              })}>
                <RotateCcw className="h-4 w-4" /> Restore
              </button>
              <button className="btn-danger px-3 py-1.5" onClick={act(async () => {
                if (!confirm('Permanently destroy this document and every version? This cannot be undone.')) return;
                await api('DELETE', `/api/documents/${d.id}/purge`);
                toast('Destroyed permanently.');
                load();
              })}>
                <Trash2 className="h-4 w-4" /> Delete forever
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
