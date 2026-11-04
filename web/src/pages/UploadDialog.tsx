import { useEffect, useRef, useState, type DragEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { CloudUpload } from 'lucide-react';
import { api, fmtBytes, uploadWithProgress } from '../api';
import { FileIcon, Modal, useToast } from '../ui';

export const ACCEPT = '.pdf,.png,.jpg,.jpeg,.docx,.xlsx,.pptx,.txt,.csv';
const MAX_BYTES = 20 * 1024 * 1024;

export function useCategories() {
  const [cats, setCats] = useState<string[]>([]);
  useEffect(() => {
    api<{ categories: string[] }>('GET', '/api/documents/categories').then((r) => setCats(r.categories)).catch(() => {});
  }, []);
  return cats;
}

/** Drag-and-drop zone shared by new uploads and new versions. */
export function DropZone({ file, onFile }: { file: File | null; onFile: (f: File) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const drop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  };
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={drop}
      onClick={() => input.current?.click()}
      className={`flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-4 py-8 text-center transition ${
        over ? 'border-brand-500 bg-brand-50 dark:bg-brand-900/20' : 'border-slate-300 hover:border-brand-400 dark:border-slate-700'
      }`}
    >
      <input ref={input} type="file" className="hidden" accept={ACCEPT} onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
      {file ? (
        <div className="flex items-center gap-3 text-left">
          <FileIcon name={file.name} />
          <div>
            <div className="max-w-[16rem] truncate text-sm font-semibold">{file.name}</div>
            <div className="text-xs text-slate-500">{fmtBytes(file.size)} · click to change</div>
          </div>
        </div>
      ) : (
        <>
          <CloudUpload className="mb-2 h-8 w-8 text-brand-500" />
          <div className="text-sm font-semibold">Drop a file here or click to choose</div>
          <div className="mt-1 text-xs text-slate-500">PDF, images, Word, Excel, PowerPoint, text or CSV · up to 20 MB</div>
        </>
      )}
    </div>
  );
}

export default function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const cats = useCategories();
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('Other');
  const [description, setDescription] = useState('');
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  const navigate = useNavigate();

  const reset = () => {
    setFile(null);
    setTitle('');
    setDescription('');
    setCategory('Other');
    setProgress(null);
    setError(null);
  };

  const choose = (f: File) => {
    setError(f.size > MAX_BYTES ? 'That file is larger than 20 MB.' : null);
    setFile(f);
    if (!title) setTitle(f.name.replace(/\.[^.]+$/, '').replace(/[-_]+/g, ' '));
  };

  async function submit() {
    if (!file) return setError('Choose a file first.');
    const form = new FormData();
    form.append('title', title);
    form.append('category', category);
    form.append('description', description);
    form.append('file', file);
    setError(null);
    setProgress(0);
    try {
      const r = await uploadWithProgress<{ document: { id: string } }>('/api/documents', form, setProgress);
      toast('Uploaded. Only you can see it until you share it.');
      reset();
      onClose();
      navigate(`/doc/${r.document.id}`);
    } catch (e) {
      setError((e as Error).message);
      setProgress(null);
    }
  }

  return (
    <Modal
      open={open}
      title="Upload a document"
      onClose={() => {
        reset();
        onClose();
      }}
    >
      <div className="space-y-4">
        <DropZone file={file} onFile={choose} />
        <div>
          <label className="label" htmlFor="up-title">Title</label>
          <input id="up-title" className="input" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="up-cat">Category</label>
            <select id="up-cat" className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
              {cats.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label className="label" htmlFor="up-desc">Description (optional)</label>
          <textarea id="up-desc" className="input" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} />
        </div>
        {progress !== null && (
          <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
            <div className="h-full rounded-full bg-brand-500 transition-all" style={{ width: `${progress}%` }} />
          </div>
        )}
        {error && <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>}
        <p className="text-xs text-slate-500">The file type is checked from its content, not just its name. It is encrypted before it is stored.</p>
        <div className="flex justify-end gap-2">
          <button className="btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!file || !title.trim() || progress !== null} onClick={submit}>
            {progress !== null ? `Uploading ${progress}%` : 'Upload'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
