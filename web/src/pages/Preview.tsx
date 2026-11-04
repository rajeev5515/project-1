import { useEffect, useRef, useState } from 'react';
import { Download, EyeOff, ZoomIn, ZoomOut } from 'lucide-react';
import * as pdfjs from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { fetchBlob } from '../api';
import { Spinner } from '../ui';

// The worker is bundled and served from our own origin (CSP worker-src 'self').
pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

const PREVIEWABLE = new Set(['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'text/csv']);
export const canPreview = (mime?: string) => !!mime && PREVIEWABLE.has(mime);

/**
 * Renders a document inside the app without ever letting its content run:
 *  - PDF: drawn onto <canvas> by pdf.js with scripting, XFA forms, embedded
 *    fonts and WebAssembly decoders disabled. No PDF JavaScript runs, and
 *    nothing is inserted into the DOM as HTML.
 *  - Images: an <img> from a blob: URL (cannot execute).
 *  - Text/CSV: inserted as text (React escapes it), never as HTML.
 * The bytes come from /preview, which the server authorises and audits.
 */
export default function Preview({ docId, mime, filename }: { docId: string; mime: string; filename: string }) {
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading');
  const [error, setError] = useState('');
  const [text, setText] = useState<string | null>(null);
  const [imgUrl, setImgUrl] = useState<string | null>(null);
  const [pdf, setPdf] = useState<pdfjs.PDFDocumentProxy | null>(null);
  const [scale, setScale] = useState(1.2);

  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    setState('loading');
    fetchBlob(`/api/documents/${docId}/preview`)
      .then(async ({ blob, mime: m }) => {
        if (cancelled) return;
        if (m.startsWith('image/')) {
          url = URL.createObjectURL(new Blob([blob], { type: m }));
          setImgUrl(url);
        } else if (m.startsWith('text/')) {
          const t = await blob.text();
          setText(t.length > 500_000 ? t.slice(0, 500_000) + '\n\n… (truncated in preview; download for the full file)' : t);
        } else if (m === 'application/pdf') {
          const doc = await pdfjs.getDocument({
            data: new Uint8Array(await blob.arrayBuffer()),
            enableXfa: false,
            disableFontFace: true,
            useWasm: false,
            standardFontDataUrl: '/pdfjs/standard_fonts/',
            isOffscreenCanvasSupported: false,
          }).promise;
          if (!cancelled) setPdf(doc);
        }
        if (!cancelled) setState('ready');
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e.message);
          setState('error');
        }
      });
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [docId]);

  if (state === 'loading')
    return (
      <div className="flex h-72 items-center justify-center">
        <Spinner className="h-8 w-8" />
      </div>
    );
  if (state === 'error')
    return (
      <div className="flex h-72 flex-col items-center justify-center gap-2 text-sm text-slate-500">
        <EyeOff className="h-6 w-6" /> {error || 'Preview unavailable'}
      </div>
    );

  return (
    <div>
      {pdf && (
        <div className="sticky top-0 z-10 mb-3 flex items-center justify-between rounded-xl bg-slate-100/90 px-3 py-1.5 text-xs backdrop-blur dark:bg-slate-800/90">
          <span className="truncate text-slate-600 dark:text-slate-300">{filename} · {pdf.numPages} page{pdf.numPages === 1 ? '' : 's'}</span>
          <span className="flex items-center gap-1">
            <button className="btn-ghost p-1" onClick={() => setScale((s) => Math.max(0.6, s - 0.2))} aria-label="Zoom out"><ZoomOut className="h-4 w-4" /></button>
            <span className="w-10 text-center">{Math.round(scale * 100)}%</span>
            <button className="btn-ghost p-1" onClick={() => setScale((s) => Math.min(3, s + 0.2))} aria-label="Zoom in"><ZoomIn className="h-4 w-4" /></button>
          </span>
        </div>
      )}
      <div className="max-h-[75vh] overflow-auto rounded-xl bg-slate-100 p-3 dark:bg-slate-950">
        {imgUrl && <img src={imgUrl} alt={filename} className="mx-auto max-w-full rounded-lg shadow" />}
        {text !== null && <pre className="whitespace-pre-wrap break-words rounded-lg bg-white p-4 font-mono text-xs text-slate-800 shadow-sm dark:bg-slate-900 dark:text-slate-200">{text}</pre>}
        {pdf && (
          <div className="flex flex-col items-center gap-3">
            {Array.from({ length: Math.min(pdf.numPages, 50) }, (_, i) => (
              <PdfPage key={`${i}-${scale}`} pdf={pdf} pageNo={i + 1} scale={scale} />
            ))}
            {pdf.numPages > 50 && <p className="text-xs text-slate-500">Showing the first 50 pages. Download for the rest.</p>}
          </div>
        )}
      </div>
    </div>
  );
}

function PdfPage({ pdf, pageNo, scale }: { pdf: pdfjs.PDFDocumentProxy; pageNo: number; scale: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    let task: pdfjs.RenderTask | null = null;
    let cancelled = false;
    pdf.getPage(pageNo).then((page) => {
      if (cancelled || !ref.current) return;
      const ratio = window.devicePixelRatio || 1;
      const viewport = page.getViewport({ scale: scale * ratio });
      const canvas = ref.current;
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      // Set only the width; height follows the canvas's own aspect ratio, so
      // max-width on narrow screens shrinks the page instead of squashing it.
      canvas.style.width = `${viewport.width / ratio}px`;
      task = page.render({ canvas, viewport });
      task.promise.catch(() => {});
    });
    return () => {
      cancelled = true;
      task?.cancel();
    };
  }, [pdf, pageNo, scale]);
  return <canvas ref={ref} className="h-auto max-w-full rounded bg-white shadow" />;
}

export function NoPreview({ href }: { href: string }) {
  return (
    <div className="flex h-56 flex-col items-center justify-center gap-3 text-center text-sm text-slate-500">
      <EyeOff className="h-6 w-6" />
      <p>This file type can't be previewed safely in the browser.</p>
      <a className="btn-outline" href={href}>
        <Download className="h-4 w-4" /> Download instead
      </a>
    </div>
  );
}
