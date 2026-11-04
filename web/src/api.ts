// Thin client for the TrustVault API. Every request is same-origin with the
// session cookie; every non-GET carries the anti-forgery header the server
// requires. The UI only hides things the user cannot do — the server decides.

export type Role = 'admin' | 'owner' | 'viewer';
export type Access = 'read' | 'edit' | 'owner';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  isDemo: boolean;
}

export interface DocSummary {
  id: string;
  title: string;
  category: string;
  owner: { id: string; name: string; email: string };
  updatedAt: number;
  createdAt: number;
  access: Access;
  mimeType?: string | null;
  filename?: string | null;
}

export interface Version {
  id: string;
  versionNo: number;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  createdAt: number;
  uploadedBy?: string;
  current?: boolean;
}

export interface DocDetail extends Omit<DocSummary, 'owner'> {
  description: string;
  owner: { id: string; name: string; email: string };
  allowedActions: string[];
  currentVersion: Version | null;
}

export interface Grant {
  id: string;
  user: { id: string; name: string; email: string; role: Role; active: boolean };
  permission: 'read' | 'edit';
  grantedBy: string;
  createdAt: number;
  expiresAt: number | null;
  expired: boolean;
}

export interface AuditEvent {
  seq: number;
  ts: number;
  actor_email: string | null;
  action: string;
  outcome: 'success' | 'denied' | 'failure';
  document_id?: string | null;
  target_user_id?: string | null;
  details: Record<string, unknown>;
}

export interface Suggestion {
  userId: string;
  name: string;
  email: string;
  permission: 'read' | 'edit';
  reason: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();
export const onUnauthorized = (l: Listener) => {
  unauthorizedListeners.add(l);
  return () => {
    unauthorizedListeners.delete(l);
  };
};

export async function api<T = any>(method: string, url: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'X-TrustVault-CSRF': '1' };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin' });
  const data = (res.headers.get('content-type') ?? '').includes('application/json') ? await res.json() : null;
  if (res.status === 401 && !url.startsWith('/api/auth/')) unauthorizedListeners.forEach((l) => l());
  if (!res.ok) throw new ApiError(res.status, data?.error ?? 'error', data?.message ?? `Request failed (${res.status})`);
  return data as T;
}

/** Fetch file bytes (preview) as a Blob, through the same authorised route. */
export async function fetchBlob(url: string): Promise<{ blob: Blob; mime: string }> {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (res.status === 401) unauthorizedListeners.forEach((l) => l());
  if (!res.ok) {
    const data = (res.headers.get('content-type') ?? '').includes('application/json') ? await res.json() : null;
    throw new ApiError(res.status, data?.error ?? 'error', data?.message ?? `Request failed (${res.status})`);
  }
  return { blob: await res.blob(), mime: res.headers.get('x-trustvault-mime') ?? 'application/octet-stream' };
}

/** Multipart upload with progress (fetch has no upload progress, so XHR). */
export function uploadWithProgress<T = any>(url: string, form: FormData, onProgress: (pct: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.withCredentials = true;
    xhr.setRequestHeader('X-TrustVault-CSRF', '1');
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onload = () => {
      let data: any = null;
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        /* not JSON */
      }
      if (xhr.status === 401) unauthorizedListeners.forEach((l) => l());
      if (xhr.status >= 200 && xhr.status < 300) resolve(data as T);
      else reject(new ApiError(xhr.status, data?.error ?? 'error', data?.message ?? `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiError(0, 'network', 'Network error during upload'));
    xhr.send(form);
  });
}

export const fmtDate = (ts: number | null | undefined) =>
  ts ? new Date(ts).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '';
export const fmtDay = (ts: number) => new Date(ts).toLocaleDateString(undefined, { dateStyle: 'medium' });
export const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
export const relTime = (ts: number) => {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 7 * 86400) return `${Math.floor(s / 86400)} d ago`;
  return fmtDay(ts);
};
