import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createApp, createContext } from '../src/app.ts';
import type { AppContext } from '../src/context.ts';
import { DEMO_USERS, seed } from '../scripts/seed.ts';

export const PASSWORD = 'Test-Password-123!';

export interface TestEnv {
  ctx: AppContext;
  base: string;
  heads: { seq: number; hash: string }[];
  close: () => Promise<void>;
  ids: Record<UserKey, string>;
  docs: Record<DocTitle, string>;
}

export type UserKey = 'admin' | 'olivia' | 'oscar' | 'vera' | 'victor' | 'pat';

/** Fresh database, seeded with the demo users (all with PASSWORD) and documents. */
export async function startEnv(overrides: Parameters<typeof createContext>[0] = {}): Promise<TestEnv> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-test-'));
  const heads: { seq: number; hash: string }[] = [];
  const ctx = createContext({ dataDir, env: 'test', ...overrides }, (h) => heads.push(h));
  seed(ctx, PASSWORD);
  const app = createApp(ctx);
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  const ids = {} as Record<UserKey, string>;
  for (const u of DEMO_USERS) {
    ids[u.email.split('@')[0] as UserKey] = (ctx.db.prepare('SELECT id FROM users WHERE email = ?').get(u.email) as { id: string }).id;
  }
  const docs = {} as Record<DocTitle, string>;
  for (const row of ctx.db.prepare('SELECT id, title FROM documents').all() as { id: string; title: DocTitle }[]) {
    docs[row.title] = row.id;
  }
  return {
    ctx,
    base: `http://127.0.0.1:${port}`,
    heads,
    ids,
    docs,
    close: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      ctx.db.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export const DOC = {
  veraSalary: 'Salary letter - Vera Viewer 2026',
  victorSalary: 'Salary letter - Victor Viewer 2026',
  handbook: 'HR policy handbook',
  msa: 'Master services agreement - Partner Co',
  memo: 'Board litigation memo',
} as const;
export type DocTitle = (typeof DOC)[keyof typeof DOC];

export interface Res {
  status: number;
  json: any;
  headers: Headers;
  body: Buffer;
}

/** A browser-like client: keeps its own session cookie and sends the CSRF header. */
export class Client {
  cookie = '';
  readonly base: string;
  constructor(base: string) {
    this.base = base;
  }

  async req(method: string, url: string, opts: { json?: unknown; form?: FormData; headers?: Record<string, string>; csrf?: boolean } = {}): Promise<Res> {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (this.cookie) headers.cookie = this.cookie;
    if (opts.csrf !== false && method !== 'GET') headers['x-trustvault-csrf'] = '1';
    let body: BodyInit | undefined;
    if (opts.json !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.json);
    } else if (opts.form) {
      body = opts.form;
    }
    const r = await fetch(this.base + url, { method, headers, body, redirect: 'manual' });
    const setCookie = r.headers.getSetCookie();
    for (const c of setCookie) {
      const [pair] = c.split(';');
      if (pair!.startsWith('tv_session=')) this.cookie = pair!.endsWith('=') ? '' : pair!;
    }
    const buf = Buffer.from(await r.arrayBuffer());
    let json: any = null;
    if ((r.headers.get('content-type') ?? '').includes('application/json')) json = JSON.parse(buf.toString('utf8'));
    return { status: r.status, json, headers: r.headers, body: buf };
  }
  get(url: string) {
    return this.req('GET', url);
  }
  post(url: string, json?: unknown) {
    return this.req('POST', url, { json: json ?? {} });
  }
  patch(url: string, json: unknown) {
    return this.req('PATCH', url, { json });
  }
  del(url: string) {
    return this.req('DELETE', url);
  }
  upload(url: string, fields: Record<string, string>, file?: { name: string; data: Buffer | string }) {
    const form = new FormData();
    for (const [k, v] of Object.entries(fields)) form.append(k, v);
    if (file) form.append('file', new Blob([typeof file.data === 'string' ? file.data : new Uint8Array(file.data)]), file.name);
    return this.req('POST', url, { form });
  }
}

export async function login(env: TestEnv, who: UserKey, password = PASSWORD): Promise<Client> {
  const c = new Client(env.base);
  const email = DEMO_USERS.find((u) => u.email.startsWith(who + '@'))!.email;
  const r = await c.post('/api/auth/login', { email, password });
  if (r.status !== 200) throw new Error(`login ${who} failed: ${r.status} ${JSON.stringify(r.json)}`);
  return c;
}

export const PDF = Buffer.from('%PDF-1.4\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n');

export function auditRows(env: TestEnv, where = '1=1', ...params: (string | number)[]) {
  return env.ctx.db.prepare(`SELECT * FROM audit_log WHERE ${where} ORDER BY seq`).all(...params) as any[];
}
