import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import { AuditLog, stdoutHeadSink, type HeadSink } from './audit.ts';
import { csrfMiddleware, sessionMiddleware } from './auth.ts';
import { loadConfig, type Config } from './config.ts';
import { HttpError, type AppContext } from './context.ts';
import { openDb } from './db.ts';
import { adminRoutes, userRoutes } from './routes/admin.ts';
import { authRoutes } from './routes/auth.ts';
import { documentRoutes } from './routes/documents.ts';
import { BlobStore } from './storage.ts';
import { ValidationError } from './validation.ts';

const here = path.dirname(fileURLToPath(import.meta.url));

export function createContext(overrides: Partial<Config> = {}, sink: HeadSink = stdoutHeadSink): AppContext {
  const config = loadConfig(overrides);
  const db = openDb(config.dataDir);
  return { config, db, audit: new AuditLog(db, config.auditKey, sink), blobs: new BlobStore(config.dataDir, config.masterKey) };
}

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.config.trustProxy ? 1 : false);
  app.set('etag', false);

  app.use((_req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (ctx.config.env === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  // API: no caching anywhere, JSON bodies only and small.
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/api', express.json({ limit: '32kb', strict: true }));
  app.use('/api', sessionMiddleware(ctx));
  app.use('/api', csrfMiddleware(ctx));
  app.use('/api/auth', authRoutes(ctx));
  app.use('/api/documents', documentRoutes(ctx));
  app.use('/api/users', userRoutes(ctx));
  app.use('/api/admin', adminRoutes(ctx));
  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'not_found', 'No such endpoint')));

  // Static UI. Contains no data; everything comes from the API after sign-in.
  app.use(express.static(path.join(here, '..', 'public'), { index: 'index.html', dotfiles: 'deny', etag: false }));
  app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(here, '..', 'public', 'index.html')));

  // Errors: known errors map to their status; everything else is a 500 with
  // no internals in the body (details go to the server log only).
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.code, message: err.message });
    if (err instanceof ValidationError) return res.status(400).json({ error: 'validation', message: err.message });
    const e = err as { type?: string; status?: number };
    if (e?.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json', message: 'Malformed JSON' });
    if (e?.type === 'entity.too.large') return res.status(413).json({ error: 'too_large', message: 'Request body too large' });
    console.error(JSON.stringify({ type: 'error', path: req.path, message: (err as Error)?.message, stack: (err as Error)?.stack }));
    res.status(500).json({ error: 'internal', message: 'Something went wrong' });
  });
  return app;
}
