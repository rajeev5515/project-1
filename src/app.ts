import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import { AuditLog, stdoutHeadSink, type HeadSink } from './audit.ts';
import { csrfMiddleware, sessionMiddleware } from './auth.ts';
import { loadConfig, type Config } from './config.ts';
import { HttpError, type AppContext } from './context.ts';
import { openDb } from './db.ts';
import { LogMailer, ResendMailer, UnconfiguredMailer, type Mailer } from './mailer.ts';
import { adminRoutes, userRoutes } from './routes/admin.ts';
import { authRoutes } from './routes/auth.ts';
import { documentRoutes } from './routes/documents.ts';
import { BlobStore } from './storage.ts';
import { ValidationError } from './validation.ts';

const here = path.dirname(fileURLToPath(import.meta.url));

function defaultMailer(config: Config): Mailer {
  if (config.resendApiKey) return new ResendMailer(config.resendApiKey, config.emailFrom);
  return config.env === 'production' ? new UnconfiguredMailer() : new LogMailer();
}

export function createContext(overrides: Partial<Config> = {}, sink: HeadSink = stdoutHeadSink, mailer?: Mailer): AppContext {
  const config = loadConfig(overrides);
  const db = openDb(config.dataDir);
  return {
    config,
    db,
    audit: new AuditLog(db, config.auditKey, sink),
    blobs: new BlobStore(config.dataDir, config.masterKey),
    mailer: mailer ?? defaultMailer(config),
  };
}

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.config.trustProxy ? 1 : false);
  app.set('etag', false);

  app.use((_req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; worker-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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

  // Static UI (React build in web/dist). Contains no data; everything comes
  // from the API after sign-in. Hashed assets can be cached; index.html not.
  const webRoot = path.join(here, '..', 'web', 'dist');
  app.use(
    express.static(webRoot, {
      index: false,
      dotfiles: 'deny',
      etag: false,
      setHeaders: (res, file) => res.setHeader('Cache-Control', file.includes(`${path.sep}assets${path.sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache'),
    }),
  );
  app.get(/^\/(?!api\/).*/, (_req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.join(webRoot, 'index.html'), (err) => {
      if (err && !res.headersSent) res.status(503).type('text/plain').send('UI not built. Run: npm run build');
    });
  });

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
