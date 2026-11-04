import { createApp, createContext } from './app.ts';
import { seed } from '../scripts/seed.ts';

const ctx = createContext();
if (process.env.TV_AUTO_SEED === '1' && seed(ctx, process.env.TV_SEED_PASSWORD)) {
  console.log(JSON.stringify({ type: 'seeded' }));
}
const app = createApp(ctx);
const server = app.listen(ctx.config.port, () => {
  const head = ctx.audit.head();
  console.log(JSON.stringify({ type: 'startup', port: ctx.config.port, env: ctx.config.env, auditHead: head }));
});

// Check the audit chain at startup and hourly; a broken chain is logged loudly
// (and shows as a critical alert in the admin view).
const check = () => {
  const r = ctx.audit.verify();
  console.log(JSON.stringify({ type: 'audit_verify', ok: r.ok, checked: r.checked, firstBadSeq: r.firstBadSeq, reason: r.reason }));
};
check();
setInterval(check, 3600_000).unref();

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
