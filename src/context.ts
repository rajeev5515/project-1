import type { AuditEvent, AuditLog } from './audit.ts';
import type { Config } from './config.ts';
import type { DB } from './db.ts';
import type { BlobStore } from './storage.ts';

export type Role = 'admin' | 'owner' | 'viewer';

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  mustChangePassword: boolean;
  sessionHash: string;
}

export interface AppContext {
  config: Config;
  db: DB;
  audit: AuditLog;
  blobs: BlobStore;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: SessionUser;
    }
  }
}

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Audit helper that fills in actor and IP from the request. */
export function auditFor(
  ctx: AppContext,
  req: { user?: SessionUser; ip?: string | undefined },
  ev: Omit<AuditEvent, 'actorId' | 'actorEmail' | 'ip'>,
) {
  return ctx.audit.record({
    ...ev,
    actorId: req.user?.id ?? null,
    actorEmail: req.user?.email ?? null,
    ip: req.ip ?? null,
  });
}
