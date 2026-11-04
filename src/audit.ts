import { createHmac, timingSafeEqual } from 'node:crypto';
import type { DB } from './db.ts';

/**
 * Tamper-evident audit trail.
 *
 * Every row stores prev_hash (the hash of the row before it) and
 *   hash = HMAC-SHA256(auditKey, prev_hash || canonical(row))
 *
 * What this gives us, layered:
 *  1. Application code has no UPDATE/DELETE path for audit_log, and the
 *     database triggers abort any attempt (see db.ts).
 *  2. Someone with raw write access to the database file can drop the
 *     triggers, but they cannot recompute valid hashes without TV_AUDIT_KEY,
 *     which lives in the environment, not the database. Editing, deleting or
 *     re-ordering a row breaks the chain at that point and verify() reports
 *     the first bad sequence number.
 *  3. Truncating the tail (deleting the newest rows) does not break the chain
 *     by itself. To catch that, every append also writes the new head
 *     (seq + hash) to stdout as a structured line, which the hosting platform
 *     collects into a log store the application cannot rewrite. Comparing the
 *     externally recorded head with the database head detects truncation.
 *
 * What it does not give us: protection against someone who holds both the
 * database and TV_AUDIT_KEY (i.e. full control of the running server). That
 * is accepted in THREATS.md; the external head log is the mitigation.
 */

export type Outcome = 'success' | 'denied' | 'failure';

export interface AuditEvent {
  actorId?: string | null;
  actorEmail?: string | null;
  action: string;
  outcome: Outcome;
  documentId?: string | null;
  targetUserId?: string | null;
  ip?: string | null;
  details?: Record<string, unknown>;
}

export interface AuditRow {
  seq: number;
  ts: number;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  outcome: Outcome;
  document_id: string | null;
  target_user_id: string | null;
  ip: string | null;
  details: string;
  prev_hash: string;
  hash: string;
}

export const GENESIS_HASH = '0'.repeat(64);

/** Stable serialisation: fixed field order, so the hash is reproducible. */
function canonical(row: Omit<AuditRow, 'hash' | 'prev_hash'>): string {
  return JSON.stringify([
    row.seq,
    row.ts,
    row.actor_id,
    row.actor_email,
    row.action,
    row.outcome,
    row.document_id,
    row.target_user_id,
    row.ip,
    row.details,
  ]);
}

function computeHash(key: Buffer, prevHash: string, row: Omit<AuditRow, 'hash' | 'prev_hash'>): string {
  return createHmac('sha256', key).update(prevHash).update('|').update(canonical(row)).digest('hex');
}

export type HeadSink = (head: { seq: number; hash: string; ts: number }) => void;

export const stdoutHeadSink: HeadSink = (head) => {
  process.stdout.write(JSON.stringify({ type: 'audit_head', ...head }) + '\n');
};

export class AuditLog {
  private readonly db: DB;
  private readonly key: Buffer;
  private readonly sink: HeadSink;

  constructor(db: DB, key: Buffer, sink: HeadSink = stdoutHeadSink) {
    this.db = db;
    this.key = key;
    this.sink = sink;
  }

  /**
   * Append one event. Synchronous: node:sqlite is synchronous and Node runs
   * this on one thread, so read-head-then-insert cannot interleave with
   * another append. When called inside tx(), the audit row commits or rolls
   * back together with the action it describes.
   */
  record(ev: AuditEvent): AuditRow {
    const last = this.db
      .prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; hash: string } | undefined;
    const prevHash = last?.hash ?? GENESIS_HASH;
    const seq = (last?.seq ?? 0) + 1;
    const base = {
      seq,
      ts: Date.now(),
      actor_id: ev.actorId ?? null,
      actor_email: ev.actorEmail ?? null,
      action: ev.action,
      outcome: ev.outcome,
      document_id: ev.documentId ?? null,
      target_user_id: ev.targetUserId ?? null,
      ip: ev.ip ?? null,
      details: JSON.stringify(ev.details ?? {}),
    };
    const hash = computeHash(this.key, prevHash, base);
    this.db
      .prepare(
        `INSERT INTO audit_log (seq, ts, actor_id, actor_email, action, outcome, document_id,
           target_user_id, ip, details, prev_hash, hash)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        base.seq,
        base.ts,
        base.actor_id,
        base.actor_email,
        base.action,
        base.outcome,
        base.document_id,
        base.target_user_id,
        base.ip,
        base.details,
        prevHash,
        hash,
      );
    this.sink({ seq, hash, ts: base.ts });
    return { ...base, prev_hash: prevHash, hash };
  }

  head(): { seq: number; hash: string } {
    const last = this.db
      .prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; hash: string } | undefined;
    return last ?? { seq: 0, hash: GENESIS_HASH };
  }

  /**
   * Walk the whole chain. Returns ok=false with the first sequence number at
   * which the chain no longer verifies (edited row, deleted row, re-ordered
   * row, or forged row).
   */
  verify(expectedHead?: { seq: number; hash: string }): {
    ok: boolean;
    checked: number;
    firstBadSeq: number | null;
    reason: string | null;
    head: { seq: number; hash: string };
  } {
    const rows = this.db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').all() as unknown as AuditRow[];
    let prevHash = GENESIS_HASH;
    let expectedSeq = 1;
    for (const row of rows) {
      const fail = (reason: string) => ({
        ok: false,
        checked: expectedSeq - 1,
        firstBadSeq: row.seq,
        reason,
        head: this.head(),
      });
      if (row.seq !== expectedSeq) return fail(`gap: expected seq ${expectedSeq}, found ${row.seq}`);
      if (row.prev_hash !== prevHash) return fail('prev_hash does not match previous row');
      const { hash, prev_hash: _p, ...base } = row;
      const recomputed = computeHash(this.key, prevHash, base);
      const a = Buffer.from(recomputed, 'hex');
      const b = Buffer.from(hash, 'hex');
      if (a.length !== b.length || !timingSafeEqual(a, b)) return fail('row content does not match its hash');
      prevHash = hash;
      expectedSeq++;
    }
    const head = this.head();
    if (expectedHead) {
      if (head.seq < expectedHead.seq) {
        return {
          ok: false,
          checked: rows.length,
          firstBadSeq: head.seq + 1,
          reason: `truncated: externally recorded head is seq ${expectedHead.seq}`,
          head,
        };
      }
      const anchored = rows.find((r) => r.seq === expectedHead.seq);
      if (!anchored || anchored.hash !== expectedHead.hash) {
        return {
          ok: false,
          checked: rows.length,
          firstBadSeq: expectedHead.seq,
          reason: 'externally recorded head hash does not match',
          head,
        };
      }
    }
    return { ok: true, checked: rows.length, firstBadSeq: null, reason: null, head };
  }
}
