/**
 * Verify the audit hash chain offline.
 *   npm run verify-audit
 *   npm run verify-audit -- <seq> <hash>     # also check against an externally recorded head
 *
 * Exit code 0 = intact, 1 = broken. Take <seq> <hash> from the last
 * {"type":"audit_head",...} line in the platform's log stream, which the
 * application cannot rewrite, to also detect a truncated tail.
 */
import { createContext } from '../src/app.ts';

const ctx = createContext({}, () => {});
const [seqArg, hashArg] = process.argv.slice(2);
const expected = seqArg && hashArg ? { seq: Number(seqArg), hash: hashArg } : undefined;
const r = ctx.audit.verify(expected);
console.log(JSON.stringify(r, null, 2));
process.exit(r.ok ? 0 : 1);
