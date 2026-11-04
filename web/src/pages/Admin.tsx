import { useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, FileText, KeySquare, Link2, ShieldAlert, ShieldCheck, UserPlus, Users } from 'lucide-react';
import { api, fmtDate, relTime, type AuditEvent, type Role } from '../api';
import { useSession } from '../session';
import { Avatar, Modal, OutcomeBadge, PageHeader, Spinner, useAction, useToast } from '../ui';

type Tab = 'overview' | 'audit' | 'permissions' | 'users';

export default function Admin() {
  const [tab, setTab] = useState<Tab>('overview');
  const tabs: { k: Tab; label: string; icon: React.ReactNode }[] = [
    { k: 'overview', label: 'Overview', icon: <Activity className="h-4 w-4" /> },
    { k: 'audit', label: 'Audit trail', icon: <KeySquare className="h-4 w-4" /> },
    { k: 'permissions', label: 'Permissions', icon: <Link2 className="h-4 w-4" /> },
    { k: 'users', label: 'Users', icon: <Users className="h-4 w-4" /> },
  ];
  return (
    <>
      <PageHeader title="Administration" subtitle="Manage accounts and review activity. Administrators cannot open documents unless an owner shares them." />
      <div className="mb-5 flex gap-1 overflow-x-auto rounded-xl bg-slate-100 p-1 dark:bg-slate-800/60">
        {tabs.map((t) => (
          <button key={t.k} onClick={() => setTab(t.k)} className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-4 py-2 text-sm font-medium transition ${tab === t.k ? 'bg-white shadow dark:bg-slate-900' : 'text-slate-500'}`}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>
      {tab === 'overview' && <Overview />}
      {tab === 'audit' && <Audit />}
      {tab === 'permissions' && <Permissions />}
      {tab === 'users' && <UsersTab />}
    </>
  );
}

interface Alert {
  severity: 'critical' | 'high' | 'medium' | 'info';
  kind: string;
  message: string;
  lastSeen?: number;
}

function Overview() {
  const [data, setData] = useState<{ stats: any; alerts: Alert[]; verify: any } | null>(null);
  useEffect(() => {
    Promise.all([api('GET', '/api/admin/stats'), api<{ alerts: Alert[] }>('GET', '/api/admin/alerts'), api('GET', '/api/admin/audit/verify')]).then(([stats, a, verify]) =>
      setData({ stats, alerts: a.alerts, verify }),
    );
  }, []);
  if (!data) return <Spinner />;
  const { stats, alerts, verify } = data;
  const sev = {
    critical: 'bg-rose-600 text-white',
    high: 'bg-rose-100 text-rose-700 dark:bg-rose-900/50 dark:text-rose-200',
    medium: 'bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200',
    info: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  };
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={<Users />} label="Active users" value={stats.users} />
        <Stat icon={<FileText />} label="Documents" value={stats.documents} hint={`${stats.inTrash} in trash`} />
        <Stat icon={<Link2 />} label="Active shares" value={stats.grants} />
        <Stat icon={<KeySquare />} label="Audit events" value={stats.auditEvents} />
      </div>
      <div className={`card flex items-start gap-3 p-4 ${verify.ok ? '' : 'border-rose-300 dark:border-rose-800'}`}>
        {verify.ok ? <ShieldCheck className="h-6 w-6 text-brand-600" /> : <ShieldAlert className="h-6 w-6 text-rose-600" />}
        <div className="min-w-0">
          <div className="font-semibold">{verify.ok ? 'Audit trail intact' : 'Audit trail has been tampered with'}</div>
          <div className="text-sm text-slate-500">
            {verify.ok ? `All ${verify.checked} entries verified against their HMAC chain.` : `First bad entry: #${verify.firstBadSeq} — ${verify.reason}`}
          </div>
          <div className="mt-1 truncate font-mono text-[11px] text-slate-400">head #{verify.head.seq} {verify.head.hash}</div>
        </div>
      </div>
      <div className="card p-4">
        <h3 className="mb-3 flex items-center gap-2 font-semibold"><AlertTriangle className="h-4 w-4 text-amber-500" /> Worth noticing</h3>
        {alerts.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-slate-500"><CheckCircle2 className="h-4 w-4 text-brand-500" /> Nothing unusual in the last 24 hours.</p>
        ) : (
          <ul className="space-y-2">
            {alerts.map((a, i) => (
              <li key={i} className="flex flex-wrap items-center gap-3 rounded-xl bg-slate-50 p-3 text-sm dark:bg-slate-800/40">
                <span className={`badge uppercase ${sev[a.severity]}`}>{a.severity}</span>
                <span className="min-w-0 flex-1">{a.message}</span>
                {a.lastSeen && <span className="text-xs text-slate-400">{relTime(a.lastSeen)}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Stat({ icon, label, value, hint }: { icon: React.ReactNode; label: string; value: number; hint?: string }) {
  return (
    <div className="card p-4">
      <div className="mb-2 flex h-9 w-9 items-center justify-center rounded-xl bg-brand-50 text-brand-600 dark:bg-brand-900/40 dark:text-brand-300 [&>svg]:h-5 [&>svg]:w-5">{icon}</div>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-slate-500">{label}{hint ? ` · ${hint}` : ''}</div>
    </div>
  );
}

function Audit() {
  const [actor, setActor] = useState('');
  const [action, setAction] = useState('');
  const [outcome, setOutcome] = useState('');
  const [events, setEvents] = useState<(AuditEvent & { ip?: string })[] | null>(null);
  useEffect(() => {
    const t = setTimeout(() => {
      const p = new URLSearchParams({ limit: '300' });
      if (actor) p.set('actor', actor);
      if (action) p.set('action', action);
      if (outcome) p.set('outcome', outcome);
      api<{ events: AuditEvent[] }>('GET', `/api/admin/audit?${p}`).then((r) => setEvents(r.events));
    }, 250);
    return () => clearTimeout(t);
  }, [actor, action, outcome]);
  return (
    <div className="card p-4">
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <input className="input" placeholder="Who (email)" value={actor} onChange={(e) => setActor(e.target.value)} />
        <select className="input" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">Any action</option>
          <option value="document.download">Downloads</option>
          <option value="document.preview">Previews</option>
          <option value="document.">All document actions</option>
          <option value="grant.">Permission changes</option>
          <option value="auth.">Sign-in</option>
          <option value="user.">User administration</option>
          <option value="ai.">AI suggestions</option>
        </select>
        <select className="input" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">Any outcome</option>
          <option value="denied">Refused</option>
          <option value="success">Succeeded</option>
          <option value="failure">Failed</option>
        </select>
      </div>
      {!events ? (
        <Spinner />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-2 pr-3">#</th>
                <th className="py-2 pr-3">When</th>
                <th className="py-2 pr-3">Who</th>
                <th className="py-2 pr-3">Action</th>
                <th className="py-2 pr-3">Result</th>
                <th className="py-2">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.map((e) => (
                <tr key={e.seq} className="align-top">
                  <td className="py-2 pr-3 font-mono text-xs text-slate-400">{e.seq}</td>
                  <td className="whitespace-nowrap py-2 pr-3 text-xs">{fmtDate(e.ts)}</td>
                  <td className="max-w-[12rem] truncate py-2 pr-3">{e.actor_email ?? '—'}</td>
                  <td className="whitespace-nowrap py-2 pr-3 font-medium">{e.action}</td>
                  <td className="py-2 pr-3"><OutcomeBadge outcome={e.outcome} /></td>
                  <td className="max-w-md break-all py-2 font-mono text-[11px] text-slate-500">{JSON.stringify(e.details)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Permissions() {
  const [grants, setGrants] = useState<any[] | null>(null);
  useEffect(() => {
    api<{ grants: any[] }>('GET', '/api/admin/grants').then((r) => setGrants(r.grants));
  }, []);
  if (!grants) return <Spinner />;
  return (
    <div className="card overflow-x-auto p-4">
      <p className="mb-3 text-sm text-slate-500">Every active share, for access reviews. Titles only; administrators cannot open the files.</p>
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="py-2 pr-3">Document</th>
            <th className="py-2 pr-3">Owner</th>
            <th className="py-2 pr-3">Shared with</th>
            <th className="py-2 pr-3">Access</th>
            <th className="py-2">Expires</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {grants.map((g) => (
            <tr key={g.id}>
              <td className="py-2 pr-3 font-medium">{g.title}</td>
              <td className="py-2 pr-3">{g.owner_email}</td>
              <td className="py-2 pr-3">{g.user_email}{!g.user_active && <span className="ml-1 text-xs text-rose-500">(deactivated)</span>}</td>
              <td className="py-2 pr-3">{g.permission === 'edit' ? 'Can edit' : 'Can view'}</td>
              <td className="py-2">{g.expires_at ? fmtDate(g.expires_at) : 'never'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface AdminUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  active: boolean;
  isDemo: boolean;
  createdAt: number;
  documentsOwned: number;
}

function UsersTab() {
  const { user: me } = useSession();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [invite, setInvite] = useState(false);
  const [transferFrom, setTransferFrom] = useState<AdminUser | null>(null);
  const toast = useToast();
  const act = useAction();
  const load = useCallback(() => {
    api<{ users: AdminUser[] }>('GET', '/api/admin/users').then((r) => setUsers(r.users));
  }, []);
  useEffect(load, [load]);
  if (!users) return <Spinner />;
  const owners = users.filter((u) => u.role === 'owner' && u.active);

  return (
    <div className="card p-4">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-slate-500">Role changes and deactivation end that person's sessions immediately.</p>
        {!me?.isDemo && (
          <button className="btn-primary" onClick={() => setInvite(true)}><UserPlus className="h-4 w-4" /> Invite</button>
        )}
      </div>
      <ul className="divide-y divide-slate-100 dark:divide-slate-800">
        {users.map((u) => (
          <li key={u.id} className="flex flex-wrap items-center gap-3 py-3">
            <Avatar name={u.name} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-semibold">
                {u.name} {!u.active && <span className="badge ml-1 bg-rose-100 text-rose-700 dark:bg-rose-900/50 dark:text-rose-200">deactivated</span>}
                {u.isDemo && <span className="badge ml-1 bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200">demo</span>}
              </div>
              <div className="truncate text-xs text-slate-500">{u.email} · {u.documentsOwned} documents · joined {relTime(u.createdAt)}</div>
            </div>
            <select
              className="input w-auto py-1"
              value={u.role}
              disabled={u.id === me?.id}
              onChange={(e) => act(async () => {
                await api('PATCH', `/api/admin/users/${u.id}`, { role: e.target.value });
                toast(`${u.name} is now ${e.target.value}. Their sessions were ended.`);
                load();
              })()}
            >
              <option value="viewer">Viewer</option>
              <option value="owner">Owner</option>
              <option value="admin">Admin</option>
            </select>
            {u.id !== me?.id && (
              <button className="btn-outline px-3 py-1.5" onClick={act(async () => {
                await api('PATCH', `/api/admin/users/${u.id}`, { active: !u.active });
                toast(u.active ? `${u.name} deactivated and signed out everywhere.` : `${u.name} reactivated.`);
                load();
              })}>{u.active ? 'Deactivate' : 'Reactivate'}</button>
            )}
            <button className="btn-ghost px-3 py-1.5" onClick={act(async () => {
              const r = await api<{ sessionsRevoked: number }>('POST', `/api/admin/users/${u.id}/revoke-sessions`);
              toast(`${r.sessionsRevoked} session(s) ended.`);
            })}>End sessions</button>
            {u.documentsOwned > 0 && <button className="btn-ghost px-3 py-1.5" onClick={() => setTransferFrom(u)}>Transfer docs</button>}
          </li>
        ))}
      </ul>
      <InviteDialog open={invite} onClose={() => setInvite(false)} onDone={load} />
      <Modal open={!!transferFrom} onClose={() => setTransferFrom(null)} title={`Transfer ${transferFrom?.name ?? ''}'s documents`}>
        <p className="mb-3 text-sm text-slate-500">For leavers: ownership moves to another owner. You do not gain access yourself.</p>
        <ul className="space-y-2">
          {owners.filter((o) => o.id !== transferFrom?.id && o.isDemo === transferFrom?.isDemo).map((o) => (
            <li key={o.id}>
              <button className="btn-outline w-full justify-start" onClick={act(async () => {
                const r = await api<{ transferred: number }>('POST', `/api/admin/users/${transferFrom!.id}/transfer-documents`, { toUserId: o.id });
                toast(`${r.transferred} document(s) transferred to ${o.name}.`);
                setTransferFrom(null);
                load();
              })}>
                <Avatar name={o.name} size="sm" /> {o.name} <span className="text-xs text-slate-400">{o.email}</span>
              </button>
            </li>
          ))}
        </ul>
      </Modal>
    </div>
  );
}

function InviteDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const toast = useToast();
  const act = useAction();
  return (
    <Modal open={open} onClose={onClose} title="Invite someone">
      <div className="space-y-3">
        <div><label className="label">Name</label><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div><label className="label">Email</label><input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <div>
          <label className="label">Role</label>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="viewer">Viewer — sees only what is shared with them</option>
            <option value="owner">Owner — can upload and share</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <p className="text-xs text-slate-500">They sign in with a code sent to this address. No password is ever set.</p>
        <div className="flex justify-end gap-2">
          <button className="btn-outline" onClick={onClose}>Cancel</button>
          <button className="btn-primary" onClick={act(async () => {
            await api('POST', '/api/admin/users', { email, name, role });
            toast(`${name} can now sign in with ${email}.`);
            setEmail('');
            setName('');
            onClose();
            onDone();
          })}>Create account</button>
        </div>
      </div>
    </Modal>
  );
}
