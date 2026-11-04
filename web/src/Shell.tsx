import { useState, type ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { FolderLock, Inbox, LayoutDashboard, LogOut, Menu, Moon, ShieldAlert, Sun, Trash2, Upload, X } from 'lucide-react';
import { useSession, useTheme } from './session';
import { Avatar } from './ui';
import { Logo } from './pages/Auth';
import UploadDialog from './pages/UploadDialog';

export default function Shell({ children }: { children: ReactNode }) {
  const { user, logout } = useSession();
  const [dark, toggleDark] = useTheme();
  const [menu, setMenu] = useState(false);
  const [upload, setUpload] = useState(false);
  const navigate = useNavigate();
  if (!user) return null;
  const canUpload = user.role === 'owner';

  const links = [
    { to: '/', label: 'All documents', icon: <LayoutDashboard className="h-4 w-4" />, end: true },
    ...(canUpload ? [{ to: '/mine', label: 'My documents', icon: <FolderLock className="h-4 w-4" /> }] : []),
    { to: '/shared', label: 'Shared with me', icon: <Inbox className="h-4 w-4" /> },
    ...(canUpload ? [{ to: '/trash', label: 'Trash', icon: <Trash2 className="h-4 w-4" /> }] : []),
    ...(user.role === 'admin' ? [{ to: '/admin', label: 'Administration', icon: <ShieldAlert className="h-4 w-4" /> }] : []),
  ];

  const nav = (
    <nav className="flex flex-col gap-1">
      {links.map((l) => (
        <NavLink
          key={l.to}
          to={l.to}
          end={l.end}
          onClick={() => setMenu(false)}
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition ${
              isActive ? 'bg-brand-50 text-brand-800 dark:bg-brand-900/40 dark:text-brand-200' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800/70'
            }`
          }
        >
          {l.icon}
          {l.label}
        </NavLink>
      ))}
    </nav>
  );

  const sidebar = (
    <div className="flex h-full flex-col gap-6 p-4">
      <div className="flex items-center justify-between px-1">
        <Logo />
        <button className="btn-ghost p-1.5 lg:hidden" onClick={() => setMenu(false)} aria-label="Close menu">
          <X className="h-5 w-5" />
        </button>
      </div>
      {canUpload && (
        <button className="btn-primary w-full" onClick={() => setUpload(true)}>
          <Upload className="h-4 w-4" /> Upload document
        </button>
      )}
      {nav}
      <div className="mt-auto space-y-3">
        {user.isDemo && (
          <div className="rounded-xl bg-amber-50 p-3 text-xs text-amber-800 ring-1 ring-amber-200 dark:bg-amber-950/30 dark:text-amber-200 dark:ring-amber-900">
            You are in the <strong>demo workspace</strong>. Anyone can sign in to demo accounts, so they are walled off from real ones.
          </div>
        )}
        <div className="flex items-center gap-3 rounded-xl border border-slate-200 p-2.5 dark:border-slate-800">
          <Avatar name={user.name} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold">{user.name}</div>
            <div className="truncate text-xs capitalize text-slate-500">{user.role}</div>
          </div>
          <button className="btn-ghost p-1.5" onClick={toggleDark} aria-label="Toggle dark mode" title="Toggle theme">
            {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            className="btn-ghost p-1.5"
            aria-label="Sign out"
            title="Sign out"
            onClick={async () => {
              await logout();
              navigate('/');
            }}
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-slate-200 bg-white/70 backdrop-blur lg:block dark:border-slate-800 dark:bg-slate-950/60">{sidebar}</aside>
      {menu && (
        <div className="fixed inset-0 z-30 bg-slate-950/40 lg:hidden" onClick={() => setMenu(false)}>
          <aside className="h-full w-72 bg-white dark:bg-slate-950" onClick={(e) => e.stopPropagation()}>
            {sidebar}
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-slate-200 bg-white/80 px-4 py-3 backdrop-blur lg:hidden dark:border-slate-800 dark:bg-slate-950/80">
          <button className="btn-ghost p-1.5" onClick={() => setMenu(true)} aria-label="Open menu">
            <Menu className="h-5 w-5" />
          </button>
          <Logo />
          {canUpload && (
            <button className="btn-primary ml-auto px-3" onClick={() => setUpload(true)} aria-label="Upload">
              <Upload className="h-4 w-4" />
            </button>
          )}
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-8 sm:py-8">{children}</main>
      </div>
      <UploadDialog open={upload} onClose={() => setUpload(false)} />
    </div>
  );
}
