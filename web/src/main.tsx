import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import './index.css';
import { SessionProvider, useSession, useTheme } from './session';
import { Spinner, ToastProvider } from './ui';
import Shell from './Shell';
import AuthPage from './pages/Auth';
import Documents from './pages/Documents';
import DocumentPage from './pages/DocumentPage';
import Trash from './pages/Trash';
import Admin from './pages/Admin';

function App() {
  useTheme();
  const { user, loading } = useSession();
  if (loading)
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner className="h-8 w-8" />
      </div>
    );
  if (!user) return <AuthPage />;
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Documents key="all" scope="all" />} />
        <Route path="/mine" element={<Documents key="mine" scope="mine" />} />
        <Route path="/shared" element={<Documents key="shared" scope="shared" />} />
        <Route path="/doc/:id" element={<DocumentPage />} />
        {user.role === 'owner' && <Route path="/trash" element={<Trash />} />}
        {user.role === 'admin' && <Route path="/admin" element={<Admin />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <SessionProvider>
          <App />
        </SessionProvider>
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>,
);
