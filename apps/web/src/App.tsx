import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppShell } from './components/layout/AppShell';

// Code-split pages for instant initial bundle loading
const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })));
const Register = lazy(() => import('./pages/Register').then(m => ({ default: m.Register })));
const Overview = lazy(() => import('./pages/Overview').then(m => ({ default: m.Overview })));
const Events = lazy(() => import('./pages/Events').then(m => ({ default: m.Events })));
const Sites = lazy(() => import('./pages/Sites').then(m => ({ default: m.Sites })));
const Policies = lazy(() => import('./pages/Policies').then(m => ({ default: m.Policies })));
const FeedbackPage = lazy(() => import('./pages/Feedback').then(m => ({ default: m.FeedbackPage })));
const TeamPage = lazy(() => import('./pages/Team').then(m => ({ default: m.TeamPage })));

const PageLoader: React.FC = () => (
  <div className="flex-1 p-8 flex items-center justify-center">
    <div className="flex items-center gap-3 text-zinc-500 dark:text-zinc-400">
      <div className="w-5 h-5 border-2 border-[#FF6600] border-t-transparent rounded-full animate-spin" />
      <span className="text-sm font-medium">Loading view...</span>
    </div>
  </div>
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 30000,
      retry: 1,
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400">
        <div className="flex items-center gap-3">
          <div className="w-5 h-5 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm font-medium">Verifying Session...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <BrowserRouter>
            <Suspense fallback={<PageLoader />}>
              <Routes>
                {/* Public Auth Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />

                {/* Protected SOC Dashboard Routes */}
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <AppShell />
                    </ProtectedRoute>
                  }
                >
                  <Route index element={<Overview />} />
                  <Route path="events" element={<Events />} />
                  <Route path="sites" element={<Sites />} />
                  <Route path="policies" element={<Policies />} />
                  <Route path="feedback" element={<FeedbackPage />} />
                  <Route path="team" element={<TeamPage />} />
                </Route>

                {/* Fallback Catch-all */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
};

export default App;
