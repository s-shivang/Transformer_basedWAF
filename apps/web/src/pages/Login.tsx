import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ThemeToggle } from '../components/common/ThemeToggle';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login({ email, password });
      navigate('/');
    } catch (err: any) {
      setError(err.message || 'Failed to authenticate. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex flex-col justify-center items-center p-4 bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-50 relative">
      <div className="absolute top-6 right-6">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md bg-white dark:bg-[#111827] rounded-xl border border-slate-200 dark:border-[#1F2937] p-8 shadow-sm">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-blue-600 dark:bg-blue-500 flex items-center justify-center mb-3 shadow-md">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight">Transformer WAF SOC</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Sign in to your enterprise security operations center
          </p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-lg bg-red-50 dark:bg-red-500/15 border border-red-200 dark:border-red-500/30 flex items-center gap-2.5 text-xs text-red-700 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              Work Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@enterprise.com"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm transition-colors shadow-sm disabled:opacity-50 mt-2"
          >
            {loading ? 'Authenticating...' : 'Sign In to Dashboard'}
          </button>
        </form>

        <div className="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
          Need a tenant account?{' '}
          <Link to="/register" className="text-blue-600 dark:text-blue-400 font-medium hover:underline">
            Register new tenant
          </Link>
        </div>
      </div>
    </div>
  );
};
