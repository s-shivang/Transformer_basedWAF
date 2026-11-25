import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, Building, User, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ThemeToggle } from '../components/common/ThemeToggle';

export const Register: React.FC = () => {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenantName, setTenantName] = useState('');
  const [tenantSlug, setTenantSlug] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  const handleSlugAuto = (name: string) => {
    setTenantName(name);
    setTenantSlug(
      name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, ''),
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await register({
        fullName,
        email,
        password,
        tenantName,
        tenantSlug,
      });
      navigate('/');
    } catch (err: any) {
      setError(err.message || 'Registration failed. Please check form values.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex flex-col justify-center items-center p-4 bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-50 relative">
      <div className="absolute top-6 right-6">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-lg bg-white dark:bg-[#111827] rounded-xl border border-slate-200 dark:border-[#1F2937] p-8 shadow-sm">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="w-12 h-12 rounded-xl bg-blue-600 dark:bg-blue-500 flex items-center justify-center mb-3 shadow-md">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight">Onboard New Tenant</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Create an enterprise tenant organization with full SOC dashboard access
          </p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-lg bg-red-50 dark:bg-red-500/15 border border-red-200 dark:border-red-500/30 flex items-center gap-2.5 text-xs text-red-700 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Your Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alice Smith"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Work Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="alice@acme.com"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Organization Name
              </label>
              <div className="relative">
                <Building className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  required
                  value={tenantName}
                  onChange={(e) => handleSlugAuto(e.target.value)}
                  placeholder="Acme Corp"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Tenant Slug
              </label>
              <input
                type="text"
                required
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value)}
                placeholder="acme-corp"
                className="w-full px-3 py-2 text-sm font-mono rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm transition-colors shadow-sm disabled:opacity-50 mt-4"
          >
            {loading ? 'Creating Tenant Workspace...' : 'Register & Launch Workspace'}
          </button>
        </form>

        <div className="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-600 dark:text-blue-400 font-medium hover:underline">
            Sign in
          </Link>
        </div>
      </div>
    </div>
  );
};
