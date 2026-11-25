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
    <div className="min-h-screen w-screen flex flex-col justify-center items-center p-4 bg-[#F9FAFB] dark:bg-[#000000] text-[#0A0A0A] dark:text-[#FFFFFF] relative font-sans">
      <div className="absolute top-6 right-6">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-lg bg-white dark:bg-[#0A0A0A] rounded-2xl border border-[#E5E7EB] dark:border-[#222222] p-8 shadow-xl">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#FF6600] to-[#EA580C] flex items-center justify-center mb-3 shadow-[0_0_20px_rgba(255,102,0,0.35)]">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight">
            <span>Onboard New </span>
            <span className="text-[#FF6600]">Tenant</span>
          </h1>
          <p className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-1">
            Create an enterprise tenant organization with full threat intelligence access
          </p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-xl bg-red-50 dark:bg-red-500/15 border border-red-200 dark:border-red-500/30 flex items-center gap-2.5 text-xs text-red-700 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
                Your Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA] absolute left-3 top-3 pointer-events-none" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alice Smith"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
                Work Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA] absolute left-3 top-3 pointer-events-none" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="alice@acme.com"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
                />
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
              Master Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA] absolute left-3 top-3 pointer-events-none" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full pl-9 pr-3 py-2 text-sm rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
            <div>
              <label className="block text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
                Tenant Organization Name
              </label>
              <div className="relative">
                <Building className="w-4 h-4 text-[#71717A] dark:text-[#A1A1AA] absolute left-3 top-3 pointer-events-none" />
                <input
                  type="text"
                  required
                  value={tenantName}
                  onChange={(e) => handleSlugAuto(e.target.value)}
                  placeholder="Acme Corp"
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
                Tenant Slug (Subdomain identifier)
              </label>
              <input
                type="text"
                required
                pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value.toLowerCase())}
                placeholder="acme-corp"
                className="w-full px-3 py-2 text-sm font-mono rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-[#FF6600] focus:border-[#FF6600]"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 text-white font-medium text-sm transition-all shadow-[0_0_15px_rgba(255,102,0,0.3)] disabled:opacity-50 mt-4"
          >
            {loading ? 'Registering...' : 'Register & Launch Workspace'}
          </button>
        </form>

        <div className="mt-6 text-center text-xs text-[#71717A] dark:text-[#A1A1AA]">
          <span>Already have an account? </span>
          <Link to="/login" className="text-[#FF6600] hover:underline font-semibold">
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};
