import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Plus,
  Sliders,
  Trash2,
  Play,
  Pause,
  AlertCircle,
  X,
  ExternalLink,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { cn } from '../lib/utils';

export const Sites: React.FC = () => {
  const { canManageSites, setSelectedSiteId } = useAuth();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [domain, setDomain] = useState('');
  const [originUrl, setOriginUrl] = useState('');
  const [modalError, setModalError] = useState<string | null>(null);

  const { data: sites = [], isLoading } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  const createSiteMutation = useMutation({
    mutationFn: (data: { name: string; domain: string; originUrl: string }) =>
      api.sites.create(data),
    onSuccess: (newSite) => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setIsAddModalOpen(false);
      setName('');
      setDomain('');
      setOriginUrl('');
      setModalError(null);
    },
    onError: (err: any) => {
      setModalError(err.message || 'Failed to create protected site');
    },
  });

  const toggleStatusMutation = useMutation({
    mutationFn: (data: { siteId: string; status: 'ACTIVE' | 'PAUSED' }) =>
      api.sites.update(data.siteId, { status: data.status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sites'] }),
  });

  const deleteSiteMutation = useMutation({
    mutationFn: (siteId: string) => api.sites.delete(siteId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sites'] }),
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);
    createSiteMutation.mutate({ name, domain, originUrl });
  };

  const handleOpenPolicy = (siteId: string) => {
    setSelectedSiteId(siteId);
    navigate(`/policies?siteId=${siteId}`);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Protected Sites</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Domain endpoints safeguarded by Transformer WAF with automated reverse-proxy inspection
          </p>
        </div>

        {canManageSites && (
          <button
            type="button"
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs transition-colors shadow-xs"
          >
            <Plus className="w-4 h-4" />
            <span>Add Protected Site</span>
          </button>
        )}
      </div>

      {/* Sites Table */}
      <div className="rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 text-slate-500 dark:text-slate-400 font-medium">
                <th className="py-3 px-4">Site Name</th>
                <th className="py-3 px-4 font-mono">Domain FQDN</th>
                <th className="py-3 px-4 font-mono">Upstream Origin URL</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-[#1F2937]">
              {sites.length > 0 ? (
                sites.map((s: any) => (
                  <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-900 dark:text-slate-100">
                      {s.name}
                    </td>
                    <td className="py-3 px-4 font-mono text-blue-600 dark:text-blue-400 font-medium">
                      {s.domain}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-600 dark:text-slate-400">
                      {s.originUrl}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={cn(
                          'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold',
                          s.status === 'ACTIVE'
                            ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400'
                            : 'bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400',
                        )}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => handleOpenPolicy(s.id)}
                          className="p-1.5 rounded text-slate-600 dark:text-slate-300 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                          title="Open WAF Policy Studio"
                        >
                          <Sliders className="w-4 h-4" />
                        </button>

                        {canManageSites && (
                          <>
                            <button
                              type="button"
                              onClick={() =>
                                toggleStatusMutation.mutate({
                                  siteId: s.id,
                                  status: s.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE',
                                })
                              }
                              className="p-1.5 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                              title={s.status === 'ACTIVE' ? 'Pause WAF Protection' : 'Resume WAF Protection'}
                            >
                              {s.status === 'ACTIVE' ? (
                                <Pause className="w-4 h-4 text-amber-500" />
                              ) : (
                                <Play className="w-4 h-4 text-emerald-500" />
                              )}
                            </button>

                            <button
                              type="button"
                              onClick={() => {
                                if (confirm(`Are you sure you want to delete ${s.domain}?`)) {
                                  deleteSiteMutation.mutate(s.id);
                                }
                              }}
                              className="p-1.5 rounded text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                              title="Delete Protected Site"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-slate-400">
                    {isLoading ? 'Loading protected sites...' : 'No protected sites registered yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Protected Site Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md bg-white dark:bg-[#111827] rounded-xl border border-slate-200 dark:border-[#1F2937] p-6 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-[#1F2937] mb-4">
              <h2 className="text-sm font-bold tracking-tight">Register Protected Site</h2>
              <button
                type="button"
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {modalError && (
              <div className="mb-4 p-2.5 rounded-lg bg-red-50 dark:bg-red-500/15 border border-red-200 dark:border-red-500/30 text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{modalError}</span>
              </div>
            )}

            <form onSubmit={handleCreate} className="space-y-3.5">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Site Name
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Production API"
                  className="w-full px-3 py-2 text-xs rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Domain FQDN (Hostname)
                </label>
                <input
                  type="text"
                  required
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="api.example.com (no scheme, path, or port)"
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Upstream Origin URL
                </label>
                <input
                  type="url"
                  required
                  value={originUrl}
                  onChange={(e) => setOriginUrl(e.target.value)}
                  placeholder="https://backend-lb.internal.net:8443"
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-[10px] text-slate-400 block mt-1">
                  SSRF protected: Link-local metadata IPs (e.g. 169.254.169.254) are forbidden.
                </span>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-[#1F2937] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSiteMutation.isPending}
                  className="px-4 py-2 text-xs rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium transition-colors disabled:opacity-50"
                >
                  {createSiteMutation.isPending ? 'Provisioning...' : 'Provision v1 Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
