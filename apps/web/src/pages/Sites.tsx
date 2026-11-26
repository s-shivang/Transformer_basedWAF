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
  ExternalLink,
  Activity,
  ShieldCheck,
  RefreshCw,
  Server,
  Lock,
  Edit2,
  Check,
  X,
} from 'lucide-react';
import { api, ProtectedSiteSummary } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { SiteOnboardingWizard } from '../components/SiteOnboardingWizard';
import { cn } from '../lib/utils';

export const Sites: React.FC = () => {
  const { user, canManageSites, setSelectedSiteId } = useAuth();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const isOwner = user?.role === 'OWNER';

  // Wizard state
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [wizardSiteId, setWizardSiteId] = useState<string | null>(null);

  // Quota edit state (OWNER only)
  const [isEditingQuota, setIsEditingQuota] = useState(false);
  const [quotaInput, setQuotaInput] = useState<number>(10);
  const [quotaError, setQuotaError] = useState<string | null>(null);

  // Health checking state per site
  const [healthCheckingSiteId, setHealthCheckingSiteId] = useState<string | null>(null);
  const [healthMessage, setHealthMessage] = useState<{ siteId: string; text: string; healthy: boolean } | null>(null);

  // Fetch sites
  const { data: sites = [], isLoading } = useQuery<ProtectedSiteSummary[]>({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  // Fetch tenant info for quota
  const { data: tenantDetails } = useQuery({
    queryKey: ['tenant-details', user?.tenantId],
    queryFn: () => (user?.tenantId ? api.tenants.get(user.tenantId) : null),
    enabled: !!user?.tenantId,
  });

  const maxSites = tenantDetails?.maxSites ?? 10;
  const usedSites = sites.length;
  const isQuotaReached = usedSites >= maxSites;

  // Quota update mutation (OWNER only)
  const updateQuotaMutation = useMutation({
    mutationFn: (newMax: number) => {
      if (!user?.tenantId) throw new Error('No tenant ID');
      return api.tenants.updateQuota(user.tenantId, newMax);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-details', user?.tenantId] });
      setIsEditingQuota(false);
      setQuotaError(null);
    },
    onError: (err: any) => {
      setQuotaError(err.message || 'Failed to update quota');
    },
  });

  // Toggle status mutation (ACTIVE / PAUSED)
  const toggleStatusMutation = useMutation({
    mutationFn: (data: { siteId: string; status: 'ACTIVE' | 'PAUSED' }) => {
      if (data.status === 'PAUSED') {
        return api.sites.pause(data.siteId);
      } else {
        return api.sites.resume(data.siteId);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
  });

  // Delete site mutation
  const deleteSiteMutation = useMutation({
    mutationFn: (siteId: string) => api.sites.delete(siteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
  });

  // Health check mutation
  const checkHealthMutation = useMutation({
    mutationFn: (siteId: string) => {
      setHealthCheckingSiteId(siteId);
      return api.sites.checkHealth(siteId);
    },
    onSuccess: (data, siteId) => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setHealthCheckingSiteId(null);
      setHealthMessage({
        siteId,
        text: data.healthy
          ? `Origin healthy (${data.latencyMs}ms, HTTP ${data.statusCode || 200})`
          : `Origin unreachable: ${data.error || 'Connection failed'}`,
        healthy: data.healthy,
      });
      setTimeout(() => setHealthMessage(null), 5000);
    },
    onError: (err: any, siteId) => {
      setHealthCheckingSiteId(null);
      setHealthMessage({
        siteId,
        text: `Health check error: ${err.message}`,
        healthy: false,
      });
      setTimeout(() => setHealthMessage(null), 5000);
    },
  });

  const handleOpenPolicy = (siteId: string) => {
    setSelectedSiteId(siteId);
    navigate(`/policies?siteId=${siteId}`);
  };

  const handleOpenNewWizard = () => {
    setWizardSiteId(null);
    setIsWizardOpen(true);
  };

  const handleResumeSetup = (siteId: string) => {
    setWizardSiteId(siteId);
    setIsWizardOpen(true);
  };

  const handleSaveQuota = (e: React.FormEvent) => {
    e.preventDefault();
    if (quotaInput < 1 || quotaInput > 100) {
      setQuotaError('Quota must be between 1 and 100');
      return;
    }
    updateQuotaMutation.mutate(quotaInput);
  };

  const getStatusBadge = (s: ProtectedSiteSummary) => {
    const status = s.onboardingStatus || s.status;
    switch (status) {
      case 'ACTIVE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            ACTIVE
          </span>
        );
      case 'PAUSED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-50 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400 border border-amber-500/20">
            PAUSED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400 border border-red-500/20">
            FAILED
          </span>
        );
      case 'PENDING_VERIFICATION':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400 border border-blue-500/20">
            VERIFY TXT
          </span>
        );
      case 'DNS_PENDING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-cyan-50 text-cyan-700 dark:bg-cyan-500/15 dark:text-cyan-400 border border-cyan-500/20">
            DNS PENDING
          </span>
        );
      case 'TLS_PENDING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-purple-50 text-purple-700 dark:bg-purple-500/15 dark:text-purple-400 border border-purple-500/20">
            TLS PENDING
          </span>
        );
      case 'HEALTH_CHECK':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-orange-50 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400 border border-orange-500/20">
            HEALTH CHECK
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
            {status}
          </span>
        );
    }
  };

  const getTlsBadge = (tlsStatus?: string) => {
    switch (tlsStatus) {
      case 'PROVISIONED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" title="Valid TLS Certificate">
            <Lock className="w-3 h-3" /> TLS Active
          </span>
        );
      case 'PENDING':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-purple-500/10 text-purple-600 dark:text-purple-400">
            <Lock className="w-3 h-3 animate-spin" /> Provisioning
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-red-500/10 text-red-600 dark:text-red-400">
            TLS Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-[#71717A] dark:text-[#A1A1AA]">
            None
          </span>
        );
    }
  };

  const getHealthBadge = (healthStatus?: string) => {
    switch (healthStatus) {
      case 'HEALTHY':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <Activity className="w-3 h-3 text-emerald-500" /> Healthy
          </span>
        );
      case 'UNHEALTHY':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-red-500/10 text-red-600 dark:text-red-400">
            <Activity className="w-3 h-3 text-red-500" /> Unhealthy
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-[#71717A] dark:text-[#A1A1AA]">
            Unknown
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Quota Card */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0A0A0A] dark:text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-[#FF6600]" />
            <span>Protected Sites</span>
          </h1>
          <p className="text-sm text-[#71717A] dark:text-[#A1A1AA] mt-1">
            Dynamic host-based WAF endpoints safeguarded with DNS-rebinding protection and zero-restart config synchronization.
          </p>
        </div>

        {canManageSites && (
          <button
            type="button"
            onClick={handleOpenNewWizard}
            disabled={isQuotaReached}
            className={cn(
              'inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl font-medium text-xs transition-all',
              isQuotaReached
                ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-400 dark:text-zinc-600 cursor-not-allowed'
                : 'bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 text-white shadow-[0_0_15px_rgba(255,102,0,0.3)]',
            )}
            title={isQuotaReached ? 'Tenant site quota reached' : 'Start 6-step site onboarding'}
          >
            <Plus className="w-4 h-4" />
            <span>Protect New Website</span>
          </button>
        )}
      </div>

      {/* Quota Banner & Stats */}
      <div className="p-4 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-[#FF6600]/10 border border-[#FF6600]/20 text-[#FF6600] dark:text-[#FF8800]">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-semibold text-[#0A0A0A] dark:text-white flex items-center gap-2">
              <span>Tenant Site Quota:</span>
              <span className="font-mono text-[#FF6600] dark:text-[#FF8800]">
                {usedSites} / {maxSites} Sites Used
              </span>
              {isQuotaReached && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                  QUOTA REACHED
                </span>
              )}
            </div>
            <p className="text-[11px] text-[#71717A] dark:text-[#A1A1AA] mt-0.5">
              Each protected site receives isolated per-site WAF threshold execution and origin health probing.
            </p>
          </div>
        </div>

        {/* OWNER Quota Management */}
        {isOwner && (
          <div className="flex items-center gap-2">
            {isEditingQuota ? (
              <form onSubmit={handleSaveQuota} className="flex items-center gap-2">
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={quotaInput}
                  onChange={(e) => setQuotaInput(parseInt(e.target.value) || 1)}
                  className="w-20 px-2.5 py-1 text-xs font-mono rounded-lg border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                />
                <button
                  type="submit"
                  disabled={updateQuotaMutation.isPending}
                  className="p-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs disabled:opacity-50"
                  title="Save Quota"
                >
                  <Check className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setIsEditingQuota(false);
                    setQuotaError(null);
                  }}
                  className="p-1.5 rounded-lg border border-[#E5E7EB] dark:border-[#222222] text-[#71717A] hover:bg-zinc-100 dark:hover:bg-zinc-800"
                  title="Cancel"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </form>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setQuotaInput(maxSites);
                  setIsEditingQuota(true);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[#E5E7EB] dark:border-[#222222] hover:border-[#FF6600]/40 text-xs font-medium text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white transition-colors"
              >
                <Edit2 className="w-3.5 h-3.5 text-[#FF6600]" />
                <span>Edit Site Quota</span>
              </button>
            )}
          </div>
        )}
      </div>

      {quotaError && (
        <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-xs text-red-600 dark:text-red-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{quotaError}</span>
        </div>
      )}

      {/* Sites Table */}
      <div className="rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 text-[#71717A] dark:text-[#A1A1AA] font-medium">
                <th className="py-3 px-4">Site Name</th>
                <th className="py-3 px-4 font-mono">Domain FQDN</th>
                <th className="py-3 px-4 font-mono">Origin URL</th>
                <th className="py-3 px-3">Onboarding Status</th>
                <th className="py-3 px-3">TLS</th>
                <th className="py-3 px-3">Origin Health</th>
                <th className="py-3 px-3 font-mono">Gateway ACK</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#222222]">
              {sites.length > 0 ? (
                sites.map((s) => {
                  const isActive = s.status === 'ACTIVE' && (!s.onboardingStatus || s.onboardingStatus === 'ACTIVE');
                  const isPaused = s.status === 'PAUSED' || s.onboardingStatus === 'PAUSED';
                  const isSetupComplete = isActive || isPaused;

                  return (
                    <tr key={s.id} className="hover:bg-[#F3F4F6] dark:hover:bg-[#161616] transition-colors">
                      <td className="py-3.5 px-4 font-semibold text-[#0A0A0A] dark:text-white">
                        <div>{s.name}</div>
                        {healthMessage && healthMessage.siteId === s.id && (
                          <div
                            className={cn(
                              'text-[10px] mt-1 font-mono',
                              healthMessage.healthy
                                ? 'text-emerald-600 dark:text-emerald-400'
                                : 'text-red-600 dark:text-red-400',
                            )}
                          >
                            {healthMessage.text}
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#FF6600] dark:text-[#FF8800] font-medium">
                        {s.domain}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#71717A] dark:text-[#A1A1AA]">
                        {s.originUrl}
                      </td>
                      <td className="py-3.5 px-3">
                        {getStatusBadge(s)}
                      </td>
                      <td className="py-3.5 px-3">
                        {getTlsBadge(s.tlsStatus)}
                      </td>
                      <td className="py-3.5 px-3">
                        {getHealthBadge(s.originHealthStatus)}
                      </td>
                      <td className="py-3.5 px-3 font-mono text-[#71717A] dark:text-[#A1A1AA]">
                        {s.gatewayAckVersion ? (
                          <span className="px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-[10px]">
                            v{s.gatewayAckVersion}
                          </span>
                        ) : (
                          <span className="text-[10px]">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Policy Studio */}
                          <button
                            type="button"
                            onClick={() => handleOpenPolicy(s.id)}
                            className="p-1.5 rounded text-[#71717A] dark:text-[#A1A1AA] hover:text-[#FF6600] dark:hover:text-[#FF8800] hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                            title="Open WAF Policy Studio"
                          >
                            <Sliders className="w-4 h-4" />
                          </button>

                          {/* Check Health action */}
                          {canManageSites && (
                            <button
                              type="button"
                              onClick={() => checkHealthMutation.mutate(s.id)}
                              disabled={healthCheckingSiteId === s.id}
                              className="p-1.5 rounded text-[#71717A] dark:text-[#A1A1AA] hover:text-cyan-500 hover:bg-[#F3F4F6] dark:hover:bg-[#161616] disabled:opacity-50"
                              title="Run On-Demand Origin Health Check"
                            >
                              <Activity className={cn('w-4 h-4', healthCheckingSiteId === s.id && 'animate-spin')} />
                            </button>
                          )}

                          {/* Resume Setup Button for Incomplete Sites */}
                          {canManageSites && !isSetupComplete && (
                            <button
                              type="button"
                              onClick={() => handleResumeSetup(s.id)}
                              className="px-2 py-1 rounded bg-[#FF6600]/10 hover:bg-[#FF6600]/20 text-[#FF6600] dark:text-[#FF8800] text-[11px] font-semibold border border-[#FF6600]/30 transition-colors"
                              title="Resume 6-step site onboarding"
                            >
                              Resume Setup
                            </button>
                          )}

                          {/* Pause / Resume for Completed Sites */}
                          {canManageSites && isSetupComplete && (
                            <button
                              type="button"
                              onClick={() =>
                                toggleStatusMutation.mutate({
                                  siteId: s.id,
                                  status: isActive ? 'PAUSED' : 'ACTIVE',
                                })
                              }
                              className="p-1.5 rounded text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                              title={isActive ? 'Pause WAF Protection' : 'Resume WAF Protection'}
                            >
                              {isActive ? (
                                <Pause className="w-4 h-4 text-amber-500" />
                              ) : (
                                <Play className="w-4 h-4 text-emerald-500" />
                              )}
                            </button>
                          )}

                          {/* Delete Site */}
                          {canManageSites && (
                            <button
                              type="button"
                              onClick={() => {
                                if (confirm(`Are you sure you want to delete ${s.domain}?`)) {
                                  deleteSiteMutation.mutate(s.id);
                                }
                              }}
                              className="p-1.5 rounded text-[#71717A] dark:text-[#A1A1AA] hover:text-red-600 dark:hover:text-red-400 hover:bg-[#F3F4F6] dark:hover:bg-[#161616]"
                              title="Delete Protected Site"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#71717A] dark:text-[#A1A1AA]">
                    {isLoading ? 'Loading protected sites...' : 'No protected sites registered yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 6-Step Site Onboarding Wizard Modal */}
      {isWizardOpen && (
        <SiteOnboardingWizard
          isOpen={isWizardOpen}
          initialSiteId={wizardSiteId}
          onClose={() => {
            setIsWizardOpen(false);
            setWizardSiteId(null);
          }}
          onSuccess={() => {
            setIsWizardOpen(false);
            setWizardSiteId(null);
            queryClient.invalidateQueries({ queryKey: ['sites'] });
            if (wizardSiteId) {
              setSelectedSiteId(wizardSiteId);
              navigate(`/policies?siteId=${wizardSiteId}`);
            }
          }}
        />
      )}
    </div>
  );
};
