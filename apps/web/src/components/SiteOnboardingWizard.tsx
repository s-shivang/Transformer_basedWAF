import React, { useState, useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  ArrowRight,
  RefreshCw,
  Sliders,
  ShieldCheck,
  Activity,
  Lock,
  Server,
  X,
  ExternalLink,
} from 'lucide-react';
import { api, OnboardingInstructions, OnboardingStatus, TenantDetails } from '../lib/api';
import { cn } from '../lib/utils';
import { useAuth } from '../context/AuthContext';

interface SiteOnboardingWizardProps {
  isOpen: boolean;
  onClose: () => void;
  initialSiteId?: string | null;
  onSuccess?: () => void;
}

const STEPS = [
  { id: 1, title: 'Details', description: 'Domain & Origin', icon: Globe },
  { id: 2, title: 'Ownership', description: 'DNS Challenge', icon: Shield },
  { id: 3, title: 'Gateway', description: 'Atomic Config', icon: Server },
  { id: 4, title: 'DNS Traffic', description: 'CNAME Routing', icon: Activity },
  { id: 5, title: 'TLS Ready', description: 'HTTPS / Cert', icon: Lock },
  { id: 6, title: 'Activation', description: 'Health & Live', icon: ShieldCheck },
];

export const SiteOnboardingWizard: React.FC<SiteOnboardingWizardProps> = ({
  isOpen,
  onClose,
  initialSiteId = null,
  onSuccess,
}) => {
  const { user, tenant, setSelectedSiteId } = useAuth();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [currentStep, setCurrentStep] = useState<number>(1);
  const [siteId, setSiteId] = useState<string | null>(initialSiteId);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Form State for Step 1
  const [name, setName] = useState('');
  const [domain, setDomain] = useState('');
  const [originUrl, setOriginUrl] = useState('');

  // Fetch Tenant quota
  const { data: tenantData } = useQuery<TenantDetails>({
    queryKey: ['tenant', user?.tenantId],
    queryFn: () => (user?.tenantId ? api.tenants.get(user.tenantId) : Promise.reject('No tenant')),
    enabled: !!user?.tenantId,
  });

  // Fetch existing sites to compute quota usage
  const { data: existingSites = [] } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  const maxSites = tenantData?.maxSites ?? 5;
  const usedSites = existingSites.length;
  const isQuotaFull = usedSites >= maxSites && !initialSiteId;

  // Fetch site onboarding status if siteId exists
  const { data: onboardingData, refetch: refetchOnboarding, isLoading: isFetchingStatus } = useQuery<OnboardingInstructions>({
    queryKey: ['site-onboarding', siteId],
    queryFn: () => (siteId ? api.sites.getOnboarding(siteId) : Promise.reject('No siteId')),
    enabled: !!siteId,
  });

  // Map status to step index
  useEffect(() => {
    if (initialSiteId) {
      setSiteId(initialSiteId);
    }
  }, [initialSiteId]);

  useEffect(() => {
    if (!onboardingData) return;

    setName(onboardingData.name || '');
    setDomain(onboardingData.domain || '');
    setOriginUrl(onboardingData.originUrl || '');

    const status = onboardingData.onboardingStatus;
    switch (status) {
      case 'PENDING_VERIFICATION':
        setCurrentStep(2);
        break;
      case 'VERIFIED':
      case 'CONFIGURING':
        setCurrentStep(3);
        break;
      case 'DNS_PENDING':
        setCurrentStep(4);
        break;
      case 'TLS_PENDING':
        setCurrentStep(5);
        break;
      case 'HEALTH_CHECK':
      case 'ACTIVE':
        setCurrentStep(6);
        break;
      case 'FAILED':
        setErrorMessage(onboardingData.lastError || 'Onboarding encountered an error.');
        setCurrentStep(2);
        break;
      default:
        break;
    }
  }, [onboardingData]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Step 1: Start Onboarding Mutation
  const startOnboardingMutation = useMutation({
    mutationFn: (data: { name: string; domain: string; originUrl: string }) =>
      api.sites.startOnboarding(data),
    onSuccess: (data) => {
      setSiteId(data.siteId);
      setCurrentStep(2);
      setErrorMessage(null);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Failed to start onboarding');
    },
  });

  // Step 2: Verify Domain Ownership Mutation
  const verifyDomainMutation = useMutation({
    mutationFn: (id: string) => api.sites.verifyDomain(id),
    onSuccess: (res) => {
      setErrorMessage(null);
      setCurrentStep(3);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Domain TXT verification failed. Please ensure the DNS TXT record is active.');
      refetchOnboarding();
    },
  });

  // Step 3: Configure Gateway Mutation
  const configureGatewayMutation = useMutation({
    mutationFn: (id: string) => api.sites.configureGateway(id),
    onSuccess: () => {
      setErrorMessage(null);
      setCurrentStep(4);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Gateway configuration sync failed');
      refetchOnboarding();
    },
  });

  // Step 4: Verify DNS Routing Mutation
  const verifyDnsRoutingMutation = useMutation({
    mutationFn: (id: string) => api.sites.verifyDnsRouting(id),
    onSuccess: () => {
      setErrorMessage(null);
      setCurrentStep(5);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Traffic routing verification failed. Ensure CNAME / A record points to WAF edge.');
      refetchOnboarding();
    },
  });

  // Step 5: Provision TLS Mutation
  const provisionTlsMutation = useMutation({
    mutationFn: (id: string) => api.sites.provisionTls(id),
    onSuccess: () => {
      setErrorMessage(null);
      setCurrentStep(6);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'TLS provisioning failed');
      refetchOnboarding();
    },
  });

  // Step 6: Activate Site Mutation
  const activateMutation = useMutation({
    mutationFn: (id: string) => api.sites.activate(id),
    onSuccess: () => {
      setErrorMessage(null);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      if (onSuccess) onSuccess();
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Site activation failed during origin health check.');
      refetchOnboarding();
    },
  });

  // Retry Mutation
  const retryMutation = useMutation({
    mutationFn: (targetStatus?: OnboardingStatus) => {
      if (!siteId) throw new Error('No site to retry');
      return api.sites.retryOnboarding(siteId, targetStatus);
    },
    onSuccess: (data) => {
      setErrorMessage(null);
      refetchOnboarding();
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
    onError: (err: any) => {
      setErrorMessage(err.message || 'Failed to retry setup');
    },
  });

  if (!isOpen) return null;

  const isFailed = onboardingData?.onboardingStatus === 'FAILED';
  const isActive = onboardingData?.onboardingStatus === 'ACTIVE';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-3xl max-h-[92vh] flex flex-col rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-2xl overflow-hidden text-[#0A0A0A] dark:text-white"
        role="dialog"
        aria-modal="true"
        aria-labelledby="wizard-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/75 dark:bg-[#111111]/75">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-[#FF6600]/20 to-[#EA580C]/20 border border-[#FF6600]/30 flex items-center justify-center text-[#FF6600]">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h2 id="wizard-title" className="text-base font-bold text-[#0A0A0A] dark:text-white">
                Protect New Website
              </h2>
              <p className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                Multi-tenant reverse proxy onboarding with TLS readiness and atomic policy distribution
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white hover:bg-[#F3F4F6] dark:hover:bg-[#1C1C1C] transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stepper Bar */}
        <div className="px-6 py-3 border-b border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/30 dark:bg-[#0A0A0A]">
          <div className="grid grid-cols-6 gap-2">
            {STEPS.map((s) => {
              const Icon = s.icon;
              const isCompleted = currentStep > s.id || isActive;
              const isCurrent = currentStep === s.id && !isActive;

              return (
                <div
                  key={s.id}
                  className={cn(
                    'flex flex-col items-center text-center p-1.5 rounded-lg border transition-all',
                    isCurrent
                      ? 'border-[#FF6600] bg-[#FF6600]/10 text-[#FF6600]'
                      : isCompleted
                      ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400'
                      : 'border-transparent text-[#71717A] dark:text-[#71717A]',
                  )}
                >
                  <div className="flex items-center justify-center w-6 h-6 rounded-full mb-1">
                    {isCompleted ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    ) : (
                      <Icon className="w-4 h-4" />
                    )}
                  </div>
                  <span className="text-[11px] font-semibold leading-tight line-clamp-1">{s.title}</span>
                  <span className="text-[9px] text-[#A1A1AA] dark:text-[#71717A] hidden sm:block">
                    {s.description}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Error Banner */}
        {errorMessage && (
          <div className="mx-6 mt-4 p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400 text-xs flex items-start justify-between gap-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Action Required</p>
                <p className="mt-0.5 text-[11px]">{errorMessage}</p>
              </div>
            </div>
            {isFailed && (
              <button
                type="button"
                onClick={() => retryMutation.mutate()}
                disabled={retryMutation.isPending}
                className="px-2.5 py-1 rounded bg-rose-600 text-white font-medium hover:bg-rose-700 transition-colors shrink-0 text-xs flex items-center gap-1"
              >
                <RefreshCw className={cn('w-3 h-3', retryMutation.isPending && 'animate-spin')} />
                Retry Setup
              </button>
            )}
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* STEP 1: Website Details */}
          {currentStep === 1 && (
            <form
              id="wizard-step-1"
              onSubmit={(e) => {
                e.preventDefault();
                setErrorMessage(null);
                startOnboardingMutation.mutate({ name, domain, originUrl });
              }}
              className="space-y-4"
            >
              {/* Quota Indicator */}
              <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 flex items-center justify-between text-xs">
                <span className="text-[#71717A] dark:text-[#A1A1AA]">
                  Protected Site Quota Usage:
                </span>
                <span
                  className={cn(
                    'font-mono font-bold px-2 py-0.5 rounded',
                    isQuotaFull
                      ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
                      : 'bg-[#FF6600]/10 text-[#FF6600]',
                  )}
                >
                  {usedSites} / {maxSites} Sites Used
                </span>
              </div>

              {isQuotaFull && (
                <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400 text-xs">
                  Your tenant has reached the maximum allowed site limit ({maxSites} sites). Please ask your Tenant Owner to expand the site quota under Team & Settings.
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold mb-1 text-[#0A0A0A] dark:text-white">
                  Friendly Website Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., E-Commerce Production API"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={isQuotaFull || startOnboardingMutation.isPending}
                  className="w-full px-3 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-[#222222] bg-white dark:bg-[#111111] focus:outline-none focus:border-[#FF6600] transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold mb-1 text-[#0A0A0A] dark:text-white">
                  Public Domain FQDN
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., api.company.com or shop.example.test"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value.trim().toLowerCase())}
                  disabled={isQuotaFull || startOnboardingMutation.isPending}
                  className="w-full px-3 py-2 rounded-xl text-xs font-mono border border-[#E5E7EB] dark:border-[#222222] bg-white dark:bg-[#111111] focus:outline-none focus:border-[#FF6600] transition-colors"
                />
                <p className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] mt-1">
                  Must be a normalized hostname without protocol or trailing paths.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold mb-1 text-[#0A0A0A] dark:text-white">
                  Upstream Origin URL
                </label>
                <input
                  type="url"
                  required
                  placeholder="e.g., http://10.0.0.15:8080 or https://internal-backend.aws:8443"
                  value={originUrl}
                  onChange={(e) => setOriginUrl(e.target.value.trim())}
                  disabled={isQuotaFull || startOnboardingMutation.isPending}
                  className="w-full px-3 py-2 rounded-xl text-xs font-mono border border-[#E5E7EB] dark:border-[#222222] bg-white dark:bg-[#111111] focus:outline-none focus:border-[#FF6600] transition-colors"
                />
                <p className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] mt-1">
                  Private origin addresses and SSRF link-local IPs (169.254.169.254) are strictly guarded at connection time.
                </p>
              </div>
            </form>
          )}

          {/* STEP 2: Verify Domain Ownership (DNS TXT) */}
          {currentStep === 2 && onboardingData && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-400 text-xs">
                To prevent domain hijacking, add the following <strong>TXT record</strong> at your DNS registrar / provider (Cloudflare, Route53, Namecheap, etc.) to verify ownership:
              </div>

              <div className="space-y-2">
                <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Record Type:</span>
                    <span className="font-bold text-[#0A0A0A] dark:text-white">TXT</span>
                  </div>
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Host / Name:</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-[#FF6600]">
                        {onboardingData.txtRecord?.host || `_waf-challenge.${onboardingData.domain}`}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(
                            onboardingData.txtRecord?.host || `_waf-challenge.${onboardingData.domain}`,
                            'txt-host',
                          )
                        }
                        className="p-1 rounded hover:bg-[#E5E7EB] dark:hover:bg-[#222222] text-[#71717A]"
                      >
                        {copiedKey === 'txt-host' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Verification Value:</span>
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold break-all text-[#0A0A0A] dark:text-white">
                        {onboardingData.verificationToken}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(onboardingData.verificationToken || '', 'txt-val')
                        }
                        className="p-1 rounded hover:bg-[#E5E7EB] dark:hover:bg-[#222222] text-[#71717A]"
                      >
                        {copiedKey === 'txt-val' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="text-right">
                <button
                  type="button"
                  onClick={() => siteId && verifyDomainMutation.mutate(siteId)}
                  disabled={verifyDomainMutation.isPending}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 shadow-md transition-all flex items-center gap-2 ml-auto"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', verifyDomainMutation.isPending && 'animate-spin')} />
                  <span>Verify Domain Ownership</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 3: Configure WAF Gateway */}
          {currentStep === 3 && onboardingData && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-[#FF6600]/20 bg-[#FF6600]/5 text-xs text-[#0A0A0A] dark:text-white">
                <p className="font-semibold text-[#FF6600]">Zero-Downtime Atomic Policy Distribution</p>
                <p className="mt-1 text-[#71717A] dark:text-[#A1A1AA]">
                  The WAF Gateway will be provisioned with an initial safe <strong>MONITOR</strong> policy and an active routing rule for <code>{onboardingData.domain}</code>. No gateway restart is required.
                </p>
              </div>

              <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Site Domain:</span>
                  <span className="font-mono font-bold">{onboardingData.domain}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Initial Mode:</span>
                  <span className="font-mono text-emerald-600 dark:text-emerald-400 font-semibold">MONITOR (Safe Passive)</span>
                </div>
                {onboardingData.gatewayAckVersion && (
                  <div className="flex justify-between">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Gateway Ack Version:</span>
                    <span className="font-mono font-bold text-[#FF6600]">v{onboardingData.gatewayAckVersion}</span>
                  </div>
                )}
              </div>

              <div className="text-right">
                <button
                  type="button"
                  onClick={() => siteId && configureGatewayMutation.mutate(siteId)}
                  disabled={configureGatewayMutation.isPending}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 shadow-md transition-all flex items-center gap-2 ml-auto"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', configureGatewayMutation.isPending && 'animate-spin')} />
                  <span>Sync Configuration to Gateway</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 4: Connect DNS Traffic */}
          {currentStep === 4 && onboardingData && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-indigo-500/20 bg-indigo-500/5 text-indigo-700 dark:text-indigo-400 text-xs">
                Point your domain traffic to the Transformer WAF Network by updating your DNS record:
              </div>

              <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Record Type:</span>
                  <span className="font-bold text-[#0A0A0A] dark:text-white">CNAME</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Host:</span>
                  <span className="font-bold text-[#FF6600]">{onboardingData.domain}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">Target:</span>
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold text-[#0A0A0A] dark:text-white">
                      {onboardingData.trafficRecord?.target || 'edge.waf-network.internal'}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(
                          onboardingData.trafficRecord?.target || 'edge.waf-network.internal',
                          'cname-target',
                        )
                      }
                      className="p-1 rounded hover:bg-[#E5E7EB] dark:hover:bg-[#222222] text-[#71717A]"
                    >
                      {copiedKey === 'cname-target' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="text-right">
                <button
                  type="button"
                  onClick={() => siteId && verifyDnsRoutingMutation.mutate(siteId)}
                  disabled={verifyDnsRoutingMutation.isPending}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 shadow-md transition-all flex items-center gap-2 ml-auto"
                >
                  <RefreshCw className={cn('w-3.5 h-3.5', verifyDnsRoutingMutation.isPending && 'animate-spin')} />
                  <span>Verify DNS Routing</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 5: HTTPS / TLS Readiness */}
          {currentStep === 5 && onboardingData && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl border border-purple-500/20 bg-purple-500/5 text-purple-700 dark:text-purple-400 text-xs">
                Zero-spend automatic TLS readiness metadata provisioning for end-to-end HTTPS encryption:
              </div>

              <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-[#71717A] dark:text-[#A1A1AA]">TLS Certificate Status:</span>
                  <span
                    className={cn(
                      'font-mono font-bold px-2 py-0.5 rounded text-[11px]',
                      onboardingData.tlsStatus === 'PROVISIONED'
                        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                        : 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
                    )}
                  >
                    {onboardingData.tlsStatus || 'PENDING'}
                  </span>
                </div>
                {onboardingData.tlsIssuer && (
                  <div className="flex justify-between">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Certificate Issuer:</span>
                    <span className="font-mono text-[#0A0A0A] dark:text-white">{onboardingData.tlsIssuer}</span>
                  </div>
                )}
                {onboardingData.tlsExpiresAt && (
                  <div className="flex justify-between">
                    <span className="text-[#71717A] dark:text-[#A1A1AA]">Expiration Date:</span>
                    <span className="font-mono text-[#0A0A0A] dark:text-white">
                      {new Date(onboardingData.tlsExpiresAt).toLocaleDateString()}
                    </span>
                  </div>
                )}
              </div>

              <div className="text-right">
                <button
                  type="button"
                  onClick={() => siteId && provisionTlsMutation.mutate(siteId)}
                  disabled={provisionTlsMutation.isPending}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 shadow-md transition-all flex items-center gap-2 ml-auto"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Provision TLS Certificate</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 6: Origin Health Check & Activate */}
          {currentStep === 6 && onboardingData && (
            <div className="space-y-4">
              {!isActive ? (
                <>
                  <div className="p-4 rounded-xl border border-[#FF6600]/20 bg-[#FF6600]/5 text-xs text-[#0A0A0A] dark:text-white">
                    <p className="font-semibold text-[#FF6600]">Pre-Activation Origin Health Probe</p>
                    <p className="mt-1 text-[#71717A] dark:text-[#A1A1AA]">
                      Before going live, the control plane will probe <code>{onboardingData.originUrl}</code> for HTTP reachability and verify that DNS rebinding SSRF protection passes.
                    </p>
                  </div>

                  <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/50 dark:bg-[#111111]/50 space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-[#71717A] dark:text-[#A1A1AA]">Origin Health:</span>
                      <span
                        className={cn(
                          'font-mono font-bold px-2 py-0.5 rounded text-[11px]',
                          onboardingData.originHealthStatus === 'HEALTHY'
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                            : 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
                        )}
                      >
                        {onboardingData.originHealthStatus || 'UNKNOWN'}
                      </span>
                    </div>
                  </div>

                  <div className="text-right">
                    <button
                      type="button"
                      onClick={() => siteId && activateMutation.mutate(siteId)}
                      disabled={activateMutation.isPending}
                      className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-emerald-600 to-teal-600 hover:brightness-110 shadow-md transition-all flex items-center gap-2 ml-auto"
                    >
                      <Activity className={cn('w-3.5 h-3.5', activateMutation.isPending && 'animate-spin')} />
                      <span>Test Origin & Activate Protection</span>
                    </button>
                  </div>
                </>
              ) : (
                <div className="p-6 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 text-center space-y-4">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center mx-auto">
                    <ShieldCheck className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-emerald-600 dark:text-emerald-400">
                      Protection ACTIVE!
                    </h3>
                    <p className="text-xs text-[#71717A] dark:text-[#A1A1AA] mt-1">
                      {onboardingData.domain} is actively guarded by the Transformer WAF data plane.
                    </p>
                  </div>

                  <div className="p-3 rounded-xl border border-emerald-500/20 bg-white dark:bg-[#0A0A0A] text-left text-xs space-y-2">
                    <div className="flex justify-between">
                      <span className="text-[#71717A] dark:text-[#A1A1AA]">Domain:</span>
                      <span className="font-mono font-bold text-[#0A0A0A] dark:text-white">{onboardingData.domain}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#71717A] dark:text-[#A1A1AA]">TLS Issuer:</span>
                      <span className="font-mono text-[#0A0A0A] dark:text-white">{onboardingData.tlsIssuer}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#71717A] dark:text-[#A1A1AA]">Origin Health:</span>
                      <span className="font-mono text-emerald-600 dark:text-emerald-400 font-bold">{onboardingData.originHealthStatus}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#71717A] dark:text-[#A1A1AA]">Activated At:</span>
                      <span className="font-mono text-[#0A0A0A] dark:text-white">
                        {onboardingData.activatedAt ? new Date(onboardingData.activatedAt).toLocaleString() : 'Just now'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center justify-center gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        if (siteId) {
                          setSelectedSiteId(siteId);
                          navigate(`/policies?siteId=${siteId}`);
                        }
                      }}
                      className="px-3.5 py-2 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-white dark:bg-[#111111] hover:bg-[#F3F4F6] dark:hover:bg-[#1A1A1A] text-xs font-semibold flex items-center gap-1.5 transition-colors"
                    >
                      <Sliders className="w-3.5 h-3.5 text-[#FF6600]" />
                      <span>WAF Policy Studio</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        onClose();
                        navigate('/events');
                      }}
                      className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md transition-all"
                    >
                      <Activity className="w-3.5 h-3.5" />
                      <span>Live Security Events</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB]/75 dark:bg-[#111111]/75 text-xs">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-xl border border-[#E5E7EB] dark:border-[#222222] hover:bg-[#F3F4F6] dark:hover:bg-[#161616] text-[#71717A] dark:text-[#A1A1AA] transition-colors"
          >
            {isActive ? 'Done' : 'Cancel'}
          </button>

          {currentStep === 1 && (
            <button
              type="submit"
              form="wizard-step-1"
              disabled={isQuotaFull || startOnboardingMutation.isPending}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 disabled:opacity-50 text-white font-semibold shadow-md transition-all"
            >
              <RefreshCw className={cn('w-3.5 h-3.5', startOnboardingMutation.isPending && 'animate-spin')} />
              <span>Continue to DNS Setup</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
