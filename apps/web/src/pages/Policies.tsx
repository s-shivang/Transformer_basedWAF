import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import {
  Sliders,
  ShieldAlert,
  AlertTriangle,
  History,
  RotateCcw,
  Plus,
  Trash2,
  CheckCircle2,
  Save,
  Info,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { cn } from '../lib/utils';

export const Policies: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { canMutatePolicies, selectedSiteId, setSelectedSiteId } = useAuth();
  const queryClient = useQueryClient();

  // Active site selection
  const siteIdFromUrl = searchParams.get('siteId');
  const activeSiteId = siteIdFromUrl || selectedSiteId;

  // Active Tab: 'editor' | 'history'
  const [activeTab, setActiveTab] = useState<'editor' | 'history'>('editor');

  // Policy Form State
  const [mode, setMode] = useState<string>('MONITOR');
  const [monitorThreshold, setMonitorThreshold] = useState<number>(0.05);
  const [challengeThreshold, setChallengeThreshold] = useState<number>(0.50);
  const [blockThreshold, setBlockThreshold] = useState<number>(0.85);
  const [mlEnabled, setMlEnabled] = useState<boolean>(true);
  const [rulesEnabled, setRulesEnabled] = useState<boolean>(true);
  const [challengeEnabled, setChallengeEnabled] = useState<boolean>(true);
  const [mlFailureMode, setMlFailureMode] = useState<string>('FAIL_OPEN');
  const [exclusions, setExclusions] = useState<any[]>([]);

  // New exclusion inputs
  const [newPathPrefix, setNewPathPrefix] = useState<string>('');
  const [newParameterName, setNewParameterName] = useState<string>('');
  const [newReason, setNewReason] = useState<string>('');
  const [newSkipMl, setNewSkipMl] = useState<boolean>(true);
  const [newSkipRules, setNewSkipRules] = useState<boolean>(false);

  // Status feedback
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // 1. Fetch sites
  const { data: sites = [] } = useQuery({
    queryKey: ['sites'],
    queryFn: () => api.sites.list(),
  });

  const effectiveSiteId = activeSiteId || (sites.length > 0 ? sites[0].id : null);

  // 2. Fetch active policy for effective site
  const { data: activePolicy, isLoading: isLoadingPolicy } = useQuery({
    queryKey: ['policy-active', effectiveSiteId],
    queryFn: () => (effectiveSiteId ? api.policies.getActive(effectiveSiteId) : Promise.resolve(null)),
    enabled: !!effectiveSiteId,
  });

  // 3. Fetch policy version history
  const { data: policyHistory = [] } = useQuery({
    queryKey: ['policy-history', effectiveSiteId],
    queryFn: () => (effectiveSiteId ? api.policies.getHistory(effectiveSiteId) : Promise.resolve([])),
    enabled: !!effectiveSiteId && activeTab === 'history',
  });

  // Sync state when activePolicy loads or site changes
  useEffect(() => {
    if (activePolicy) {
      setMode(activePolicy.mode || 'MONITOR');
      if (activePolicy.thresholds) {
        setMonitorThreshold(activePolicy.thresholds.monitorThreshold ?? 0.05);
        setChallengeThreshold(activePolicy.thresholds.challengeThreshold ?? 0.50);
        setBlockThreshold(activePolicy.thresholds.blockThreshold ?? 0.85);
      }
      if (activePolicy.features) {
        setMlEnabled(activePolicy.features.mlEnabled ?? true);
        setRulesEnabled(activePolicy.features.rulesEnabled ?? true);
        setChallengeEnabled(activePolicy.features.challengeEnabled ?? true);
      }
      setMlFailureMode(activePolicy.mlFailureMode || 'FAIL_OPEN');
      setExclusions(activePolicy.exclusions || []);
    }
  }, [activePolicy]);

  // Mutation: Update Policy
  const updatePolicyMutation = useMutation({
    mutationFn: (newPolicyData: any) => {
      if (!effectiveSiteId) throw new Error('No site selected');
      return api.policies.update(effectiveSiteId, newPolicyData);
    },
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ['policy-active', effectiveSiteId] });
      queryClient.invalidateQueries({ queryKey: ['policy-history', effectiveSiteId] });
      setStatusMsg({
        type: 'success',
        text: `Policy v${updated.version} published and synced to WAF Gateway successfully!`,
      });
    },
    onError: (err: any) => {
      setStatusMsg({
        type: 'error',
        text: err.message || 'Failed to update policy',
      });
    },
  });

  // Mutation: Rollback Policy
  const rollbackMutation = useMutation({
    mutationFn: (targetVersion: number) => {
      if (!effectiveSiteId) throw new Error('No site selected');
      return api.policies.rollback(effectiveSiteId, targetVersion);
    },
    onSuccess: (restored) => {
      queryClient.invalidateQueries({ queryKey: ['policy-active', effectiveSiteId] });
      queryClient.invalidateQueries({ queryKey: ['policy-history', effectiveSiteId] });
      setStatusMsg({
        type: 'success',
        text: `Successfully rolled back to configuration of version v${restored.version}!`,
      });
      setActiveTab('editor');
    },
    onError: (err: any) => {
      setStatusMsg({
        type: 'error',
        text: err.message || 'Rollback failed',
      });
    },
  });

  const handleSavePolicy = (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    // Validation: Strict threshold ordering
    if (monitorThreshold >= challengeThreshold) {
      setStatusMsg({
        type: 'error',
        text: 'Validation Error: Monitor threshold must be strictly less than Challenge threshold.',
      });
      return;
    }
    if (challengeThreshold >= blockThreshold) {
      setStatusMsg({
        type: 'error',
        text: 'Validation Error: Challenge threshold must be strictly less than Block threshold.',
      });
      return;
    }

    updatePolicyMutation.mutate({
      mode,
      thresholds: {
        monitorThreshold,
        challengeThreshold,
        blockThreshold,
      },
      features: {
        mlEnabled,
        rulesEnabled,
        challengeEnabled,
      },
      mlFailureMode,
      exclusions,
    });
  };

  const handleAddExclusion = () => {
    if (!newPathPrefix) return;
    if (!newPathPrefix.startsWith('/')) {
      setStatusMsg({ type: 'error', text: 'Exclusion pathPrefix must start with a leading slash ("/")' });
      return;
    }
    if (newPathPrefix === '*' || newPathPrefix === '/*') {
      setStatusMsg({ type: 'error', text: 'Broad wildcard full-site bypass (*, /*) is forbidden.' });
      return;
    }
    if (!newReason || newReason.length < 5) {
      setStatusMsg({ type: 'error', text: 'Descriptive justification reason (>= 5 chars) is required.' });
      return;
    }

    setExclusions([
      ...exclusions,
      {
        pathPrefix: newPathPrefix,
        parameterName: newParameterName || undefined,
        reason: newReason,
        skipMl: newSkipMl,
        skipRules: newSkipRules,
      },
    ]);

    setNewPathPrefix('');
    setNewParameterName('');
    setNewReason('');
  };

  const handleRemoveExclusion = (index: number) => {
    setExclusions(exclusions.filter((_, i) => i !== index));
  };

  const modes = [
    { id: 'MONITOR', label: 'MONITOR', desc: 'Alert & log telemetry only; zero traffic blocked' },
    { id: 'CORROBORATED', label: 'CORROBORATED', desc: 'Block only when rules + ML model both agree' },
    { id: 'BLOCKING', label: 'BLOCKING', desc: 'Standard production blocking on high-confidence attacks' },
    { id: 'STRICT', label: 'STRICT', desc: 'Tightened challenge & lower block threshold' },
    { id: 'DISABLED', label: 'DISABLED', desc: 'Bypass all WAF inspection filters' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Header with Site Selector & Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-[#0A0A0A] dark:text-white">WAF Policy Studio</h1>
            {activePolicy && (
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-[#FF6600]/10 text-[#FF6600] dark:text-[#FF8800] border border-[#FF6600]/20">
                Active v{activePolicy.version}
              </span>
            )}
          </div>
          <p className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
            Per-site multi-layer inspection tuning, 4-band risk thresholds, and scoped exclusions
          </p>
        </div>

        {/* Site Switcher */}
        <div className="flex items-center gap-2">
          <select
            value={effectiveSiteId || ''}
            onChange={(e) => {
              setSelectedSiteId(e.target.value);
              setStatusMsg(null);
            }}
            className="text-xs font-medium rounded-xl border px-3 py-2 bg-white dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
          >
            {sites.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.domain})
              </option>
            ))}
          </select>

          {/* Tab Switcher */}
          <div className="inline-flex rounded-xl p-0.5 bg-[#F9FAFB] dark:bg-[#111111] border border-[#E5E7EB] dark:border-[#222222]">
            <button
              type="button"
              onClick={() => setActiveTab('editor')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5',
                activeTab === 'editor'
                  ? 'bg-gradient-to-r from-[#FF6600] to-[#EA580C] text-white shadow-[0_0_12px_rgba(255,102,0,0.3)]'
                  : 'text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white',
              )}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Studio</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('history')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5',
                activeTab === 'history'
                  ? 'bg-gradient-to-r from-[#FF6600] to-[#EA580C] text-white shadow-[0_0_12px_rgba(255,102,0,0.3)]'
                  : 'text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white',
              )}
            >
              <History className="w-3.5 h-3.5" />
              <span>Version History</span>
            </button>
          </div>
        </div>
      </div>

      {statusMsg && (
        <div
          className={cn(
            'p-3 rounded-xl text-xs flex items-center gap-2.5 border',
            statusMsg.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30'
              : 'bg-red-50 text-red-800 dark:bg-red-500/15 dark:text-red-400 border-red-200 dark:border-red-500/30',
          )}
        >
          {statusMsg.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-600" />
          )}
          <span>{statusMsg.text}</span>
        </div>
      )}

      {/* Mode Switch Warning Banner */}
      {(mode === 'BLOCKING' || mode === 'STRICT') && (
        <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 flex items-start gap-3 text-xs text-amber-800 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />
          <div>
            <strong className="font-semibold">Active Blocking Mode Enabled:</strong> High-confidence attack
            traffic scoring above <code className="font-mono font-bold">{blockThreshold.toFixed(2)}</code> will be
            actively blocked with an HTTP 403 Forbidden page. Ensure exclusions are configured for any known
            false positives.
          </div>
        </div>
      )}

      {/* TAB 1: POLICY EDITOR */}
      {activeTab === 'editor' && (
        <form onSubmit={handleSavePolicy} className="space-y-6">
          {/* Section 1: Visual Mode Selector Cards */}
          <div className="p-5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm space-y-3">
            <h2 className="text-sm font-semibold tracking-tight text-[#0A0A0A] dark:text-white">Inspection Mode</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              {modes.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  disabled={!canMutatePolicies}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    'p-3 rounded-xl border text-left transition-all flex flex-col justify-between',
                    mode === m.id
                      ? 'border-[#FF6600] bg-[#FFF7ED] dark:bg-[#FF6600]/10 ring-1 ring-[#FF6600]'
                      : 'border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111] hover:border-[#FF6600]/50',
                  )}
                >
                  <div className="font-mono text-xs font-bold text-[#0A0A0A] dark:text-white mb-1">
                    {m.label}
                  </div>
                  <div className="text-[11px] text-[#71717A] dark:text-[#A1A1AA] leading-snug">
                    {m.desc}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Section 2: Interactive 4-Band Risk Threshold Bar */}
          <div className="p-5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm space-y-4">
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-[#0A0A0A] dark:text-white">Risk Decision Bands & Thresholds</h2>
              <p className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                Tune the ML confidence thresholds that govern Fast-Pass Allow, Monitor Alert, Challenge, and Block.
              </p>
            </div>

            {/* Visual Segmented 4-Band Bar */}
            <div className="h-6 w-full rounded-xl overflow-hidden flex font-mono text-[11px] font-bold text-white shadow-inner">
              <div
                className="bg-emerald-500 flex items-center justify-center transition-all"
                style={{ width: `${monitorThreshold * 100}%` }}
              >
                Fast-Pass
              </div>
              <div
                className="bg-orange-500 flex items-center justify-center transition-all"
                style={{ width: `${(challengeThreshold - monitorThreshold) * 100}%` }}
              >
                Monitor
              </div>
              <div
                className="bg-amber-500 flex items-center justify-center transition-all"
                style={{ width: `${(blockThreshold - challengeThreshold) * 100}%` }}
              >
                Challenge
              </div>
              <div
                className="bg-red-500 flex items-center justify-center transition-all"
                style={{ width: `${(1.0 - blockThreshold) * 100}%` }}
              >
                Block
              </div>
            </div>

            {/* Numeric Threshold Inputs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  Monitor Threshold (tau_monitor)
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0.01"
                  max="0.98"
                  value={monitorThreshold}
                  onChange={(e) => setMonitorThreshold(parseFloat(e.target.value) || 0.05)}
                  disabled={!canMutatePolicies}
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                />
                <span className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] block mt-1">Default 0.05</span>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  Challenge Threshold (tau_challenge)
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0.02"
                  max="0.99"
                  value={challengeThreshold}
                  onChange={(e) => setChallengeThreshold(parseFloat(e.target.value) || 0.50)}
                  disabled={!canMutatePolicies}
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                />
                <span className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] block mt-1">Default 0.50 (Gray zone start)</span>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  Block Threshold (tau_block)
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0.03"
                  max="1.00"
                  value={blockThreshold}
                  onChange={(e) => setBlockThreshold(parseFloat(e.target.value) || 0.85)}
                  disabled={!canMutatePolicies}
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-xl border bg-[#F9FAFB] dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                />
                <span className="text-[10px] text-[#71717A] dark:text-[#A1A1AA] block mt-1">Default 0.85 (Hard block start)</span>
              </div>
            </div>
          </div>

          {/* Section 3: Feature Toggles & ML Failure Mode */}
          <div className="p-5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm space-y-4">
            <h2 className="text-sm font-semibold tracking-tight text-[#0A0A0A] dark:text-white">Inspection Modules & Failsafe Options</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <label className="flex items-center gap-2.5 p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111] cursor-pointer">
                <input
                  type="checkbox"
                  checked={mlEnabled}
                  onChange={(e) => setMlEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-[#FF6600] accent-[#FF6600] focus:ring-[#FF6600]"
                />
                <span className="text-xs font-medium text-[#0A0A0A] dark:text-white">Layer 2 ML Engine</span>
              </label>

              <label className="flex items-center gap-2.5 p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111] cursor-pointer">
                <input
                  type="checkbox"
                  checked={rulesEnabled}
                  onChange={(e) => setRulesEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-[#FF6600] accent-[#FF6600] focus:ring-[#FF6600]"
                />
                <span className="text-xs font-medium text-[#0A0A0A] dark:text-white">Layer 1 Regex Rules</span>
              </label>

              <label className="flex items-center gap-2.5 p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111] cursor-pointer">
                <input
                  type="checkbox"
                  checked={challengeEnabled}
                  onChange={(e) => setChallengeEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-[#FF6600] accent-[#FF6600] focus:ring-[#FF6600]"
                />
                <span className="text-xs font-medium text-[#0A0A0A] dark:text-white">PoW Human Challenge</span>
              </label>

              <div className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111]">
                <label className="block text-[11px] font-medium text-[#71717A] dark:text-[#A1A1AA] mb-1">
                  ML Failure Mode
                </label>
                <select
                  value={mlFailureMode}
                  onChange={(e) => setMlFailureMode(e.target.value)}
                  disabled={!canMutatePolicies}
                  className="w-full text-xs font-mono rounded-lg border p-1 bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                >
                  <option value="FAIL_OPEN">FAIL_OPEN (Pass traffic on ML outage)</option>
                  <option value="FAIL_CLOSED">FAIL_CLOSED (Block on ML outage)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Section 4: Scoped Exclusions Editor */}
          <div className="p-5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold tracking-tight text-[#0A0A0A] dark:text-white">Scoped Path / Parameter Exclusions</h2>
                <p className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
                  Targeted exceptions to suppress false alarms on third-party webhooks or binary payloads
                </p>
              </div>
            </div>

            {/* List of existing exclusions */}
            {exclusions.length > 0 ? (
              <div className="space-y-2">
                {exclusions.map((exc, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl border border-[#E5E7EB] dark:border-[#222222] bg-[#F9FAFB] dark:bg-[#111111] flex items-center justify-between text-xs"
                  >
                    <div className="flex flex-col gap-0.5">
                      <div className="font-mono font-semibold text-[#0A0A0A] dark:text-white">
                        {exc.pathPrefix}
                        {exc.parameterName && (
                          <span className="text-[#FF6600] dark:text-[#FF8800] font-normal ml-2">
                            param: {exc.parameterName}
                          </span>
                        )}
                      </div>
                      <div className="text-[#71717A] dark:text-[#A1A1AA] text-[11px]">{exc.reason}</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#E5E7EB] dark:bg-[#222222] text-zinc-700 dark:text-zinc-300">
                        {exc.skipMl ? 'Skip ML' : ''} {exc.skipRules ? 'Skip Rules' : ''}
                      </span>
                      {canMutatePolicies && (
                        <button
                          type="button"
                          onClick={() => handleRemoveExclusion(idx)}
                          className="p-1 text-[#71717A] hover:text-red-500 rounded"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-4 text-center text-xs text-[#71717A] dark:text-[#A1A1AA] italic">
                No active exclusions. Narrow, justified exclusions can be added below.
              </div>
            )}

            {/* Add Exclusion Form */}
            {canMutatePolicies && (
              <div className="p-3.5 rounded-xl border border-dashed border-[#E5E7EB] dark:border-[#222222] space-y-3 bg-[#F9FAFB]/50 dark:bg-transparent">
                <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 block">
                  Add Narrow Scoped Exclusion
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="/api/v1/webhooks"
                    value={newPathPrefix}
                    onChange={(e) => setNewPathPrefix(e.target.value)}
                    className="px-3 py-1.5 text-xs font-mono rounded-xl border bg-white dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                  />
                  <input
                    type="text"
                    placeholder="payload (optional param)"
                    value={newParameterName}
                    onChange={(e) => setNewParameterName(e.target.value)}
                    className="px-3 py-1.5 text-xs font-mono rounded-xl border bg-white dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                  />
                  <input
                    type="text"
                    placeholder="Reason (>= 5 chars)"
                    value={newReason}
                    onChange={(e) => setNewReason(e.target.value)}
                    className="px-3 py-1.5 text-xs rounded-xl border bg-white dark:bg-[#111111] border-[#E5E7EB] dark:border-[#222222] text-[#0A0A0A] dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF6600]"
                  />
                </div>
                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-4 text-xs">
                    <label className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                      <input
                        type="checkbox"
                        checked={newSkipMl}
                        onChange={(e) => setNewSkipMl(e.target.checked)}
                        className="accent-[#FF6600]"
                      />
                      <span>Skip ML</span>
                    </label>
                    <label className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                      <input
                        type="checkbox"
                        checked={newSkipRules}
                        onChange={(e) => setNewSkipRules(e.target.checked)}
                        className="accent-[#FF6600]"
                      />
                      <span>Skip Rules</span>
                    </label>
                  </div>
                  <button
                    type="button"
                    onClick={handleAddExclusion}
                    className="px-3 py-1.5 rounded-xl bg-[#E5E7EB] dark:bg-[#222222] text-[#0A0A0A] dark:text-white hover:bg-[#D1D5DB] dark:hover:bg-[#333333] text-xs font-medium transition-colors"
                  >
                    Add to Policy
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Save Policy Button */}
          {canMutatePolicies && (
            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={updatePolicyMutation.isPending}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#FF6600] to-[#EA580C] hover:brightness-110 text-white font-medium text-xs transition-all shadow-[0_0_15px_rgba(255,102,0,0.3)] disabled:opacity-50"
              >
                <Save className="w-4 h-4" />
                <span>{updatePolicyMutation.isPending ? 'Publishing Version...' : 'Publish New Policy Version'}</span>
              </button>
            </div>
          )}
        </form>
      )}

      {/* TAB 2: VERSION HISTORY & 1-CLICK ROLLBACK */}
      {activeTab === 'history' && (
        <div className="p-5 rounded-2xl border bg-white dark:bg-[#0A0A0A] border-[#E5E7EB] dark:border-[#222222] shadow-sm space-y-4">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-[#0A0A0A] dark:text-white">Immutable Policy Audit Trail & Rollback</h2>
            <p className="text-xs text-[#71717A] dark:text-[#A1A1AA]">
              Every policy update creates a new immutable version. Rolling back restores historical state as a new
              active version without erasing audit records.
            </p>
          </div>

          <div className="divide-y divide-[#E5E7EB] dark:divide-[#222222]">
            {policyHistory.map((p: any) => (
              <div key={p.id} className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm text-[#0A0A0A] dark:text-white">
                      Version v{p.version}
                    </span>
                    {p.isActive && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30">
                        CURRENT ACTIVE
                      </span>
                    )}
                    <span className="font-mono text-[#71717A] dark:text-[#A1A1AA]">Mode: {p.mode}</span>
                  </div>
                  <div className="text-[#71717A] dark:text-[#A1A1AA] font-mono text-[11px]">
                    Thresholds: {p.thresholds?.monitorThreshold} / {p.thresholds?.challengeThreshold} /{' '}
                    {p.thresholds?.blockThreshold} • {p.exclusions?.length || 0} exclusions
                  </div>
                  <div className="text-[#71717A] dark:text-[#A1A1AA] text-[10px]">
                    Created: {p.createdAt ? new Date(p.createdAt).toLocaleString() : '-'}
                  </div>
                </div>

                {!p.isActive && canMutatePolicies && (
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm(`Restore configuration from version v${p.version}?`)) {
                        rollbackMutation.mutate(p.version);
                      }
                    }}
                    disabled={rollbackMutation.isPending}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[#E5E7EB] dark:border-[#222222] hover:bg-[#F3F4F6] dark:hover:bg-[#161616] text-[#71717A] dark:text-[#A1A1AA] hover:text-[#0A0A0A] dark:hover:text-white font-medium text-xs transition-colors shrink-0"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-[#FF6600]" />
                    <span>Rollback to v{p.version}</span>
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
