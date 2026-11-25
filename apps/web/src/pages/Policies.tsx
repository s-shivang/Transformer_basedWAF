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

  // 2. Fetch active policy
  const { data: activePolicy, isLoading: loadingPolicy } = useQuery({
    queryKey: ['active-policy', effectiveSiteId],
    queryFn: () => api.policies.getActive(effectiveSiteId!),
    enabled: !!effectiveSiteId,
  });

  // 3. Fetch policy version history
  const { data: policyHistory = [] } = useQuery({
    queryKey: ['policy-history', effectiveSiteId],
    queryFn: () => api.policies.getHistory(effectiveSiteId!),
    enabled: !!effectiveSiteId && activeTab === 'history',
  });

  // Populate form when active policy loads
  useEffect(() => {
    if (activePolicy) {
      setMode(activePolicy.mode || 'MONITOR');
      setMonitorThreshold(activePolicy.thresholds?.monitorThreshold ?? 0.05);
      setChallengeThreshold(activePolicy.thresholds?.challengeThreshold ?? 0.50);
      setBlockThreshold(activePolicy.thresholds?.blockThreshold ?? 0.85);
      setMlEnabled(activePolicy.mlEnabled ?? true);
      setRulesEnabled(activePolicy.rulesEnabled ?? true);
      setChallengeEnabled(activePolicy.challengeEnabled ?? true);
      setMlFailureMode(activePolicy.mlFailureMode || 'FAIL_OPEN');
      setExclusions(activePolicy.exclusions || []);
    }
  }, [activePolicy]);

  // Update Policy Mutation
  const updatePolicyMutation = useMutation({
    mutationFn: (payload: any) => api.policies.update(effectiveSiteId!, payload),
    onSuccess: (updated) => {
      setStatusMsg({
        type: 'success',
        text: `Policy successfully incremented to version v${updated.version}.`,
      });
      queryClient.invalidateQueries({ queryKey: ['active-policy', effectiveSiteId] });
      queryClient.invalidateQueries({ queryKey: ['policy-history', effectiveSiteId] });
    },
    onError: (err: any) => {
      setStatusMsg({ type: 'error', text: err.message || 'Failed to update policy' });
    },
  });

  // Rollback Mutation
  const rollbackMutation = useMutation({
    mutationFn: (targetVersion: number) => api.policies.rollback(effectiveSiteId!, targetVersion),
    onSuccess: (rolledBack) => {
      setStatusMsg({
        type: 'success',
        text: `1-Click Rollback complete: restored settings as active version v${rolledBack.version}.`,
      });
      setActiveTab('editor');
      queryClient.invalidateQueries({ queryKey: ['active-policy', effectiveSiteId] });
      queryClient.invalidateQueries({ queryKey: ['policy-history', effectiveSiteId] });
    },
    onError: (err: any) => {
      setStatusMsg({ type: 'error', text: err.message || 'Rollback failed' });
    },
  });

  const handleSavePolicy = (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);

    // Threshold validation: 0 < monitor < challenge < block <= 1
    if (!(monitorThreshold > 0 && monitorThreshold < challengeThreshold && challengeThreshold < blockThreshold && blockThreshold <= 1)) {
      setStatusMsg({
        type: 'error',
        text: 'Threshold ordering violated: 0.0 < monitor < challenge < block <= 1.0 required.',
      });
      return;
    }

    updatePolicyMutation.mutate({
      mode,
      monitorThreshold,
      challengeThreshold,
      blockThreshold,
      mlEnabled,
      rulesEnabled,
      challengeEnabled,
      mlFailureMode,
      exclusions,
    });
  };

  const handleAddExclusion = () => {
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
            <h1 className="text-xl font-bold tracking-tight">WAF Policy Studio</h1>
            {activePolicy && (
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-50 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400 border border-blue-200 dark:border-blue-500/30">
                Active v{activePolicy.version}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
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
            className="text-xs font-medium rounded-lg border px-3 py-2 bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            {sites.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.domain})
              </option>
            ))}
          </select>

          {/* Tab Switcher */}
          <div className="inline-flex rounded-lg p-0.5 bg-slate-100 dark:bg-[#090D16] border border-slate-200 dark:border-[#1F2937]">
            <button
              type="button"
              onClick={() => setActiveTab('editor')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5',
                activeTab === 'editor'
                  ? 'bg-white dark:bg-[#111827] text-blue-600 dark:text-blue-400 shadow-xs'
                  : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-100',
              )}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Studio</span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('history')}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5',
                activeTab === 'history'
                  ? 'bg-white dark:bg-[#111827] text-blue-600 dark:text-blue-400 shadow-xs'
                  : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-100',
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
            'p-3 rounded-lg text-xs flex items-center gap-2.5 border',
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
        <div className="p-3.5 rounded-lg bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 flex items-start gap-3 text-xs text-amber-800 dark:text-amber-300">
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
          <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs space-y-3">
            <h2 className="text-sm font-semibold tracking-tight">Inspection Mode</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              {modes.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  disabled={!canMutatePolicies}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    'p-3 rounded-lg border text-left transition-all flex flex-col justify-between',
                    mode === m.id
                      ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-500/10 ring-1 ring-blue-500'
                      : 'border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 hover:border-slate-300 dark:hover:border-slate-700',
                  )}
                >
                  <div className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 mb-1">
                    {m.label}
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">
                    {m.desc}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Section 2: Interactive 4-Band Risk Threshold Bar */}
          <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs space-y-4">
            <div>
              <h2 className="text-sm font-semibold tracking-tight">Risk Decision Bands & Thresholds</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Tune the ML confidence thresholds that govern Fast-Pass Allow, Monitor Alert, Challenge, and Block.
              </p>
            </div>

            {/* Visual Segmented 4-Band Bar */}
            <div className="h-6 w-full rounded-lg overflow-hidden flex font-mono text-[11px] font-bold text-white shadow-inner">
              <div
                className="bg-emerald-500 flex items-center justify-center transition-all"
                style={{ width: `${monitorThreshold * 100}%` }}
              >
                Fast-Pass
              </div>
              <div
                className="bg-cyan-500 flex items-center justify-center transition-all"
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
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50"
                />
                <span className="text-[10px] text-slate-400 block mt-1">Default 0.05</span>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50"
                />
                <span className="text-[10px] text-slate-400 block mt-1">Default 0.50 (Gray zone start)</span>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                  className="w-full px-3 py-1.5 font-mono text-xs rounded-lg border bg-slate-50 dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937] text-slate-900 dark:text-slate-50"
                />
                <span className="text-[10px] text-slate-400 block mt-1">Default 0.85 (Hard block start)</span>
              </div>
            </div>
          </div>

          {/* Section 3: Feature Toggles & ML Failure Mode */}
          <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs space-y-4">
            <h2 className="text-sm font-semibold tracking-tight">Inspection Modules & Failsafe Options</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <label className="flex items-center gap-2.5 p-3 rounded-lg border border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={mlEnabled}
                  onChange={(e) => setMlEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="text-xs font-medium">Layer 2 ML Engine</span>
              </label>

              <label className="flex items-center gap-2.5 p-3 rounded-lg border border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rulesEnabled}
                  onChange={(e) => setRulesEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="text-xs font-medium">Layer 1 Regex Rules</span>
              </label>

              <label className="flex items-center gap-2.5 p-3 rounded-lg border border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={challengeEnabled}
                  onChange={(e) => setChallengeEnabled(e.target.checked)}
                  disabled={!canMutatePolicies}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="text-xs font-medium">PoW Human Challenge</span>
              </label>

              <div className="p-3 rounded-lg border border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50">
                <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                  ML Failure Mode
                </label>
                <select
                  value={mlFailureMode}
                  onChange={(e) => setMlFailureMode(e.target.value)}
                  disabled={!canMutatePolicies}
                  className="w-full text-xs font-mono rounded border p-1 bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937]"
                >
                  <option value="FAIL_OPEN">FAIL_OPEN (Pass traffic on ML outage)</option>
                  <option value="FAIL_CLOSED">FAIL_CLOSED (Block on ML outage)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Section 4: Scoped Exclusions Editor */}
          <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold tracking-tight">Scoped Path / Parameter Exclusions</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
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
                    className="p-3 rounded-lg border border-slate-200 dark:border-[#1F2937] bg-slate-50/50 dark:bg-[#090D16]/50 flex items-center justify-between text-xs"
                  >
                    <div className="flex flex-col gap-0.5">
                      <div className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                        {exc.pathPrefix}
                        {exc.parameterName && (
                          <span className="text-blue-600 dark:text-blue-400 font-normal ml-2">
                            param: {exc.parameterName}
                          </span>
                        )}
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 text-[11px]">{exc.reason}</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                        {exc.skipMl ? 'Skip ML' : ''} {exc.skipRules ? 'Skip Rules' : ''}
                      </span>
                      {canMutatePolicies && (
                        <button
                          type="button"
                          onClick={() => handleRemoveExclusion(idx)}
                          className="p-1 text-slate-400 hover:text-red-500 rounded"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-4 text-center text-xs text-slate-400 italic">
                No active exclusions. Narrow, justified exclusions can be added below.
              </div>
            )}

            {/* Add Exclusion Form */}
            {canMutatePolicies && (
              <div className="p-3.5 rounded-lg border border-dashed border-slate-300 dark:border-[#1F2937] space-y-3 bg-slate-50/30 dark:bg-transparent">
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">
                  Add Narrow Scoped Exclusion
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <input
                    type="text"
                    placeholder="/api/v1/webhooks"
                    value={newPathPrefix}
                    onChange={(e) => setNewPathPrefix(e.target.value)}
                    className="px-3 py-1.5 text-xs font-mono rounded-lg border bg-white dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937]"
                  />
                  <input
                    type="text"
                    placeholder="payload (optional param)"
                    value={newParameterName}
                    onChange={(e) => setNewParameterName(e.target.value)}
                    className="px-3 py-1.5 text-xs font-mono rounded-lg border bg-white dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937]"
                  />
                  <input
                    type="text"
                    placeholder="Reason (>= 5 chars)"
                    value={newReason}
                    onChange={(e) => setNewReason(e.target.value)}
                    className="px-3 py-1.5 text-xs rounded-lg border bg-white dark:bg-[#090D16] border-slate-200 dark:border-[#1F2937]"
                  />
                </div>
                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-4 text-xs">
                    <label className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                      <input
                        type="checkbox"
                        checked={newSkipMl}
                        onChange={(e) => setNewSkipMl(e.target.checked)}
                      />
                      <span>Skip ML</span>
                    </label>
                    <label className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                      <input
                        type="checkbox"
                        checked={newSkipRules}
                        onChange={(e) => setNewSkipRules(e.target.checked)}
                      />
                      <span>Skip Rules</span>
                    </label>
                  </div>
                  <button
                    type="button"
                    onClick={handleAddExclusion}
                    className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-300 dark:hover:bg-slate-700 text-xs font-medium"
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
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs transition-colors shadow-sm disabled:opacity-50"
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
        <div className="p-5 rounded-xl border bg-white dark:bg-[#111827] border-slate-200 dark:border-[#1F2937] shadow-xs space-y-4">
          <div>
            <h2 className="text-sm font-semibold tracking-tight">Immutable Policy Audit Trail & Rollback</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Every policy update creates a new immutable version. Rolling back restores historical state as a new
              active version without erasing audit records.
            </p>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-[#1F2937]">
            {policyHistory.map((p: any) => (
              <div key={p.id} className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm text-slate-900 dark:text-slate-100">
                      Version v{p.version}
                    </span>
                    {p.isActive && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30">
                        CURRENT ACTIVE
                      </span>
                    )}
                    <span className="font-mono text-slate-500 dark:text-slate-400">Mode: {p.mode}</span>
                  </div>
                  <div className="text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                    Thresholds: {p.thresholds?.monitorThreshold} / {p.thresholds?.challengeThreshold} /{' '}
                    {p.thresholds?.blockThreshold} • {p.exclusions?.length || 0} exclusions
                  </div>
                  <div className="text-slate-400 text-[10px]">
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
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-[#1F2937] hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 font-medium text-xs transition-colors shrink-0"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-blue-500" />
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
