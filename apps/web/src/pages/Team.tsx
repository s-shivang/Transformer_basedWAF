import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import {
  Users,
  UserPlus,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Mail,
  Calendar,
  Lock,
} from 'lucide-react';

export const TeamPage: React.FC = () => {
  const { user, canManageTeam } = useAuth();
  const queryClient = useQueryClient();
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'ADMIN' | 'ANALYST' | 'VIEWER'>('ANALYST');

  const {
    data: members,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['team-members', user?.tenantId],
    queryFn: () => (user?.tenantId ? api.team.listMembers(user.tenantId) : Promise.resolve([])),
    enabled: !!user?.tenantId,
  });

  const inviteMutation = useMutation({
    mutationFn: (data: { email: string; role: string }) => {
      if (!user?.tenantId) throw new Error('No active tenant selected');
      return api.team.addMember(user.tenantId, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['team-members', user?.tenantId] });
      setIsInviteOpen(false);
      setInviteEmail('');
      setInviteRole('ANALYST');
    },
  });

  const handleInviteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail) return;
    inviteMutation.mutate({ email: inviteEmail, role: inviteRole });
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'OWNER':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
            <ShieldCheck className="w-3.5 h-3.5" /> Tenant Owner
          </span>
        );
      case 'ADMIN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
            <Shield className="w-3.5 h-3.5" /> Security Admin
          </span>
        );
      case 'ANALYST':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
            <ShieldAlert className="w-3.5 h-3.5" /> SOC Analyst
          </span>
        );
      case 'VIEWER':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/20">
            <Eye className="w-3.5 h-3.5" /> Read-Only Viewer
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-indigo-500" />
            Team & Access Control (RBAC)
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Manage organization members, assign granular security roles, and enforce tenant access policies.
          </p>
        </div>
        {canManageTeam && (
          <button
            onClick={() => setIsInviteOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-500 shadow-sm transition-colors"
          >
            <UserPlus className="w-4 h-4" />
            Add Member
          </button>
        )}
      </div>

      {/* Role Permissions Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          {
            role: 'OWNER',
            desc: 'Full tenant ownership, billing, member deletion & all policies',
            color: 'border-purple-500/30',
          },
          {
            role: 'ADMIN',
            desc: 'Full WAF policy mutation, site provisioning, member invitations',
            color: 'border-indigo-500/30',
          },
          {
            role: 'ANALYST',
            desc: 'Investigate security events, submit false-positive feedback',
            color: 'border-blue-500/30',
          },
          {
            role: 'VIEWER',
            desc: 'Read-only access to overview dashboards, analytics, and events',
            color: 'border-slate-500/30',
          },
        ].map((item) => (
          <div
            key={item.role}
            className={`p-4 rounded-xl border bg-white dark:bg-slate-900 ${item.color} shadow-sm`}
          >
            <div className="text-xs font-bold tracking-wider uppercase text-slate-900 dark:text-white">
              {item.role}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {item.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Members Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 animate-pulse">
            Loading team members...
          </div>
        ) : error ? (
          <div className="p-8 text-center text-rose-500">
            Failed to load members: {(error as Error).message}
          </div>
        ) : !members || members.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            No team members found for this tenant.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-600 dark:text-slate-300">
              <thead className="bg-slate-50 dark:bg-slate-800/50 text-xs uppercase tracking-wider text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Email Address</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Joined Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {members.map((member: any) => (
                  <tr
                    key={member.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-900 dark:text-white">
                        {member.user?.fullName || 'Active User'}
                      </div>
                      <div className="text-xs text-slate-400 font-mono">
                        {member.userId}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-700 dark:text-slate-300">
                      {member.user?.email || 'N/A'}
                    </td>
                    <td className="py-3 px-4">{getRoleBadge(member.role)}</td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-xs text-slate-400">
                      {member.createdAt
                        ? new Date(member.createdAt).toLocaleDateString()
                        : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Member Modal */}
      {isInviteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-indigo-500" />
              Add Organization Member
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Add an existing registered user to this tenant with a designated RBAC permission tier.
            </p>

            <form onSubmit={handleInviteSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-1">
                  User Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                  <input
                    type="email"
                    required
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    placeholder="analyst@corp.io"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-1">
                  Role Tier
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) =>
                    setInviteRole(e.target.value as 'ADMIN' | 'ANALYST' | 'VIEWER')
                  }
                  className="w-full px-3 py-2 text-sm rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  <option value="ADMIN">ADMIN — Can modify policies & manage sites</option>
                  <option value="ANALYST">ANALYST — Can triage events & submit feedback</option>
                  <option value="VIEWER">VIEWER — Read-only observation access</option>
                </select>
              </div>

              {inviteMutation.isError && (
                <div className="p-3 text-xs rounded-lg bg-rose-500/10 text-rose-500 border border-rose-500/20">
                  {(inviteMutation.error as Error).message}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsInviteOpen(false)}
                  className="px-4 py-2 text-sm font-medium rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={inviteMutation.isPending}
                  className="px-4 py-2 text-sm font-semibold rounded-lg text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50"
                >
                  {inviteMutation.isPending ? 'Adding...' : 'Add Member'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
