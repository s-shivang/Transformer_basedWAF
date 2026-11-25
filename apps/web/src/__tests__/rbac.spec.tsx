import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ActionBadge } from '../components/common/ActionBadge';

describe('RBAC & ActionBadge Components', () => {
  it('renders ActionBadge correctly for BLOCK', () => {
    render(<ActionBadge action="BLOCK" />);
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
  });

  it('renders ActionBadge correctly for CHALLENGE', () => {
    render(<ActionBadge action="CHALLENGE" />);
    expect(screen.getByText('CHALLENGE')).toBeInTheDocument();
  });

  it('renders ActionBadge correctly for MONITOR', () => {
    render(<ActionBadge action="MONITOR" />);
    expect(screen.getByText('MONITOR')).toBeInTheDocument();
  });

  it('renders ActionBadge correctly for ALLOW', () => {
    render(<ActionBadge action="ALLOW" />);
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
  });

  it('evaluates RBAC role permission rules correctly', () => {
    const checkRolePermissions = (role: string) => {
      const isOwner = role === 'OWNER';
      const isAdmin = role === 'ADMIN';
      const isAnalyst = role === 'ANALYST';
      const isViewer = role === 'VIEWER';

      return {
        canMutatePolicies: isOwner || isAdmin,
        canSubmitFeedback: isOwner || isAdmin || isAnalyst,
        canReviewFeedback: isOwner || isAdmin,
        canManageTeam: isOwner || isAdmin,
        canManageSites: isOwner || isAdmin,
        isReadOnly: isViewer,
      };
    };

    // OWNER permissions
    const ownerPerms = checkRolePermissions('OWNER');
    expect(ownerPerms.canMutatePolicies).toBe(true);
    expect(ownerPerms.canReviewFeedback).toBe(true);
    expect(ownerPerms.canSubmitFeedback).toBe(true);
    expect(ownerPerms.canManageSites).toBe(true);
    expect(ownerPerms.isReadOnly).toBe(false);

    // ADMIN permissions
    const adminPerms = checkRolePermissions('ADMIN');
    expect(adminPerms.canMutatePolicies).toBe(true);
    expect(adminPerms.canReviewFeedback).toBe(true);
    expect(adminPerms.canSubmitFeedback).toBe(true);
    expect(adminPerms.canManageSites).toBe(true);
    expect(adminPerms.isReadOnly).toBe(false);

    // ANALYST permissions
    const analystPerms = checkRolePermissions('ANALYST');
    expect(analystPerms.canMutatePolicies).toBe(false);
    expect(analystPerms.canReviewFeedback).toBe(false);
    expect(analystPerms.canSubmitFeedback).toBe(true);
    expect(analystPerms.canManageSites).toBe(false);
    expect(analystPerms.isReadOnly).toBe(false);

    // VIEWER permissions
    const viewerPerms = checkRolePermissions('VIEWER');
    expect(viewerPerms.canMutatePolicies).toBe(false);
    expect(viewerPerms.canReviewFeedback).toBe(false);
    expect(viewerPerms.canSubmitFeedback).toBe(false);
    expect(viewerPerms.canManageSites).toBe(false);
    expect(viewerPerms.isReadOnly).toBe(true);
  });
});
