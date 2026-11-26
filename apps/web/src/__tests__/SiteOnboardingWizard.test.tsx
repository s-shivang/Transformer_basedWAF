import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { SiteOnboardingWizard } from '../components/SiteOnboardingWizard';
import { api, OnboardingInstructions, ProtectedSiteSummary, TenantDetails } from '../lib/api';
import { AuthContext } from '../context/AuthContext';

// Mock Lucide icons
vi.mock('lucide-react', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return {
    ...actual,
  };
});

// Mock api methods
vi.mock('../lib/api', () => ({
  api: {
    sites: {
      startOnboarding: vi.fn(),
      getOnboarding: vi.fn(),
      verifyDomain: vi.fn(),
      configureGateway: vi.fn(),
      verifyDnsRouting: vi.fn(),
      provisionTls: vi.fn(),
      activate: vi.fn(),
      retryOnboarding: vi.fn(),
      list: vi.fn(),
    },
    tenants: {
      get: vi.fn(),
      updateQuota: vi.fn(),
    },
  },
}));

const mockTenant: TenantDetails = {
  id: 't1',
  name: 'Test Tenant',
  slug: 'test',
  status: 'ACTIVE',
  maxSites: 5,
};

function createMockSite(overrides: Partial<OnboardingInstructions> = {}): OnboardingInstructions {
  return {
    siteId: 'site-123',
    name: 'Shop Portal',
    domain: 'shop.example.com',
    originUrl: 'https://backend.shop.local:8443',
    onboardingStatus: 'PENDING_VERIFICATION',
    verificationToken: 'waf_txt_test_token_abc',
    configVersion: 1,
    gatewayAckVersion: 1,
    lastSyncedAt: new Date().toISOString(),
    txtRecord: {
      host: '_waf-challenge.shop.example.com',
      value: 'waf_txt_test_token_abc',
      ttl: 300,
    },
    trafficRecord: {
      type: 'CNAME',
      host: 'shop.example.com',
      target: 'edge.transformer-waf.internal',
    },
    tlsStatus: 'NONE',
    tlsIssuer: null,
    tlsExpiresAt: null,
    originHealthStatus: 'UNKNOWN',
    lastHealthCheckAt: null,
    activatedAt: null,
    lastError: null,
    verifiedAt: null,
    ...overrides,
  };
}

function createTestWrapper(authValue: any = {}) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  const defaultAuth = {
    user: { id: 'u1', email: 'owner@test.com', tenantId: 't1', role: 'OWNER' as const },
    tenant: { id: 't1', name: 'Test Tenant', slug: 'test' },
    isLoading: false,
    selectedSiteId: null,
    setSelectedSiteId: vi.fn(),
    timeWindow: '24h' as const,
    setTimeWindow: vi.fn(),
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    canMutatePolicies: true,
    canSubmitFeedback: true,
    canReviewFeedback: true,
    canManageTeam: true,
    canManageSites: true,
    ...authValue,
  };

  return ({ children }: { children: React.ReactNode }) => (
    <BrowserRouter>
      <AuthContext.Provider value={defaultAuth}>
        <QueryClientProvider client={queryClient}>
          {children}
        </QueryClientProvider>
      </AuthContext.Provider>
    </BrowserRouter>
  );
}

describe('SiteOnboardingWizard Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders Step 1 (Details) when isOpen=true and initialSiteId=null', async () => {
    vi.mocked(api.sites.list).mockResolvedValue([]);
    vi.mocked(api.tenants.get).mockResolvedValue(mockTenant);

    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(
      <SiteOnboardingWizard isOpen={true} onClose={onClose} onSuccess={onSuccess} />,
      { wrapper: createTestWrapper() },
    );

    expect(screen.getByText('Protect New Website')).toBeInTheDocument();
    expect(screen.getByText('Friendly Website Name')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/E-Commerce Production API/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/api\.company\.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/10\.0\.0\.15/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Continue to DNS Setup/i })).toBeInTheDocument();
  });

  it('submits Step 1 and advances to Step 2 (Domain Ownership)', async () => {
    vi.mocked(api.sites.list).mockResolvedValue([]);
    vi.mocked(api.tenants.get).mockResolvedValue(mockTenant);

    vi.mocked(api.sites.startOnboarding).mockResolvedValueOnce(
      createMockSite({
        onboardingStatus: 'PENDING_VERIFICATION',
      }),
    );

    vi.mocked(api.sites.getOnboarding).mockResolvedValue(createMockSite());

    render(
      <SiteOnboardingWizard isOpen={true} onClose={vi.fn()} onSuccess={vi.fn()} />,
      { wrapper: createTestWrapper() },
    );

    fireEvent.change(screen.getByPlaceholderText(/E-Commerce Production API/i), {
      target: { value: 'Shop Portal' },
    });
    fireEvent.change(screen.getByPlaceholderText(/api\.company\.com/i), {
      target: { value: 'shop.example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/10\.0\.0\.15/i), {
      target: { value: 'https://backend.shop.local:8443' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Continue to DNS Setup/i }));

    await waitFor(() => {
      expect(api.sites.startOnboarding).toHaveBeenCalledWith({
        name: 'Shop Portal',
        domain: 'shop.example.com',
        originUrl: 'https://backend.shop.local:8443',
      });
    });

    await waitFor(() => {
      expect(screen.getByText('_waf-challenge.shop.example.com')).toBeInTheDocument();
      expect(screen.getByText('waf_txt_test_token_abc')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Verify Domain Ownership/i })).toBeInTheDocument();
    });
  });

  it('progresses through Step 2 (Verify Domain) to Step 3 (Gateway Sync)', async () => {
    vi.mocked(api.sites.list).mockResolvedValue([]);
    vi.mocked(api.tenants.get).mockResolvedValue(mockTenant);

    vi.mocked(api.sites.getOnboarding).mockResolvedValue(createMockSite());

    vi.mocked(api.sites.verifyDomain).mockResolvedValueOnce({
      verified: true,
      site: createMockSite({ onboardingStatus: 'VERIFIED' }),
    });

    render(
      <SiteOnboardingWizard isOpen={true} initialSiteId="site-123" onClose={vi.fn()} onSuccess={vi.fn()} />,
      { wrapper: createTestWrapper() },
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Verify Domain Ownership/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Verify Domain Ownership/i }));

    await waitFor(() => {
      expect(api.sites.verifyDomain).toHaveBeenCalledWith('site-123');
    });

    await waitFor(() => {
      expect(screen.getByText('Zero-Downtime Atomic Policy Distribution')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Sync Configuration to Gateway/i })).toBeInTheDocument();
    });
  });

  it('renders Step 5 TLS and Step 6 Activation successfully', async () => {
    vi.mocked(api.sites.list).mockResolvedValue([]);
    vi.mocked(api.tenants.get).mockResolvedValue(mockTenant);

    let currentStatus = 'TLS_PENDING';
    vi.mocked(api.sites.getOnboarding).mockImplementation(async () =>
      createMockSite({
        onboardingStatus: currentStatus as any,
        tlsStatus: currentStatus === 'TLS_PENDING' ? 'PENDING' : 'PROVISIONED',
        tlsIssuer: 'local-dev-acme',
        originHealthStatus: currentStatus === 'ACTIVE' ? 'HEALTHY' : 'UNKNOWN',
      }),
    );

    vi.mocked(api.sites.provisionTls).mockImplementation(async () => {
      currentStatus = 'HEALTH_CHECK';
      return createMockSite({
        onboardingStatus: 'HEALTH_CHECK',
        tlsStatus: 'PROVISIONED',
        tlsIssuer: 'local-dev-acme',
        tlsExpiresAt: new Date(Date.now() + 90 * 86400000).toISOString(),
      });
    });

    vi.mocked(api.sites.activate).mockImplementation(async () => {
      currentStatus = 'ACTIVE';
      return createMockSite({
        onboardingStatus: 'ACTIVE',
        originHealthStatus: 'HEALTHY',
        activatedAt: new Date().toISOString(),
      });
    });

    const onSuccess = vi.fn();

    render(
      <SiteOnboardingWizard isOpen={true} initialSiteId="site-123" onClose={vi.fn()} onSuccess={onSuccess} />,
      { wrapper: createTestWrapper() },
    );

    // Should be on Step 5
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Provision TLS Certificate/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Provision TLS Certificate/i }));

    // Advances to Step 6
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Test Origin & Activate Protection/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Test Origin & Activate Protection/i }));

    // Shows completion card
    await waitFor(() => {
      expect(screen.getByText('Protection ACTIVE!')).toBeInTheDocument();
    });

    expect(onSuccess).toHaveBeenCalled();
  });

  it('renders FAILED state error banner and retry action', async () => {
    vi.mocked(api.sites.list).mockResolvedValue([]);
    vi.mocked(api.tenants.get).mockResolvedValue(mockTenant);

    vi.mocked(api.sites.getOnboarding).mockResolvedValue(
      createMockSite({
        onboardingStatus: 'FAILED',
        lastError: 'DNS TXT verification failed: record not found',
      }),
    );

    vi.mocked(api.sites.retryOnboarding).mockResolvedValueOnce(
      createMockSite({ onboardingStatus: 'PENDING_VERIFICATION' }),
    );

    render(
      <SiteOnboardingWizard isOpen={true} initialSiteId="site-err" onClose={vi.fn()} onSuccess={vi.fn()} />,
      { wrapper: createTestWrapper() },
    );

    await waitFor(() => {
      expect(screen.getByText('Action Required')).toBeInTheDocument();
      expect(screen.getByText('DNS TXT verification failed: record not found')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry Setup/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Retry Setup/i }));

    await waitFor(() => {
      expect(api.sites.retryOnboarding).toHaveBeenCalled();
    });
  });

  it('enforces quota check in Step 1 by disabling submit button when quota is reached', async () => {
    const mockSitesList: ProtectedSiteSummary[] = [
      {
        id: 's1',
        name: 'Site 1',
        domain: 's1.com',
        originUrl: 'http://s1',
        status: 'ACTIVE',
        tenantId: 't1',
        onboardingStatus: 'ACTIVE',
        configVersion: 1,
        gatewayAckVersion: 1,
        tlsStatus: 'NONE',
        tlsIssuer: null,
        tlsExpiresAt: null,
        originHealthStatus: 'HEALTHY',
        lastHealthCheckAt: null,
        activatedAt: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
      {
        id: 's2',
        name: 'Site 2',
        domain: 's2.com',
        originUrl: 'http://s2',
        status: 'ACTIVE',
        tenantId: 't1',
        onboardingStatus: 'ACTIVE',
        configVersion: 1,
        gatewayAckVersion: 1,
        tlsStatus: 'NONE',
        tlsIssuer: null,
        tlsExpiresAt: null,
        originHealthStatus: 'HEALTHY',
        lastHealthCheckAt: null,
        activatedAt: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ];

    vi.mocked(api.sites.list).mockResolvedValue(mockSitesList);
    vi.mocked(api.tenants.get).mockResolvedValue({
      ...mockTenant,
      maxSites: 2, // Quota is 2, and 2 sites exist
    });

    render(
      <SiteOnboardingWizard isOpen={true} onClose={vi.fn()} onSuccess={vi.fn()} />,
      { wrapper: createTestWrapper() },
    );

    await waitFor(() => {
      expect(screen.getByText(/Your tenant has reached the maximum allowed site limit/i)).toBeInTheDocument();
      const submitBtn = screen.getByRole('button', { name: /Continue to DNS Setup/i });
      expect(submitBtn).toBeDisabled();
    });
  });
});
