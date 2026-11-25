import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { Login } from '../pages/Login';
import { Register } from '../pages/Register';
import { AuthContext } from '../context/AuthContext';
import { ThemeProvider } from '../context/ThemeContext';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Auth Pages (Login & Register)', () => {
  it('renders login page with credentials form', () => {
    const mockLogin = vi.fn().mockResolvedValue(undefined);
    render(
      <MemoryRouter>
        <ThemeProvider>
          <AuthContext.Provider
            value={{
              user: null,
              tenant: null,
              isLoading: false,
              selectedSiteId: 'all',
              timeWindow: '24h',
              login: mockLogin,
              register: vi.fn(),
              logout: vi.fn(),
              setSelectedSiteId: vi.fn(),
              setTimeWindow: vi.fn(),
              canMutatePolicies: false,
              canSubmitFeedback: false,
              canReviewFeedback: false,
              canManageTeam: false,
              canManageSites: false,
            }}
          >
            <Login />
          </AuthContext.Provider>
        </ThemeProvider>
      </MemoryRouter>,
    );

    expect(screen.getByRole('heading', { name: /transformer waf soc/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('analyst@enterprise.com')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••••••')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in to dashboard/i })).toBeInTheDocument();
  });

  it('handles login form submission and invokes auth provider', async () => {
    const mockLogin = vi.fn().mockResolvedValue(undefined);
    render(
      <MemoryRouter>
        <ThemeProvider>
          <AuthContext.Provider
            value={{
              user: null,
              tenant: null,
              isLoading: false,
              selectedSiteId: 'all',
              timeWindow: '24h',
              login: mockLogin,
              register: vi.fn(),
              logout: vi.fn(),
              setSelectedSiteId: vi.fn(),
              setTimeWindow: vi.fn(),
              canMutatePolicies: false,
              canSubmitFeedback: false,
              canReviewFeedback: false,
              canManageTeam: false,
              canManageSites: false,
            }}
          >
            <Login />
          </AuthContext.Provider>
        </ThemeProvider>
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByPlaceholderText('analyst@enterprise.com'), {
      target: { value: 'admin@acme.corp' },
    });
    fireEvent.change(screen.getByPlaceholderText('••••••••••••'), {
      target: { value: 'SuperSecret123!' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in to dashboard/i }));

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith({
        email: 'admin@acme.corp',
        password: 'SuperSecret123!',
      });
    });
  });

  it('renders register page with tenant and account inputs', () => {
    const mockRegister = vi.fn().mockResolvedValue(undefined);
    render(
      <MemoryRouter>
        <ThemeProvider>
          <AuthContext.Provider
            value={{
              user: null,
              tenant: null,
              isLoading: false,
              selectedSiteId: 'all',
              timeWindow: '24h',
              login: vi.fn(),
              register: mockRegister,
              logout: vi.fn(),
              setSelectedSiteId: vi.fn(),
              setTimeWindow: vi.fn(),
              canMutatePolicies: false,
              canSubmitFeedback: false,
              canReviewFeedback: false,
              canManageTeam: false,
              canManageSites: false,
            }}
          >
            <Register />
          </AuthContext.Provider>
        </ThemeProvider>
      </MemoryRouter>,
    );

    expect(screen.getByRole('heading', { name: /onboard new tenant/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Alice Smith')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('alice@acme.com')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('At least 8 characters')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('acme-corp')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /register & launch workspace/i })).toBeInTheDocument();
  });
});
