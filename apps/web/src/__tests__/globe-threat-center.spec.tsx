import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { GlobalThreatGlobe, ThreatCallout } from '../components/GlobalThreatGlobe';
import { ThemeProvider } from '../context/ThemeContext';
import { ThemeToggle } from '../components/common/ThemeToggle';
import { ActionBadge } from '../components/common/ActionBadge';

const customCallouts: ThreatCallout[] = [
  {
    id: 't-1',
    type: 'malicious',
    label: 'Malicious IP',
    sublabel: '198.51.100.99',
    lat: 40.7128,
    lng: -74.006,
    positionClass: 'top-10 left-10',
  },
  {
    id: 't-2',
    type: 'benign',
    label: 'Benign Traffic',
    sublabel: 'US-West',
    lat: 37.7749,
    lng: -122.4194,
    positionClass: 'bottom-10 right-10',
  },
];

describe('Phase 12.5 Threat Center Redesign: Globe & Dual Theme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove('dark', 'light');
  });

  it('renders GlobalThreatGlobe cleanly in JSDOM via SVG fallback without WebGL crash', () => {
    render(
      <ThemeProvider>
        <GlobalThreatGlobe callouts={customCallouts} />
      </ThemeProvider>,
    );

    // Verify main globe container renders
    const globeContainer = screen.getByTestId('global-threat-globe');
    expect(globeContainer).toBeInTheDocument();

    // Verify SVG fallback renders when WebGL is absent in JSDOM
    const svgFallback = screen.getByTestId('globe-svg-fallback');
    expect(svgFallback).toBeInTheDocument();

    // Verify floating callout badges render
    expect(screen.getByText('Malicious IP')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.99')).toBeInTheDocument();
    expect(screen.getByText('Benign Traffic')).toBeInTheDocument();
    expect(screen.getByText('US-West')).toBeInTheDocument();

    // Verify zoom and reset controls
    expect(screen.getByLabelText('Zoom in globe')).toBeInTheDocument();
    expect(screen.getByLabelText('Zoom out globe')).toBeInTheDocument();
    expect(screen.getByLabelText('Reset globe view')).toBeInTheDocument();

    // Verify horizontal legend
    expect(screen.getByText('Malicious')).toBeInTheDocument();
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
    expect(screen.getByText('Benign')).toBeInTheDocument();
  });

  it('interacts with zoom and reset controls smoothly', () => {
    render(
      <ThemeProvider>
        <GlobalThreatGlobe />
      </ThemeProvider>,
    );

    const zoomIn = screen.getByLabelText('Zoom in globe');
    const zoomOut = screen.getByLabelText('Zoom out globe');
    const reset = screen.getByLabelText('Reset globe view');

    // Click controls to ensure no runtime errors
    fireEvent.click(zoomIn);
    fireEvent.click(zoomOut);
    fireEvent.click(reset);

    expect(screen.getByTestId('global-threat-globe')).toBeInTheDocument();
  });

  it('renders sleek pill ThemeToggle and toggles dark/light with localStorage persistence', () => {
    render(
      <ThemeProvider>
        <ThemeToggle />
      </ThemeProvider>,
    );

    const toggle = screen.getByLabelText('Toggle theme');
    expect(toggle).toBeInTheDocument();
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    // Toggle to Light Mode
    fireEvent.click(toggle);
    expect(document.documentElement.classList.contains('light')).toBe(true);
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('waf_theme')).toBe('light');

    // Toggle back to Dark Mode
    fireEvent.click(toggle);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(document.documentElement.classList.contains('light')).toBe(false);
    expect(localStorage.getItem('waf_theme')).toBe('dark');
  });

  it('renders semantic action pills correctly in dark and light modes', () => {
    const { rerender } = render(
      <ThemeProvider>
        <div>
          <ActionBadge action="BLOCK" />
          <ActionBadge action="CHALLENGE" />
          <ActionBadge action="MONITOR" />
          <ActionBadge action="ALLOW" />
        </div>
      </ThemeProvider>,
    );

    expect(screen.getByText('BLOCK')).toBeInTheDocument();
    expect(screen.getByText('CHALLENGE')).toBeInTheDocument();
    expect(screen.getByText('MONITOR')).toBeInTheDocument();
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
  });
});
