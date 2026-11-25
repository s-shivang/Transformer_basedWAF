import React, { useEffect, useRef, useState } from 'react';
import createGlobe from 'cobe';
import { useTheme } from '../context/ThemeContext';
import { Plus, Minus, RotateCcw } from 'lucide-react';
import { cn } from '../lib/utils';

export interface ThreatCallout {
  id: string;
  type: 'malicious' | 'suspicious' | 'benign';
  label: string;
  sublabel: string;
  lat: number;
  lng: number;
  count?: number;
  positionClass: string;
  targetNode?: { x: number; y: number };
}

const DEFAULT_CALLOUTS: ThreatCallout[] = [
  {
    id: 'c1',
    type: 'malicious',
    label: 'Malicious IP',
    sublabel: '185.190.110.23',
    lat: 51.5074,
    lng: -0.1278,
    count: 342,
    positionClass: 'top-6 left-6',
    targetNode: { x: 105, y: 135 },
  },
  {
    id: 'c2',
    type: 'suspicious',
    label: 'High Risk Region',
    sublabel: 'Asia Pacific',
    lat: 35.6762,
    lng: 139.6503,
    count: 189,
    positionClass: 'top-8 right-6',
    targetNode: { x: 295, y: 145 },
  },
  {
    id: 'c3',
    type: 'suspicious',
    label: 'Suspicious Traffic',
    sublabel: 'EU-West',
    lat: 48.8566,
    lng: 2.3522,
    count: 76,
    positionClass: 'bottom-20 left-8',
    targetNode: { x: 125, y: 260 },
  },
  {
    id: 'c4',
    type: 'benign',
    label: 'Benign Traffic',
    sublabel: 'US-East',
    lat: 38.9072,
    lng: -77.0369,
    count: 1420,
    positionClass: 'bottom-16 right-8',
    targetNode: { x: 275, y: 250 },
  },
];

interface GlobalThreatGlobeProps {
  callouts?: ThreatCallout[];
  className?: string;
}

const checkWebGLAvailability = (): boolean => {
  if (typeof window === 'undefined') return false;
  if (
    navigator.userAgent.includes('jsdom') ||
    typeof (window as any).WebGLRenderingContext === 'undefined'
  ) {
    return false;
  }
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    return !!gl;
  } catch {
    return false;
  }
};

export const GlobalThreatGlobe: React.FC<GlobalThreatGlobeProps> = ({
  callouts = DEFAULT_CALLOUTS,
  className,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const [webGLSupported, setWebGLSupported] = useState<boolean>(checkWebGLAvailability);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [rotationOffset, setRotationOffset] = useState<number>(0);
  const [selectedCallout, setSelectedCallout] = useState<ThreatCallout | null>(null);

  // WebGL Globe Initialization via cobe
  useEffect(() => {
    if (!webGLSupported || !canvasRef.current) return;

    let phi = rotationOffset;
    let width = 0;
    const currentCanvas = canvasRef.current;

    const onResize = () => {
      if (currentCanvas) {
        width = currentCanvas.offsetWidth || 340;
      }
    };
    window.addEventListener('resize', onResize);
    onResize();

    // Key geographical telemetry hotspots on the rotating globe
    const markers = [
      { location: [51.5074, -0.1278] as [number, number], size: 0.08 }, // London/Europe
      { location: [35.6762, 139.6503] as [number, number], size: 0.09 }, // Tokyo/Asia
      { location: [38.9072, -77.0369] as [number, number], size: 0.06 }, // US-East DC
      { location: [48.8566, 2.3522] as [number, number], size: 0.07 }, // Paris
      { location: [-33.9249, 18.4241] as [number, number], size: 0.05 }, // Cape Town
      { location: [1.3521, 103.8198] as [number, number], size: 0.06 }, // Singapore
      { location: [25.2048, 55.2708] as [number, number], size: 0.06 }, // Dubai
    ];

    let globe: ReturnType<typeof createGlobe> | null = null;
    let animId: number | null = null;
    try {
      globe = createGlobe(currentCanvas, {
        devicePixelRatio: Math.min(2, window.devicePixelRatio || 1),
        width: (width || 340) * 2,
        height: (width || 340) * 2,
        phi: 0,
        theta: 0.22,
        dark: isDark ? 1 : 0,
        diffuse: isDark ? 1.4 : 1.15,
        mapSamples: 24000,
        mapBrightness: isDark ? 6.2 : 3.8,
        baseColor: isDark ? [0.07, 0.07, 0.07] : [0.94, 0.94, 0.93],
        markerColor: [1.0, 0.42, 0.0], // Radiant glowing orange hotspot markers
        glowColor: isDark ? [1.0, 0.45, 0.05] : [1.0, 0.58, 0.2], // Warm atmospheric rim glow
        markers,
      });

      const animate = () => {
        phi += 0.0032;
        globe?.update({ phi });
        animId = requestAnimationFrame(animate);
      };
      animId = requestAnimationFrame(animate);
    } catch {
      setWebGLSupported(false);
    }

    return () => {
      window.removeEventListener('resize', onResize);
      if (animId !== null) {
        cancelAnimationFrame(animId);
      }
      if (globe) {
        try {
          globe.destroy();
        } catch {}
      }
    };
  }, [webGLSupported, isDark, rotationOffset]);

  const handleZoomIn = () => setZoomLevel((z) => Math.min(1.35, z + 0.1));
  const handleZoomOut = () => setZoomLevel((z) => Math.max(0.75, z - 0.1));
  const handleReset = () => {
    setZoomLevel(1);
    setRotationOffset((r) => r + 0.4);
    setSelectedCallout(null);
  };

  return (
    <div
      ref={containerRef}
      className={cn(
        'relative w-full h-[410px] flex items-center justify-center overflow-hidden select-none rounded-xl',
        isDark ? 'bg-[#0A0A0A]' : 'bg-white',
        className,
      )}
      data-testid="global-threat-globe"
    >
      {/* 1. Atmospheric Ambient Radial Glow */}
      <div
        className={cn(
          'absolute inset-0 pointer-events-none transition-opacity duration-700',
          isDark
            ? 'bg-[radial-gradient(circle_at_center,rgba(255,102,0,0.18)_0%,transparent_65%)]'
            : 'bg-[radial-gradient(circle_at_center,rgba(255,140,40,0.14)_0%,transparent_65%)]',
        )}
      />

      {/* 2. 3D Orbital Trajectory Arcs Layer (Matching reference ss3 with precision curves, gradients & nodes) */}
      <div
        className="absolute inset-0 flex items-center justify-center pointer-events-none transition-transform duration-300 z-10"
        style={{ transform: `scale(${zoomLevel})` }}
      >
        <svg
          viewBox="0 0 400 400"
          className="w-[390px] h-[390px] max-w-full aspect-square overflow-visible"
        >
          <defs>
            {/* Orange Orbital Gradient */}
            <linearGradient id="orangeOrbitGrad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#FF6600" stopOpacity="0.95" />
              <stop offset="60%" stopColor="#EA580C" stopOpacity="0.75" />
              <stop offset="100%" stopColor="#FF8800" stopOpacity="0.2" />
            </linearGradient>

            {/* Green Orbital Gradient */}
            <linearGradient id="greenOrbitGrad" x1="1" y1="1" x2="0" y2="0">
              <stop offset="0%" stopColor="#10B981" stopOpacity="0.9" />
              <stop offset="50%" stopColor="#059669" stopOpacity="0.65" />
              <stop offset="100%" stopColor="#34D399" stopOpacity="0.15" />
            </linearGradient>

            {/* Amber Dotted Orbit Gradient */}
            <linearGradient id="amberOrbitGrad" x1="0" y1="1" x2="1" y2="0">
              <stop offset="0%" stopColor="#F59E0B" stopOpacity="0.65" />
              <stop offset="100%" stopColor="#D97706" stopOpacity="0.1" />
            </linearGradient>

            {/* Glow Filter */}
            <filter id="orbitGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Orbit 1: Primary Orange Trajectory Arc (Inclined -28deg) */}
          <g filter={isDark ? 'url(#orbitGlow)' : undefined}>
            <ellipse
              cx="200"
              cy="200"
              rx="164"
              ry="88"
              transform="rotate(-28 200 200)"
              fill="none"
              stroke="url(#orangeOrbitGrad)"
              strokeWidth="1.6"
              strokeLinecap="round"
            />
          </g>

          {/* Orbit 2: Secondary Green Trajectory Arc (Inclined +24deg) */}
          <g filter={isDark ? 'url(#orbitGlow)' : undefined}>
            <ellipse
              cx="200"
              cy="200"
              rx="152"
              ry="78"
              transform="rotate(24 200 200)"
              fill="none"
              stroke="url(#greenOrbitGrad)"
              strokeWidth="1.6"
              strokeLinecap="round"
            />
          </g>

          {/* Orbit 3: Amber Dotted Perimeter Arc */}
          <ellipse
            cx="200"
            cy="200"
            rx="178"
            ry="102"
            transform="rotate(-8 200 200)"
            fill="none"
            stroke="url(#amberOrbitGrad)"
            strokeWidth="1.2"
            strokeDasharray="4 6"
          />

          {/* Orbital Transit Nodes with Glowing Radii (from ss3) */}
          {/* Node 1: Orange Trajectory Top-Left */}
          <g transform="translate(85, 122)">
            <circle r="7" fill="#FF6600" opacity="0.3" className="animate-pulse" />
            <circle r="3.5" fill="#FF6600" stroke="#FFFFFF" strokeWidth="1" />
          </g>

          {/* Node 2: Orange Trajectory Right */}
          <g transform="translate(315, 230)">
            <circle r="6" fill="#EA580C" opacity="0.3" />
            <circle r="3.2" fill="#EA580C" stroke="#FFFFFF" strokeWidth="0.8" />
          </g>

          {/* Node 3: Orange Trajectory Lower-Left */}
          <g transform="translate(108, 268)">
            <circle r="6.5" fill="#FF8800" opacity="0.3" />
            <circle r="3" fill="#FF8800" stroke="#FFFFFF" strokeWidth="0.8" />
          </g>

          {/* Node 4: Green Trajectory Lower-Right (Benign US-East Transit) */}
          <g transform="translate(252, 266)">
            <circle r="7" fill="#10B981" opacity="0.35" className="animate-pulse" />
            <circle r="3.5" fill="#10B981" stroke="#FFFFFF" strokeWidth="1" />
          </g>

          {/* Node 5: Green Trajectory Center-Cross */}
          <g transform="translate(175, 218)">
            <circle r="4" fill="#059669" opacity="0.4" />
            <circle r="2.5" fill="#059669" />
          </g>

          {/* Leader Lines linking Callout Badges to Target Nodes */}
          {/* Callout 1 (Top-Left Malicious IP) */}
          <line
            x1="70"
            y1="55"
            x2="85"
            y2="122"
            stroke={isDark ? '#EF4444' : '#DC2626'}
            strokeWidth="1"
            strokeDasharray="2 3"
            strokeOpacity="0.6"
          />
          {/* Callout 2 (Top-Right High Risk Region) */}
          <line
            x1="325"
            y1="60"
            x2="275"
            y2="135"
            stroke={isDark ? '#F59E0B' : '#D97706'}
            strokeWidth="1"
            strokeDasharray="2 3"
            strokeOpacity="0.55"
          />
          {/* Callout 3 (Bottom-Left Suspicious Traffic) */}
          <line
            x1="75"
            y1="340"
            x2="108"
            y2="268"
            stroke={isDark ? '#F97316' : '#EA580C'}
            strokeWidth="1"
            strokeDasharray="2 3"
            strokeOpacity="0.55"
          />
          {/* Callout 4 (Bottom-Right Benign Traffic) */}
          <line
            x1="320"
            y1="335"
            x2="252"
            y2="266"
            stroke={isDark ? '#10B981' : '#059669'}
            strokeWidth="1"
            strokeDasharray="2 3"
            strokeOpacity="0.6"
          />
        </svg>
      </div>

      {/* 3. Primary Rotating Globe: WebGL Canvas or High-Fidelity SVG Fallback */}
      <div
        className="relative w-[340px] h-[340px] max-w-full aspect-square flex items-center justify-center transition-transform duration-300 z-0"
        style={{ transform: `scale(${zoomLevel})` }}
      >
        {webGLSupported ? (
          <canvas
            ref={canvasRef}
            className="w-[340px] h-[340px] aspect-square rounded-full cursor-grab active:cursor-grabbing mx-auto drop-shadow-[0_0_30px_rgba(255,102,0,0.22)]"
            style={{ width: '340px', height: '340px' }}
          />
        ) : (
          /* High-Fidelity Interactive SVG Fallback (for JSDOM Vitest tests and non-WebGL environments) */
          <div
            className="w-[300px] h-[300px] relative flex items-center justify-center"
            data-testid="globe-svg-fallback"
          >
            <svg
              viewBox="0 0 200 200"
              className="w-full h-full animate-[spin_60s_linear_infinite]"
              style={{
                filter: isDark
                  ? 'drop-shadow(0 0 25px rgba(255,102,0,0.3))'
                  : 'drop-shadow(0 4px 18px rgba(0,0,0,0.08))',
              }}
            >
              <defs>
                <radialGradient id="sphereRadial" cx="35%" cy="35%" r="65%">
                  <stop offset="0%" stopColor={isDark ? '#1F1F1F' : '#FFFFFF'} />
                  <stop offset="60%" stopColor={isDark ? '#121212' : '#F4EFEA'} />
                  <stop offset="100%" stopColor={isDark ? '#080808' : '#E8DFD8'} />
                </radialGradient>
              </defs>

              {/* Base Sphere */}
              <circle
                cx="100"
                cy="100"
                r="85"
                fill="url(#sphereRadial)"
                stroke={isDark ? '#FF6600' : '#EA580C'}
                strokeWidth="1.5"
                strokeOpacity="0.55"
              />

              {/* Meridian and Parallel Grid Lines */}
              <ellipse cx="100" cy="100" rx="85" ry="30" fill="none" stroke={isDark ? '#262626' : '#E5E7EB'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="85" ry="60" fill="none" stroke={isDark ? '#262626' : '#E5E7EB'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="30" ry="85" fill="none" stroke={isDark ? '#262626' : '#E5E7EB'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="60" ry="85" fill="none" stroke={isDark ? '#262626' : '#E5E7EB'} strokeWidth="0.8" />

              {/* Stylized Continental Dot Matrix (Warm Amber & Orange) */}
              <g fill={isDark ? '#FF7A1A' : '#EA580C'} fillOpacity="0.85">
                {/* Europe & Africa */}
                <circle cx="105" cy="65" r="3" />
                <circle cx="112" cy="72" r="3.5" />
                <circle cx="110" cy="95" r="3.2" />
                <circle cx="115" cy="115" r="3" />
                <circle cx="118" cy="130" r="2.5" />
                {/* Americas */}
                <circle cx="65" cy="75" r="2.5" />
                <circle cx="70" cy="80" r="3" />
                <circle cx="62" cy="85" r="2.5" />
                <circle cx="75" cy="95" r="3.2" />
                <circle cx="80" cy="120" r="3" />
                {/* Asia & Pacific */}
                <circle cx="135" cy="70" r="3.5" />
                <circle cx="145" cy="78" r="3.2" />
                <circle cx="130" cy="85" r="3" />
                <circle cx="150" cy="95" r="2.8" />
                <circle cx="148" cy="125" r="3.2" />
              </g>

              {/* Hotspot Threat Beacons on Globe */}
              <circle cx="112" cy="72" r="4.5" fill="#EF4444" className="animate-ping" opacity="0.75" />
              <circle cx="112" cy="72" r="3.5" fill="#EF4444" />
              <circle cx="145" cy="78" r="3.5" fill="#F59E0B" />
              <circle cx="65" cy="80" r="3.5" fill="#FB923C" />
              <circle cx="75" cy="95" r="3.5" fill="#10B981" />
            </svg>
          </div>
        )}
      </div>

      {/* 4. Floating Threat Callout Cards (Styled exactly as in reference ss3) */}
      {callouts.map((callout) => {
        const isMalicious = callout.type === 'malicious';
        const isSuspicious = callout.type === 'suspicious';
        const isSelected = selectedCallout?.id === callout.id;

        return (
          <div
            key={callout.id}
            onClick={() => setSelectedCallout(isSelected ? null : callout)}
            className={cn(
              'absolute z-20 cursor-pointer transition-all duration-200 transform hover:scale-105 select-none',
              callout.positionClass,
            )}
          >
            <div
              className={cn(
                'flex items-center gap-2.5 px-3 py-2 rounded-xl border text-xs backdrop-blur-md shadow-md transition-all',
                isDark
                  ? 'bg-[#111111]/95 border-[#262626] text-white hover:border-[#FF6600]/60'
                  : 'bg-white/95 border-[#E5E7EB] text-[#0A0A0A] hover:border-[#EA580C]/60 shadow-[0_4px_16px_rgba(0,0,0,0.06)]',
                isSelected &&
                  (isDark
                    ? 'border-[#FF6600] ring-1 ring-[#FF6600]'
                    : 'border-[#EA580C] ring-1 ring-[#EA580C]'),
              )}
            >
              {/* Severity Status Indicator Dot */}
              <span className="relative flex h-2.5 w-2.5 shrink-0">
                <span
                  className={cn(
                    'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
                    isMalicious ? 'bg-red-400' : isSuspicious ? 'bg-amber-400' : 'bg-emerald-400',
                  )}
                />
                <span
                  className={cn(
                    'relative inline-flex rounded-full h-2.5 w-2.5',
                    isMalicious ? 'bg-red-500' : isSuspicious ? 'bg-amber-500' : 'bg-[#10B981]',
                  )}
                />
              </span>

              <div className="flex flex-col leading-tight">
                <span className="text-xs text-[#71717A] dark:text-[#A1A1AA] font-medium tracking-wider uppercase">
                  {callout.label}
                </span>
                <span className="font-mono font-semibold text-sm tabular-nums text-[#0A0A0A] dark:text-white mt-0.5">
                  {callout.sublabel}
                </span>
              </div>
            </div>
          </div>
        );
      })}

      {/* 5. Minimal Vertical Floating Controls (+ / - / Reset) */}
      <div
        className={cn(
          'absolute bottom-4 left-4 z-20 flex flex-col rounded-xl border overflow-hidden shadow-sm backdrop-blur-md',
          isDark ? 'bg-[#111111]/90 border-[#262626]' : 'bg-white/90 border-[#E5E7EB]',
        )}
      >
        <button
          type="button"
          onClick={handleZoomIn}
          aria-label="Zoom in globe"
          className={cn(
            'w-7 h-7 flex items-center justify-center text-xs transition-colors border-b',
            isDark
              ? 'border-[#222222] text-[#A1A1AA] hover:text-white hover:bg-[#1A1A1A]'
              : 'border-[#E5E7EB] text-[#71717A] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <Plus className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onClick={handleZoomOut}
          aria-label="Zoom out globe"
          className={cn(
            'w-7 h-7 flex items-center justify-center text-xs transition-colors border-b',
            isDark
              ? 'border-[#222222] text-[#A1A1AA] hover:text-white hover:bg-[#1A1A1A]'
              : 'border-[#E5E7EB] text-[#71717A] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <Minus className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onClick={handleReset}
          aria-label="Reset globe view"
          className={cn(
            'w-7 h-7 flex items-center justify-center text-xs transition-colors',
            isDark
              ? 'text-[#A1A1AA] hover:text-white hover:bg-[#1A1A1A]'
              : 'text-[#71717A] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* 6. Centered Bottom Severity Legend */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-20 flex items-center gap-5 text-xs font-sans font-medium">
        <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 shrink-0" /> Malicious
        </span>
        <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shrink-0" /> Suspicious
        </span>
        <span className="flex items-center gap-1.5 text-[#71717A] dark:text-[#A1A1AA]">
          <span className="w-2.5 h-2.5 rounded-full bg-[#10B981] shrink-0" /> Benign
        </span>
      </div>
    </div>
  );
};
