import React, { useEffect, useRef, useState } from 'react';
import createGlobe from 'cobe';
import { useTheme } from '../context/ThemeContext';
import { Plus, Minus, RotateCcw, AlertTriangle, ShieldCheck, Skull } from 'lucide-react';
import { cn } from '../lib/utils';

export interface ThreatCallout {
  id: string;
  type: 'malicious' | 'suspicious' | 'benign';
  label: string;
  sublabel: string;
  lat: number;
  lng: number;
  count?: number;
  positionClass: string; // Tailwind positioning for floating callout overlay
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
    positionClass: 'top-8 left-6',
  },
  {
    id: 'c2',
    type: 'suspicious',
    label: 'High Risk Region',
    sublabel: 'Asia Pacific',
    lat: 35.6762,
    lng: 139.6503,
    count: 189,
    positionClass: 'top-12 right-6',
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
  },
];

interface GlobalThreatGlobeProps {
  callouts?: ThreatCallout[];
  className?: string;
}

export const GlobalThreatGlobe: React.FC<GlobalThreatGlobeProps> = ({
  callouts = DEFAULT_CALLOUTS,
  className,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const [webGLSupported, setWebGLSupported] = useState<boolean>(true);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [rotationOffset, setRotationOffset] = useState<number>(0);
  const [selectedCallout, setSelectedCallout] = useState<ThreatCallout | null>(null);

  // Check WebGL availability safely (crucial for JSDOM / Vitest hermetic tests)
  useEffect(() => {
    try {
      const testCanvas = document.createElement('canvas');
      const gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
      if (!gl) {
        setWebGLSupported(false);
      }
    } catch {
      setWebGLSupported(false);
    }
  }, []);

  // WebGL Globe Initialization via cobe
  useEffect(() => {
    if (!webGLSupported || !canvasRef.current) return;

    let phi = rotationOffset;
    let width = 0;
    const currentCanvas = canvasRef.current;

    const onResize = () => {
      if (currentCanvas) {
        width = currentCanvas.offsetWidth;
      }
    };
    window.addEventListener('resize', onResize);
    onResize();

    // Map callouts to cobe markers
    const markers = callouts.map((c) => ({
      location: [c.lat, c.lng] as [number, number],
      size: c.type === 'malicious' ? 0.08 : c.type === 'suspicious' ? 0.06 : 0.04,
    }));

    let globe: ReturnType<typeof createGlobe> | null = null;
    try {
      globe = createGlobe(currentCanvas, {
        devicePixelRatio: Math.min(2, window.devicePixelRatio || 1),
        width: width * 2,
        height: width * 2,
        phi: 0,
        theta: 0.25,
        dark: isDark ? 1 : 0,
        diffuse: isDark ? 1.4 : 1.1,
        mapSamples: 16000,
        mapBrightness: isDark ? 6.0 : 3.5,
        baseColor: isDark ? [0.06, 0.06, 0.06] : [0.94, 0.94, 0.94],
        markerColor: [1.0, 0.4, 0.0], // Glowing orange marker dots
        glowColor: isDark ? [1.0, 0.42, 0.0] : [0.95, 0.55, 0.2], // Subtle orange atmospheric halo
        markers,
        onRender: (state) => {
          state.phi = phi;
          phi += 0.003;
        },
      });
    } catch {
      setWebGLSupported(false);
    }

    return () => {
      window.removeEventListener('resize', onResize);
      if (globe) {
        try {
          globe.destroy();
        } catch {}
      }
    };
  }, [webGLSupported, isDark, rotationOffset, callouts]);

  const handleZoomIn = () => setZoomLevel((z) => Math.min(1.4, z + 0.1));
  const handleZoomOut = () => setZoomLevel((z) => Math.max(0.7, z - 0.1));
  const handleReset = () => {
    setZoomLevel(1);
    setRotationOffset((r) => r + 0.5);
    setSelectedCallout(null);
  };

  return (
    <div
      ref={containerRef}
      className={cn(
        'relative w-full h-[400px] flex items-center justify-center overflow-hidden select-none rounded-xl',
        isDark ? 'bg-[#0A0A0A]' : 'bg-white',
        className,
      )}
      data-testid="global-threat-globe"
    >
      {/* Radial Ambient Glow */}
      <div
        className={cn(
          'absolute inset-0 pointer-events-none transition-opacity duration-500',
          isDark
            ? 'bg-[radial-gradient(ellipse_at_center,rgba(255,102,0,0.12)_0%,transparent_70%)]'
            : 'bg-[radial-gradient(ellipse_at_center,rgba(255,140,50,0.08)_0%,transparent_70%)]',
        )}
      />

      {/* Orbit Rings (Stylized Visual Lines) */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div
          className={cn(
            'w-[340px] h-[340px] rounded-full border border-dashed transition-transform duration-700',
            isDark ? 'border-[#FF6600]/25' : 'border-[#EA580C]/25',
          )}
          style={{ transform: `scale(${zoomLevel}) rotate(-25deg)` }}
        />
        <div
          className={cn(
            'w-[400px] h-[220px] rounded-[100%] border border-dashed transition-transform duration-700',
            isDark ? 'border-[#FF8800]/15' : 'border-[#F97316]/15',
          )}
          style={{ transform: `scale(${zoomLevel}) rotate(15deg)` }}
        />
      </div>

      {/* Primary Globe Container: WebGL or Interactive SVG Fallback */}
      <div
        className="relative w-full h-full flex items-center justify-center transition-transform duration-300"
        style={{ transform: `scale(${zoomLevel})` }}
      >
        {webGLSupported ? (
          <canvas
            ref={canvasRef}
            className="w-[340px] h-[340px] max-w-full aspect-square cursor-grab active:cursor-grabbing"
            style={{ width: '340px', height: '340px' }}
          />
        ) : (
          /* High-Fidelity Interactive SVG Fallback for JSDOM & Non-WebGL Browsers */
          <div
            className="w-[300px] h-[300px] relative flex items-center justify-center"
            data-testid="globe-svg-fallback"
          >
            <svg
              viewBox="0 0 200 200"
              className="w-full h-full animate-[spin_60s_linear_infinite]"
              style={{ filter: isDark ? 'drop-shadow(0 0 25px rgba(255,102,0,0.25))' : 'drop-shadow(0 4px 12px rgba(0,0,0,0.08))' }}
            >
              {/* Globe Base Sphere */}
              <circle
                cx="100"
                cy="100"
                r="85"
                fill={isDark ? '#0F0F0F' : '#F4F4F5'}
                stroke={isDark ? '#FF6600' : '#EA580C'}
                strokeWidth="1.5"
                strokeOpacity="0.5"
              />

              {/* Meridian and Parallel Grid Lines */}
              <ellipse cx="100" cy="100" rx="85" ry="30" fill="none" stroke={isDark ? '#262626' : '#E4E4E7'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="85" ry="60" fill="none" stroke={isDark ? '#262626' : '#E4E4E7'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="30" ry="85" fill="none" stroke={isDark ? '#262626' : '#E4E4E7'} strokeWidth="0.8" />
              <ellipse cx="100" cy="100" rx="60" ry="85" fill="none" stroke={isDark ? '#262626' : '#E4E4E7'} strokeWidth="0.8" />
              <line x1="15" y1="100" x2="185" y2="100" stroke={isDark ? '#FF6600' : '#EA580C'} strokeWidth="1" strokeOpacity="0.4" />
              <line x1="100" y1="15" x2="100" y2="185" stroke={isDark ? '#FF6600' : '#EA580C'} strokeWidth="1" strokeOpacity="0.4" />

              {/* Stylized Dotted Continents */}
              <g fill={isDark ? '#FF7A1A' : '#EA580C'} fillOpacity="0.85">
                {/* Americas */}
                <circle cx="65" cy="75" r="2.5" />
                <circle cx="70" cy="80" r="3" />
                <circle cx="62" cy="85" r="2.5" />
                <circle cx="75" cy="95" r="3.2" />
                <circle cx="80" cy="120" r="3" />
                <circle cx="85" cy="135" r="2.5" />
                {/* Europe & Africa */}
                <circle cx="105" cy="65" r="3" />
                <circle cx="112" cy="72" r="3.5" />
                <circle cx="110" cy="95" r="3.2" />
                <circle cx="115" cy="115" r="3" />
                <circle cx="118" cy="130" r="2.5" />
                {/* Asia & Pacific */}
                <circle cx="135" cy="70" r="3.5" />
                <circle cx="145" cy="78" r="3.2" />
                <circle cx="130" cy="85" r="3" />
                <circle cx="150" cy="95" r="2.8" />
                <circle cx="148" cy="125" r="3.2" />
              </g>

              {/* Threat Markers on Globe */}
              <circle cx="65" cy="80" r="4.5" fill="#EF4444" className="animate-ping" opacity="0.75" />
              <circle cx="65" cy="80" r="3.5" fill="#EF4444" />
              <circle cx="140" cy="75" r="3.5" fill="#F59E0B" />
              <circle cx="110" cy="70" r="3.5" fill="#FB923C" />
              <circle cx="75" cy="95" r="3.5" fill="#10B981" />
            </svg>
          </div>
        )}
      </div>

      {/* Floating Glassmorphic Threat Callout Badges */}
      {callouts.map((callout) => {
        const isMalicious = callout.type === 'malicious';
        const isSuspicious = callout.type === 'suspicious';
        const isSelected = selectedCallout?.id === callout.id;

        return (
          <div
            key={callout.id}
            onClick={() => setSelectedCallout(isSelected ? null : callout)}
            className={cn(
              'absolute z-20 cursor-pointer transition-all duration-200 transform hover:scale-105',
              callout.positionClass,
            )}
          >
            <div
              className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs backdrop-blur-md shadow-lg',
                isDark
                  ? 'bg-[#111111]/85 border-[#262626] text-white hover:border-[#FF6600]/50'
                  : 'bg-white/90 border-[#E5E7EB] text-[#0A0A0A] hover:border-[#EA580C]/50',
                isSelected && (isDark ? 'border-[#FF6600] ring-1 ring-[#FF6600]' : 'border-[#EA580C] ring-1 ring-[#EA580C]'),
              )}
            >
              {/* Severity Status Indicator Dot */}
              <span className="relative flex h-2 w-2">
                <span
                  className={cn(
                    'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
                    isMalicious ? 'bg-red-400' : isSuspicious ? 'bg-amber-400' : 'bg-emerald-400',
                  )}
                />
                <span
                  className={cn(
                    'relative inline-flex rounded-full h-2 w-2',
                    isMalicious ? 'bg-red-500' : isSuspicious ? 'bg-amber-500' : 'bg-emerald-500',
                  )}
                />
              </span>

              <div className="flex flex-col leading-tight">
                <span className="text-[10px] text-[#A1A1AA] font-sans">{callout.label}</span>
                <span className="font-mono font-medium text-xs tabular-nums">{callout.sublabel}</span>
              </div>
            </div>
          </div>
        );
      })}

      {/* Interactive Floating Map Controls (Zoom & Reset) */}
      <div className="absolute bottom-4 left-4 z-20 flex flex-col gap-1.5">
        <button
          type="button"
          onClick={handleZoomIn}
          aria-label="Zoom in globe"
          className={cn(
            'w-7 h-7 flex items-center justify-center rounded-md border text-xs transition-colors',
            isDark
              ? 'bg-[#161616] border-[#262626] text-[#A1A1AA] hover:text-white hover:bg-[#222222]'
              : 'bg-white border-[#E5E7EB] text-[#52525B] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <Plus className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onClick={handleZoomOut}
          aria-label="Zoom out globe"
          className={cn(
            'w-7 h-7 flex items-center justify-center rounded-md border text-xs transition-colors',
            isDark
              ? 'bg-[#161616] border-[#262626] text-[#A1A1AA] hover:text-white hover:bg-[#222222]'
              : 'bg-white border-[#E5E7EB] text-[#52525B] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <Minus className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          onClick={handleReset}
          aria-label="Reset globe view"
          className={cn(
            'w-7 h-7 flex items-center justify-center rounded-md border text-xs transition-colors',
            isDark
              ? 'bg-[#161616] border-[#262626] text-[#A1A1AA] hover:text-white hover:bg-[#222222]'
              : 'bg-white border-[#E5E7EB] text-[#52525B] hover:text-[#0A0A0A] hover:bg-[#F3F4F6]',
          )}
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Bottom Horizontal Severity Legend */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-20 flex items-center gap-4 text-[11px] font-sans">
        <span className="flex items-center gap-1.5 text-[#A1A1AA]">
          <span className="w-2 h-2 rounded-full bg-red-500" /> Malicious
        </span>
        <span className="flex items-center gap-1.5 text-[#A1A1AA]">
          <span className="w-2 h-2 rounded-full bg-amber-500" /> Suspicious
        </span>
        <span className="flex items-center gap-1.5 text-[#A1A1AA]">
          <span className="w-2 h-2 rounded-full bg-emerald-500" /> Benign
        </span>
      </div>
    </div>
  );
};
