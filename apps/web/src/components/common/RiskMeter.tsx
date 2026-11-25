import React from 'react';
import { cn } from '../../lib/utils';

interface RiskMeterProps {
  score: number; // 0.00 to 1.00
  className?: string;
  showLabels?: boolean;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score, className, showLabels = true }) => {
  const clamped = Math.max(0, Math.min(1, score));
  const pct = Math.round(clamped * 100);

  let bandColor = 'bg-emerald-500';
  let bandName = 'Fast-Pass (Benign)';
  if (clamped >= 0.85) {
    bandColor = 'bg-red-500';
    bandName = 'Hard Block (Attack)';
  } else if (clamped >= 0.50) {
    bandColor = 'bg-amber-500';
    bandName = 'Challenge (Gray Zone)';
  } else if (clamped >= 0.05) {
    bandColor = 'bg-[#FF6600]';
    bandName = 'Monitor Alert';
  }

  return (
    <div className={cn('w-full space-y-1.5', className)}>
      <div className="flex justify-between items-center text-xs">
        <span className="font-medium text-zinc-700 dark:text-zinc-300">
          Risk Score: <span className="font-mono tabular-nums font-bold">{clamped.toFixed(4)}</span>
        </span>
        <span className="text-xs text-zinc-500 dark:text-zinc-400">{bandName}</span>
      </div>

      {/* Progress Track */}
      <div className="h-2 w-full rounded-full bg-[#E5E7EB] dark:bg-[#222222] overflow-hidden relative">
        <div
          className={cn('h-full transition-all duration-300 rounded-full', bandColor)}
          style={{ width: `${Math.max(3, pct)}%` }}
        />
      </div>

      {showLabels && (
        <div className="flex justify-between text-[10px] font-mono text-zinc-400 dark:text-zinc-500 pt-0.5">
          <span>0.00 (Allow)</span>
          <span className="text-orange-600 dark:text-[#FF8800]">0.05</span>
          <span className="text-amber-600 dark:text-amber-400">0.50</span>
          <span className="text-red-600 dark:text-red-400">0.85 (Block)</span>
          <span>1.00</span>
        </div>
      )}
    </div>
  );
};
