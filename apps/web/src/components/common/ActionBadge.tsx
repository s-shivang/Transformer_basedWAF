import React from 'react';
import { cn } from '../../lib/utils';

interface ActionBadgeProps {
  action: 'BLOCK' | 'CHALLENGE' | 'MONITOR' | 'ALLOW' | string;
  className?: string;
}

export const ActionBadge: React.FC<ActionBadgeProps> = ({ action, className }) => {
  const norm = (action || '').toUpperCase();

  switch (norm) {
    case 'BLOCK':
      return (
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border',
            'bg-red-50 text-red-700 border-red-200',
            'dark:bg-red-500/15 dark:text-red-400 dark:border-red-500/30',
            className,
          )}
        >
          BLOCK
        </span>
      );
    case 'CHALLENGE':
      return (
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border',
            'bg-amber-50 text-amber-700 border-amber-200',
            'dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30',
            className,
          )}
        >
          CHALLENGE
        </span>
      );
    case 'MONITOR':
      return (
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border',
            'bg-cyan-50 text-cyan-700 border-cyan-200',
            'dark:bg-cyan-500/15 dark:text-cyan-400 dark:border-cyan-500/30',
            className,
          )}
        >
          MONITOR
        </span>
      );
    case 'ALLOW':
    default:
      return (
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border',
            'bg-emerald-50 text-emerald-700 border-emerald-200',
            'dark:bg-emerald-500/15 dark:text-emerald-400 dark:border-emerald-500/30',
            className,
          )}
        >
          ALLOW
        </span>
      );
  }
};
