import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { cn } from '../../lib/utils';

export const ThemeToggle: React.FC<{ className?: string }> = ({ className }) => {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle dark/light mode"
      className={cn(
        'p-2 rounded-lg transition-colors border text-slate-500 dark:text-slate-400',
        'hover:bg-slate-100 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800',
        className,
      )}
      title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
    >
      {theme === 'dark' ? (
        <Sun className="w-4 h-4 text-amber-400 transition-transform rotate-0 hover:rotate-45" />
      ) : (
        <Moon className="w-4 h-4 text-blue-600 transition-transform -rotate-12 hover:rotate-0" />
      )}
    </button>
  );
};
