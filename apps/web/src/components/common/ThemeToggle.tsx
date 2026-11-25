import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { cn } from '../../lib/utils';

export const ThemeToggle: React.FC<{ className?: string }> = ({ className }) => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle theme"
      className={cn(
        'relative inline-flex items-center h-8 px-1.5 py-1 rounded-full transition-colors border select-none',
        'bg-[#161616] border-[#222222] text-[#A1A1AA]',
        'light:bg-white light:border-[#E5E7EB] light:text-[#52525B]',
        className,
      )}
      title={`Switch to ${isDark ? 'Light' : 'Dark'} mode`}
    >
      <div className="flex items-center gap-1">
        <span
          className={cn(
            'flex items-center justify-center w-6 h-6 rounded-full transition-all duration-200',
            !isDark ? 'bg-[#FFF7ED] text-[#EA580C] shadow-xs' : 'text-[#71717A] hover:text-[#A1A1AA]',
          )}
        >
          <Sun className="w-3.5 h-3.5" />
        </span>
        <span
          className={cn(
            'flex items-center justify-center w-6 h-6 rounded-full transition-all duration-200',
            isDark ? 'bg-[#262626] text-[#FF8800] shadow-xs' : 'text-[#A1A1AA] hover:text-[#71717A]',
          )}
        >
          <Moon className="w-3.5 h-3.5" />
        </span>
      </div>
    </button>
  );
};
