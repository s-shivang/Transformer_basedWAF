/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        canvas: {
          dark: '#090D16',
          light: '#F8FAFC',
        },
        card: {
          dark: '#111827',
          light: '#FFFFFF',
        },
        border: {
          dark: '#1F2937',
          light: '#E2E8F0',
        },
      },
    },
  },
  plugins: [],
};
