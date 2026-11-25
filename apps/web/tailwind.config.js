/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        brand: {
          orange: '#FF6600',
          'orange-glow': '#FF8800',
          ember: '#EA580C',
          peach: '#FFF7ED',
          'peach-dark': '#FFEDD5',
        },
        pitch: {
          DEFAULT: '#000000',
          card: '#0A0A0A',
          surface: '#111111',
          hover: '#161616',
          active: '#1C1C1C',
          border: '#222222',
        },
      },
    },
  },
  plugins: [],
};
