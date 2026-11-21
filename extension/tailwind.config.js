/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './*.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        shield: {
          dark: '#080D18',
          bg: '#0D1422',
          bgAlt: '#111B2B',
          card: '#131D2E',
          cardHover: '#192438',
          surface: '#202C40',
          border: '#202C40',
          accent: '#00B8D9',
          accentHover: '#0096B0',
        },
        threat: {
          safe: '#22C55E',
          safeBg: 'rgba(34, 197, 94, 0.12)',
          warning: '#F59E0B',
          warningBg: 'rgba(245, 158, 11, 0.12)',
          danger: '#EF4444',
          dangerBg: 'rgba(239, 68, 68, 0.14)',
          neutral: '#94A3B8',
          neutralBg: 'rgba(148, 163, 184, 0.1)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
};
