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
          dark: '#030712',
          card: '#0f172a',
          cardHover: '#1e293b',
          border: '#334155',
          accent: '#06b6d4',
          accentHover: '#0891b2',
        },
        threat: {
          safe: '#10b981',
          safeBg: 'rgba(16, 185, 129, 0.1)',
          warning: '#f59e0b',
          warningBg: 'rgba(245, 158, 11, 0.1)',
          danger: '#ef4444',
          dangerBg: 'rgba(239, 68, 68, 0.12)',
          neutral: '#64748b',
          neutralBg: 'rgba(100, 116, 139, 0.1)',
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
