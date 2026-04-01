/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        g: {
          bg: 'var(--g-bg)',
          raised: 'var(--g-bg-raised)',
          card: 'var(--g-bg-card)',
          hover: 'var(--g-bg-hover)',
          border: 'var(--g-border)',
          text: 'var(--g-text)',
          secondary: 'var(--g-text-secondary)',
          muted: 'var(--g-text-muted)',
          accent: 'var(--g-accent)',
          green: 'var(--g-green)',
          red: 'var(--g-red)'
        }
      },
      fontFamily: {
        sans: ['Inter', 'Noto Sans SC', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['Space Grotesk', 'Noto Sans SC', 'sans-serif'],
        mono: ['Geist Mono', 'Consolas', 'monospace']
      },
      borderRadius: {
        g: '12px',
        'g-sm': '8px'
      }
    }
  },
  plugins: []
};
