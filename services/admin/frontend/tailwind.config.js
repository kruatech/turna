/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        sans: ['"DM Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      colors: {
        // dark surfaces
        d: {
          bg:      '#0d0f17',
          card:    '#131620',
          raised:  '#1a1e2e',
          border:  '#ffffff0d',
          border2: '#ffffff18',
          ink:     '#e8eaf2',
          muted:   '#6b7394',
          faint:   '#353a52',
        },
        // light surfaces
        l: {
          bg:      '#f4f6fb',
          card:    '#ffffff',
          raised:  '#eef1f8',
          border:  '#e2e6f0',
          border2: '#d0d5e8',
          ink:     '#111827',
          muted:   '#6b7280',
          faint:   '#9ca3af',
        },
        // accent palette
        teal:    { DEFAULT: '#2dd4bf', dim: '#2dd4bf1a' },
        violet:  { DEFAULT: '#818cf8', dim: '#818cf81a' },
        sky:     { DEFAULT: '#38bdf8', dim: '#38bdf81a' },
        amber:   { DEFAULT: '#fbbf24', dim: '#fbbf241a' },
        rose:    { DEFAULT: '#f87171', dim: '#f871711a' },
        emerald: { DEFAULT: '#34d399', dim: '#34d3991a' },
        orange:  { DEFAULT: '#fb923c', dim: '#fb923c1a' },
      },
    },
  },
  plugins: [],
}
