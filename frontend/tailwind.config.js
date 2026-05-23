/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0d1117',
          panel: '#161b22',
          border: '#30363d',
          text: '#e6edf3',
          muted: '#8b949e',
          accent: '#58a6ff',
          critical: '#f85149',
          high: '#ff7b72',
          medium: '#f0883e',
          low: '#3fb950',
          info: '#58a6ff',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
