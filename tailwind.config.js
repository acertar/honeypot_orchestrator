/** Tailwind CSS config — Honeypot Orchestrator */
module.exports = {
  content: [
    './backend/app/templates/**/*.html',
    './backend/app/static/js/**/*.js'
  ],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#04060c', 900: '#070b14', 850: '#0a101c', 800: '#0c1422', 700: '#111c2f', 600: '#18253c' },
        neon: { cyan: '#22d3ee', blue: '#38bdf8', violet: '#8b5cf6', green: '#34d399', amber: '#fbbf24', red: '#fb7185' }
      },
      fontFamily: {
        sans: ['Manrope', 'Noto Sans', 'Liberation Sans', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Noto Sans Mono', 'DejaVu Sans Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      boxShadow: {
        glow: '0 0 40px -12px rgba(34,211,238,.45)',
        'glow-violet': '0 0 40px -12px rgba(139,92,246,.45)'
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(.4,0,.6,1) infinite',
        float: 'float 8s ease-in-out infinite',
        'fade-up': 'fadeUp .45s ease both'
      },
      keyframes: {
        float: { '0%,100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-12px)' } },
        fadeUp: { '0%': { opacity: '0', transform: 'translateY(10px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } }
      }
    }
  },
  plugins: []
};
