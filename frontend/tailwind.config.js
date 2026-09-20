/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          950: '#0b0f17', // Deepest background
          900: '#0f172a', // Main background
          850: '#131e36', // Card background
          800: '#1e293b', // Elevated borders & panels
          700: '#334155', // Subtle divider
          600: '#475569', // Muted text
          400: '#94a3b8', // Secondary text
          200: '#e2e8f0', // Primary text
          100: '#f8fafc', // Bright highlight
        },
        threat: {
          critical: '#ef4444', // Red-500
          high: '#f97316',     // Orange-500
          medium: '#f59e0b',   // Amber-500
          low: '#3b82f6',      // Blue-500
          clean: '#10b981',    // Emerald-500
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
}
