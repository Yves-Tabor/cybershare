/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./home.html",
    "./scanner.html",
    "./resources.html",
    "./src/**/*.{js,ts}", // Watches your scripts
  ],
  theme: {
    extend: {
      colors: {
        'cyber-dark': '#0A0E1A',
        'cyber-darker': '#060911',
        'cyber-blue': '#00D9FF',
        'cyber-purple': '#8B5CF6',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'monospace'],
        'sans': ['Sora', 'sans-serif'],
      },
    },
  },
  plugins: [],
}