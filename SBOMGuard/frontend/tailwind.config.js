/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        dark: {
          950: "#07090E",
          900: "#0B0F19",
          850: "#0F172A",
          800: "#1E293B",
          700: "#334155",
        },
        cyber: {
          cyan: "#06B6D4",
          blue: "#3B82F6",
          purple: "#8B5CF6",
          emerald: "#10B981",
          rose: "#F43F5E",
          amber: "#F59E0B",
        },
      },
      fontFamily: {
        sans: ["'Plus Jakarta Sans'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      boxShadow: {
        glass: "0 8px 32px 0 rgba(0, 0, 0, 0.37)",
        glow: "0 0 25px -5px rgba(6, 182, 212, 0.4)",
        "glow-rose": "0 0 25px -5px rgba(244, 63, 94, 0.4)",
        "glow-purple": "0 0 25px -5px rgba(139, 92, 246, 0.4)",
      },
    },
  },
  plugins: [],
};
