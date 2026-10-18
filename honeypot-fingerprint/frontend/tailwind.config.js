/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: "var(--page)",
        surface: "var(--surface-1)",
        surface2: "var(--surface-2)",
        line: "var(--line)",
        ink: "var(--text-primary)",
        ink2: "var(--text-secondary)",
        muted: "var(--text-muted)",
        accent: "var(--accent)",
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', '"Segoe UI"', "sans-serif"],
        mono: ['ui-monospace', '"Cascadia Code"', "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
