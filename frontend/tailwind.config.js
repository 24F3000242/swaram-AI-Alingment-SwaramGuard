/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: ["-apple-system", "BlinkMacSystemFont", '"SF Pro Text"', '"SF Pro Display"', "Inter", "system-ui", "sans-serif"],
        mono: ['"SF Mono"', "ui-monospace", "Menlo", "Consolas", "monospace"],
      },
      colors: {
        bg: "var(--bg)",
        "bg-alt": "var(--bg-alt)",
        card: "var(--card)",
        "card-alt": "var(--card-alt)",
        hairline: "var(--hairline)",
        text: "var(--text)",
        "text-2": "var(--text-2)",
        "text-3": "var(--text-3)",
        ink: "var(--text)",
        muted: "var(--text-2)",
        faint: "var(--text-3)",
        line: "var(--hairline)",
        canvas: "var(--bg-alt)",
        accent: {
          DEFAULT: "var(--accent)",
          hover: "var(--accent-hover)",
        },
        link: "var(--link)",
        crit: "var(--crit)",
        high: "var(--high)",
        med: "var(--med)",
        low: "var(--low)",
        ok: "var(--ok)",
      },
      borderRadius: {
        card: "var(--r-card)",
        tile: "var(--r-tile)",
        btn: "var(--r-btn)",
        input: "var(--r-input)",
      },
      boxShadow: {
        "apple-1": "var(--shadow-1)",
        "apple-2": "var(--shadow-2)",
        card: "var(--shadow-1)",
        pop: "var(--shadow-2)",
      },
    },
  },
  plugins: [],
};
