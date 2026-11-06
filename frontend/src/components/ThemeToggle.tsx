import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

export function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("sg_theme");
      if (saved === "light" || saved === "dark") return saved;
      if (window.matchMedia("(prefers-color-scheme: dark)").matches) return "dark";
    }
    return "light";
  });

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", theme);
    localStorage.setItem("sg_theme", theme);
  }, [theme]);

  const toggle = () => setTheme((t) => (t === "light" ? "dark" : "light"));

  return (
    <button
      onClick={toggle}
      type="button"
      className="inline-flex h-8 w-8 items-center justify-center rounded-full text-[var(--text-2)] transition-colors hover:bg-[var(--hairline-subtle)] hover:text-[var(--text)]"
      title={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
      aria-label="Toggle theme"
    >
      {theme === "light" ? <Moon size={16} strokeWidth={1.5} /> : <Sun size={16} strokeWidth={1.5} />}
    </button>
  );
}
