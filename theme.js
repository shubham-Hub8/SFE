/* ==========================================
   SFE 3.0 — Theme Preference
   Uses a first-party cookie when available,
   with localStorage fallback for file:// usage.
========================================== */

"use strict";

(() => {
    const COOKIE_NAME = "sfe-theme";
    const COOKIE_MAX_AGE = 60 * 60 * 24 * 365;
    const STORAGE_KEY = "sfe-theme";

    function readCookie() {
        try {
            const row = document.cookie
                .split("; ")
                .find(part => part.startsWith(`${COOKIE_NAME}=`));
            return row ? decodeURIComponent(row.slice(COOKIE_NAME.length + 1)) : null;
        } catch {
            return null;
        }
    }

    function readStorage() {
        try {
            const value = window.localStorage.getItem(STORAGE_KEY);
            return value === "dark" || value === "light" ? value : null;
        } catch {
            return null;
        }
    }

    function writeCookie(theme) {
        try {
            const secure = window.location.protocol === "https:" ? "; Secure" : "";
            document.cookie = `${COOKIE_NAME}=${encodeURIComponent(theme)}; Max-Age=${COOKIE_MAX_AGE}; Path=/; SameSite=Lax${secure}`;
            return readCookie() === theme;
        } catch {
            return false;
        }
    }

    function writeStorage(theme) {
        try {
            window.localStorage.setItem(STORAGE_KEY, theme);
            return readStorage() === theme;
        } catch {
            return false;
        }
    }

    function getSavedTheme() {
        return readCookie() || readStorage();
    }

    function getInitialTheme() {
        const saved = getSavedTheme();
        if (saved === "dark" || saved === "light") {
            return saved;
        }

        try {
            return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
        } catch {
            return "light";
        }
    }

    function applyTheme(theme, persist = false) {
        const normalized = theme === "dark" ? "dark" : "light";
        document.documentElement.dataset.theme = normalized;

        if (persist) {
            writeCookie(normalized);
            writeStorage(normalized);
        }

        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) {
            meta.setAttribute("content", normalized === "dark" ? "#120d18" : "#f4f0fa");
        }

        const toggle = document.getElementById("themeToggle");
        if (toggle) {
            const isDark = normalized === "dark";
            toggle.setAttribute("aria-pressed", String(isDark));
            toggle.setAttribute("aria-label", `Dark mode: ${isDark ? "on" : "off"}`);
            toggle.title = isDark ? "Switch to light mode" : "Switch to dark mode";
            toggle.classList.toggle("is-dark", isDark);
        }
    }

    applyTheme(getInitialTheme(), false);

    function bindToggle() {
        const toggle = document.getElementById("themeToggle");
        if (!toggle || toggle.dataset.themeBound === "true") {
            return;
        }

        toggle.dataset.themeBound = "true";
        toggle.addEventListener("click", () => {
            const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
            applyTheme(next, true);
        });

        applyTheme(document.documentElement.dataset.theme || "light", false);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bindToggle, { once: true });
    } else {
        bindToggle();
    }
})();
