// Light/dark switch for the Console. The choice lives in localStorage; blocked storage just means "dark".
const KEY = "oculus-theme";
export const currentTheme = () => (document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");
export function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem(KEY, theme); } catch { /* ignore */ }
}
