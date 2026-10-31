import { get, post } from "./api.js";

// Resolve the signed-in user or bounce to the login page. `want` is "admin" or "employee".
export async function requireSession(want) {
  let user;
  try { user = await get("/api/me"); } catch { location.replace("/login.html"); return new Promise(() => {}); }
  user = user.user ?? user;
  const isAdmin = user.role === "Admin";
  if (want === "admin" && !isAdmin) { location.replace("/workspace.html"); return new Promise(() => {}); }
  if (want === "employee" && isAdmin) { location.replace("/console.html"); return new Promise(() => {}); }
  return user;
}

export async function signOut() {
  try { await post("/api/logout"); } finally { location.assign("/login.html"); }
}

export const initials = (name) => name.split(/\s+/).map((p) => p[0]).slice(0, 2).join("").toUpperCase();
