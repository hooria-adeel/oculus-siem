// Fetch wrapper: same-origin cookies, CSRF double-submit header on writes, uniform errors.
export class ApiError extends Error {
  constructor(status, message, data = {}, retryAfter = null) {
    super(message); this.status = status; this.data = data; this.retryAfter = retryAfter;
  }
}

const cookie = (name) => document.cookie.split("; ").find((c) => c.startsWith(name + "="))?.split("=")[1] ?? "";

export async function api(path, { method = "GET", body, params, signal } = {}) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params || {})) if (v !== "" && v != null) url.searchParams.set(k, v);
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = decodeURIComponent(cookie("oculus_csrf"));
  let res;
  try {
    res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin", signal });
  } catch (e) {
    if (e.name === "AbortError") throw e;
    throw new ApiError(0, "Cannot reach the Oculus server.");
  }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.endsWith("/api/login") && !path.endsWith("/api/me")) { location.assign("/login.html"); }
  if (!res.ok) throw new ApiError(res.status, data.message || `Request failed (${res.status})`, data, Number(res.headers.get("Retry-After")) || null);
  return data;
}

export const get = (path, params, opts) => api(path, { params, ...opts });
export const post = (path, body) => api(path, { method: "POST", body: body ?? {} });
export const patch = (path, body) => api(path, { method: "PATCH", body });
