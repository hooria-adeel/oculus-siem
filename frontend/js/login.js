import { h, icon } from "/js/lib/dom.js";
import { post, get, ApiError } from "/js/lib/api.js";

const form = document.getElementById("form"), err = document.getElementById("err"), go = document.getElementById("go");
const pw = document.getElementById("p"), toggle = document.getElementById("toggle"), caps = document.getElementById("caps");
let countdown;

const paintToggle = () => { toggle.replaceChildren(icon(pw.type === "password" ? "eye" : "lock-keyhole")); };
paintToggle();
toggle.addEventListener("click", () => { pw.type = pw.type === "password" ? "text" : "password"; toggle.ariaLabel = pw.type === "password" ? "Show password" : "Hide password"; paintToggle(); });

const capsCheck = (e) => caps.classList.toggle("hidden", !e.getModifierState?.("CapsLock"));
pw.addEventListener("keydown", capsCheck); pw.addEventListener("keyup", capsCheck); pw.addEventListener("blur", () => caps.classList.add("hidden"));

const show = (msg) => { err.textContent = msg; err.classList.toggle("hidden", !msg); };

function lockout(seconds) {
  clearInterval(countdown);
  const end = Date.now() + seconds * 1000;
  go.disabled = true;
  const tick = () => {
    const left = Math.ceil((end - Date.now()) / 1000);
    if (left <= 0) { clearInterval(countdown); go.disabled = false; show(""); return; }
    show(`Too many attempts. Try again in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}.`);
  };
  tick(); countdown = setInterval(tick, 500);
}

form.addEventListener("submit", (e) => { e.preventDefault(); signIn(); });

async function signIn() {
  show("");
  const username = form.username.value.trim(), password = form.password.value;
  if (!username || !password) return show("Enter your email and password.");
  go.disabled = true; go.textContent = "Signing in…";
  try {
    const res = await post("/api/login", { username, password });
    location.assign(res.user.role === "Admin" ? "/console.html" : "/workspace.html");
  } catch (ex) {
    go.disabled = false; go.textContent = "Sign in";
    if (ex instanceof ApiError && ex.status === 429) lockout(ex.retryAfter || 60);
    else show(ex instanceof ApiError && ex.status === 401 ? "That email and password don't match." : ex.message);
    pw.select();
  }
}

// Demo mode (server decides): one-click sign-in for the fictional accounts, so a visitor can see both interfaces.
get("/api/demo-accounts").then(({ demo, accounts }) => {
  if (!demo || !accounts.length) return;
  const list = document.getElementById("demo-list");
  accounts.forEach((a) => list.append(h("button", { type: "button", class: "demo-btn", onclick: () => {
      form.username.value = a.username; form.password.value = a.password; signIn(); } },
    h("b", {}, a.label), h("small", {}, a.username), h("span", { class: "opens" }, a.opens, icon("arrow-right", "sm")))));
  document.getElementById("demo").classList.remove("hidden");
}).catch(() => {});

// Already signed in? Skip the form.
get("/api/me").then((u) => location.replace(u.role === "Admin" ? "/console.html" : "/workspace.html")).catch(() => {});
