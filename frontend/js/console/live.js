// Live feed: polls /api/events?since_id= and fans new events out to subscribers. Polling keeps the stack
// dependency-free; the contract (monotonic ids, ascending "since") is what a WebSocket/SSE swap would reuse.
import { get } from "../lib/api.js";

export function createLive({ interval = 3000 } = {}) {
  let lastId = null, timer = null, paused = false, state = "connecting", lastOk = 0;
  const subs = new Set(), statusSubs = new Set();
  const setState = (s) => { if (s !== state) { state = s; statusSubs.forEach((f) => f(getStatus())); } };
  const getStatus = () => ({ state, paused, lastOk });

  async function tick() {
    clearTimeout(timer);
    let delay = interval;
    if (!paused && !document.hidden) {
      try {
        if (lastId === null) lastId = (await get("/api/events", { limit: 1 })).latestId;
        else {
          const d = await get("/api/events", { since_id: lastId, limit: 100 });
          if (d.events.length) { lastId = d.latestId ?? d.events.at(-1).id; subs.forEach((f) => f(d.events)); }
        }
        lastOk = Date.now(); setState("live");
      } catch { setState("down"); delay = 8000; }
    }
    timer = setTimeout(tick, delay);
  }

  return {
    start() { tick(); },
    subscribe(fn) { subs.add(fn); return () => subs.delete(fn); },
    onStatus(fn) { statusSubs.add(fn); fn(getStatus()); return () => statusSubs.delete(fn); },
    toggle() { paused = !paused; setState(paused ? "paused" : "connecting"); if (!paused) tick(); statusSubs.forEach((f) => f(getStatus())); return paused; },
    get paused() { return paused; },
    get lastOk() { return lastOk; },
  };
}
