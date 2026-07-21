import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

type Relay = { node_id: string; host: string; port: number };
type Hop = { role: string; node_id: string; host: string; port: number };
type Circuit = { node_id: string; static_pub: string; path: Hop[]; guards: Relay[]; relays: Relay[] };

const short = (h: string) => (h && h.length > 16 ? h.slice(0, 10) + "…" + h.slice(-4) : h);

// The daemon returns the site body hex-encoded (despite the field name).
// Decode hex → bytes → UTF-8 string.
function hexToStr(hex: string): string {
  const n = Math.floor(hex.length / 2);
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return new TextDecoder("utf-8").decode(bytes);
}

/** Resolve a site-relative href against the page we're on. */
function resolvePath(base: string, href: string): string {
  if (href.startsWith("/")) return href;
  const dir = base.slice(0, base.lastIndexOf("/") + 1) || "/";
  return (dir + href).replace(/\/{2,}/g, "/");
}

/** Decode the daemon's hex body to raw bytes. */
function hexToBytes(hex: string): Uint8Array {
  const n = Math.floor(hex.length / 2);
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

/** Fetch one path from a hidden service; returns text or null. */
async function fetchHs(hsId: string, path: string): Promise<string | null> {
  try {
    const r: any = await invoke("browser_fetch", { hsId, path });
    if (r?.ok && r.body_b64 != null) return hexToStr(r.body_b64);
  } catch { /* fall through */ }
  return null;
}

/** Fetch one path as bytes — images and other binary assets. */
async function fetchHsBytes(hsId: string, path: string): Promise<Uint8Array | null> {
  try {
    const r: any = await invoke("browser_fetch", { hsId, path });
    if (r?.ok && r.body_b64 != null) return hexToBytes(r.body_b64);
  } catch { /* fall through */ }
  return null;
}

const MIME: Record<string, string> = {
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
  webp: "image/webp", svg: "image/svg+xml", ico: "image/x-icon",
  avif: "image/avif", bmp: "image/bmp",
};

function dataUri(bytes: Uint8Array, path: string): string {
  const ext = (path.split(".").pop() || "").toLowerCase().split("?")[0];
  const mime = MIME[ext] || "application/octet-stream";
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return `data:${mime};base64,${btoa(bin)}`;
}

// Injected into the rendered page so clicks on in-site links come back to us
// instead of dead-ending: a srcDoc iframe has no base URL, so the browser has
// nothing to resolve "/how.html" against. We hand the href to the parent,
// which re-fetches it through the hidden service.
const NAV_HOOK_JS = `
document.addEventListener('click', function (e) {
  var n = e.target, a = null;
  while (n) { if (n.tagName === 'A') { a = n; break; } n = n.parentNode; }
  if (!a) return;
  var href = a.getAttribute('href') || '';
  if (!href || /^(https?:|mailto:|#)/.test(href)) return;  // external/anchor
  e.preventDefault();
  e.stopPropagation();
  parent.postMessage({ phinetNav: href }, '*');
}, true);
`;

/**
 * Build a self-contained page: the daemon serves one path per request, so
 * stylesheets and scripts referenced by the HTML must each be fetched through
 * the hidden service and inlined. Without this the page renders unstyled —
 * the iframe has no origin to resolve "/style.css" against.
 */
async function inlineResources(hsId: string, path: string, html: string)
  : Promise<{ html: string; title: string }>
{
  const doc = new DOMParser().parseFromString(html, "text/html");

  const links = Array.from(doc.querySelectorAll('link[rel="stylesheet"][href]'));
  await Promise.all(links.map(async (el) => {
    const href = el.getAttribute("href")!;
    if (/^https?:/.test(href)) return;             // external CSS: not ours to fetch
    const css = await fetchHs(hsId, resolvePath(path, href));
    if (css == null) return;
    const style = doc.createElement("style");
    style.textContent = css;
    el.replaceWith(style);
  }));

  const scripts = Array.from(doc.querySelectorAll("script[src]"));
  await Promise.all(scripts.map(async (el) => {
    const src = el.getAttribute("src")!;
    if (/^https?:/.test(src)) return;
    const js = await fetchHs(hsId, resolvePath(path, src));
    if (js == null) return;
    const s = doc.createElement("script");
    s.textContent = js;
    el.replaceWith(s);
  }));

  // Images: same story as CSS — the iframe can't resolve "/logo.png", so
  // fetch the bytes over the hidden service and embed them.
  const imgs = Array.from(doc.querySelectorAll("img[src]"));
  await Promise.all(imgs.map(async (el) => {
    const src = el.getAttribute("src")!;
    if (/^(https?:|data:)/.test(src)) return;
    const p = resolvePath(path, src);
    const bytes = await fetchHsBytes(hsId, p);
    if (bytes) el.setAttribute("src", dataUri(bytes, p));
  }));

  // Lock the page down before it runs.
  //
  // Everything it needs is already inlined, so it has no legitimate reason to
  // touch the network — and every illegitimate one deanonymises the reader:
  // one fetch() to a clearnet host and the site learns the real IP of someone
  // who came to it over an anonymous circuit. The iframe is sandboxed but
  // sandboxing doesn't stop outbound requests, so state it explicitly.
  const csp = doc.createElement("meta");
  csp.setAttribute("http-equiv", "Content-Security-Policy");
  csp.setAttribute("content", [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    "script-src 'unsafe-inline'",
    "img-src data:",
    "font-src data:",
    "connect-src 'none'",     // no fetch/XHR/WebSocket, to anywhere
    "form-action 'none'",
    "frame-src 'none'",
    "base-uri 'none'",
  ].join("; "));
  doc.head.insertBefore(csp, doc.head.firstChild);

  const hook = doc.createElement("script");
  hook.textContent = NAV_HOOK_JS;
  doc.body.appendChild(hook);

  const title = (doc.querySelector("title")?.textContent || "").trim();
  return { html: "<!DOCTYPE html>" + doc.documentElement.outerHTML, title };
}

type Site = { id: string; path: string };
type Mark = { id: string; path: string; title: string };

const BM_KEY = "phinet.bookmarks";
const loadMarks = (): Mark[] => {
  try { return JSON.parse(localStorage.getItem(BM_KEY) || "[]"); } catch { return []; }
};
const saveMarks = (m: Mark[]) => {
  try { localStorage.setItem(BM_KEY, JSON.stringify(m)); } catch { /* full/blocked */ }
};

export default function Browser() {
  const [bar, setBar] = useState("");
  const [mode, setMode] = useState<"home" | "loading" | "web" | "phinet" | "error">("home");
  const [webUrl, setWebUrl] = useState("");
  const [phinetHtml, setPhinetHtml] = useState("");
  const [errMsg, setErrMsg] = useState("");
  const [showCircuit, setShowCircuit] = useState(false);
  const [stage, setStage] = useState("");
  // Session history: entries are sites we've loaded; `hi` is where we are in it.
  const [hist, setHist] = useState<Site[]>([]);
  const [hi, setHi] = useState(-1);
  const [marks, setMarks] = useState<Mark[]>(loadMarks);
  const [title, setTitle] = useState("");

  const site = hi >= 0 ? hist[hi] : null;

  const load = async (s: Site, push: boolean) => {
    setMode("loading");
    // A fetch can take 15-30s: descriptor lookup, then two circuits, then the
    // rendezvous. Naming the stage beats a spinner that looks like a hang.
    setStage("Resolving the address on the network…");
    const t = setTimeout(() => setStage("Building circuits and rendezvousing… this can take ~30s"), 2500);
    const html = await fetchHs(s.id, s.path);
    clearTimeout(t);
    if (html == null) {
      setErrMsg(`Couldn't reach ${s.id.slice(0, 12)}….phinet — is the node connected, and are there enough relays for a circuit?`);
      setMode("error");
      return;
    }
    setStage("Loading page resources…");
    const { html: full, title: t2 } = await inlineResources(s.id, s.path, html);
    setPhinetHtml(full);
    setTitle(t2);
    setBar(s.id + ".phinet" + (s.path === "/" ? "" : s.path));
    if (push) {
      setHist((h) => [...h.slice(0, hi + 1), s]);
      setHi((i) => i + 1);
    }
    setMode("phinet");
  };

  const openHs = (id: string, path: string) => load({ id, path }, true);

  const back    = () => { if (hi > 0) { setHi(hi - 1); load(hist[hi - 1], false); } };
  const forward = () => { if (hi < hist.length - 1) { setHi(hi + 1); load(hist[hi + 1], false); } };
  const reload  = () => { if (site) load(site, false); };

  const isMarked = !!site && marks.some((m) => m.id === site.id && m.path === site.path);
  const toggleMark = () => {
    if (!site) return;
    const next = isMarked
      ? marks.filter((m) => !(m.id === site.id && m.path === site.path))
      : [...marks, { id: site.id, path: site.path, title: title || site.id.slice(0, 12) + "…" }];
    setMarks(next); saveMarks(next);
  };

  // In-site link clicks arrive from the injected hook in the rendered page.
  useEffect(() => {
    const onMsg = (e: MessageEvent) => {
      const href = (e.data || {}).phinetNav;
      if (typeof href === "string" && site) {
        openHs(site.id, resolvePath(site.path, href));
      }
    };
    window.addEventListener("message", onMsg);
    return () => window.removeEventListener("message", onMsg);
  }, [site, hi, hist]);

  const go = async (raw: string) => {
    const s = raw.trim();
    if (!s) { setMode("home"); return; }
    if (s.includes(".phinet")) {
      const clean = s.replace(/^\w+:\/\//, "");
      const host = clean.split("/")[0].replace(/\.phinet$/, "");
      const path = clean.slice(clean.indexOf("/") >= 0 ? clean.indexOf("/") : clean.length) || "/";
      await openHs(host, path);
      return;
    }
    const url = /^https?:\/\//.test(s) ? s
      : s.includes(".") && !s.includes(" ") ? "https://" + s
      : "https://duckduckgo.com/?q=" + encodeURIComponent(s);
    // Clearnet opens in a real webview window — an iframe is blocked by most
    // sites (X-Frame-Options / CSP). Note: clearnet is a DIRECT connection,
    // not routed through ΦNET.
    setWebUrl(url); setMode("web");
    try { await invoke("open_web", { url }); } catch { /* iframe fallback still renders */ }
  };

  return (
    <div className="browser">
      {mode === "home" ? (
        <div className="bhome">
          <div className="butil">
            <button className="iconbtn" title="Circuit" onClick={() => setShowCircuit(true)}>⛓</button>
          </div>
          <div className="blogo"><span className="phi">Φ</span>NET</div>
          <div className="btag">private overlay browser</div>
          <div className="bsearch">
            <span className="bmag">⌕</span>
            <input autoFocus value={bar} placeholder="Search the web or open <id>.phinet"
              onChange={(e) => setBar(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && go(bar)} />
          </div>
          <div className="bchips">
            {[["duckduckgo.com", "Search"], ["news.ycombinator.com", "HN"]].map(([u, l]) => (
              <button key={u} onClick={() => { setBar(u); go(u); }}>{l}</button>
            ))}
          </div>
          {marks.length > 0 && (
            <div className="bmarks">
              <div className="bmarks-head">Saved .phinet sites</div>
              {marks.map((m, i) => (
                <div key={i} className="bmark">
                  <button className="bmark-go" onClick={() => openHs(m.id, m.path)}>
                    <span className="bmark-title">{m.title}</span>
                    <span className="bmark-id">{m.id.slice(0, 16)}…phinet{m.path === "/" ? "" : m.path}</span>
                  </button>
                  <button className="bmark-x" title="Remove"
                    onClick={() => { const n = marks.filter((_, j) => j !== i); setMarks(n); saveMarks(n); }}>×</button>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="baddr">
            <button className="iconbtn" title="Back" disabled={hi <= 0} onClick={back}>‹</button>
            <button className="iconbtn" title="Forward" disabled={hi >= hist.length - 1} onClick={forward}>›</button>
            <button className="iconbtn" title="Reload" disabled={!site} onClick={reload}>↻</button>
            <button className="iconbtn" title="Home" onClick={() => { setBar(""); setMode("home"); }}>⌂</button>
            {/* The two networks look identical in an address bar but one is
                anonymous and the other isn't. Say which, always. */}
            {mode === "phinet" && <span className="netbadge onion">ΦNET · HS</span>}
            {mode === "web"    && <span className="netbadge clear">clearnet · direct</span>}
            <input value={bar} placeholder="Search or <id>.phinet"
              onChange={(e) => setBar(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && go(bar)} />
            <button className={"iconbtn" + (isMarked ? " on" : "")} title={isMarked ? "Remove bookmark" : "Bookmark"}
              disabled={!site} onClick={toggleMark}>{isMarked ? "★" : "☆"}</button>
            <button className="iconbtn" title="Circuit" onClick={() => setShowCircuit(true)}>⛓</button>
          </div>
          <div className="bview">
            {mode === "loading" && (
              <div className="bcenter">
                <div className="bload">
                  <div className="spinner" />
                  <div className="bload-stage">{stage}</div>
                </div>
              </div>
            )}
            {mode === "error" && (
              <div className="bcenter"><div className="berr">{errMsg}</div></div>
            )}
            {mode === "phinet" && (
              <iframe title="phinet" className="bframe" sandbox="allow-forms allow-scripts"
                srcDoc={phinetHtml} />
            )}
            {mode === "web" && (
              <div className="bcenter">
                <div className="bweb-note">
                  <div className="bweb-url">{webUrl}</div>
                  <div className="bweb-sub">Opened in a web window.</div>
                  <div className="bweb-warn">
                    Clearnet is a direct connection — not routed through ΦNET.
                    Only <b>.phinet</b> sites go through the network.
                  </div>
                  <button className="bweb-again" onClick={() => invoke("open_web", { url: webUrl })}>
                    Reopen window
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
      {showCircuit && <CircuitPanel onClose={() => setShowCircuit(false)} />}
    </div>
  );
}

function CircuitPanel({ onClose }: { onClose: () => void }) {
  const [ci, setCi] = useState<Circuit | null>(null);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);

  const load = async () => {
    setLoading(true);
    const r: any = await invoke("circuit_info");
    setCi(r && r.node_id ? r : null);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="modal" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card">
        <h3>This ΦNET circuit</h3>
        <p className="foot">Your traffic enters through these relays. Request a new identity to rebuild through fresh relays.</p>
        {loading ? <div className="spinner" /> : !ci ? (
          <div className="berr">Couldn't read circuit — is the node running?</div>
        ) : (
          <div className="circuit">
            <Hop label="You" id={ci.node_id} host="this device" you />
            {(ci.path && ci.path.length > 0) ? (
              ci.path.map((h, i) => (
                <div key={i}>
                  <span className="conn" />
                  <Hop label={roleLabel(h.role)} id={h.node_id} host={h.host} />
                </div>
              ))
            ) : (
              <div className="foot" style={{ marginTop: 8 }}>
                No circuit built yet — need more independent relays to form a path.
              </div>
            )}
          </div>
        )}
        <button className="newbtn wide" disabled={rotating || loading}
          onClick={async () => { setRotating(true); await invoke("new_identity"); await new Promise(r => setTimeout(r, 700)); await load(); setRotating(false); }}>
          {rotating ? "Rotating…" : "↻ New identity"}
        </button>
      </div>
    </div>
  );
}

function roleLabel(role: string): string {
  switch (role) {
    case "guard":  return "Guard (entry)";
    case "middle": return "Middle";
    case "exit":   return "Exit";
    case "single": return "Relay (single hop)";
    default:       return role;
  }
}

function Hop({ label, id, host, you }: { label: string; id: string; host: string; you?: boolean }) {
  return (
    <div className="hop">
      <span className={"hopdot" + (you ? " you" : "")} />
      <div>
        <div className="hoplabel">{label}</div>
        <div className="hopsub">{host ? `${host} · ${short(id)}` : short(id)}</div>
      </div>
    </div>
  );
}
