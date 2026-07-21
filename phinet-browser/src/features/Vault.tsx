import { useState, useEffect } from "react";
import { invoke, convertFileSrc } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { open as openPath } from "@tauri-apps/plugin-shell";

type Item = {
  id: string; kind: string; title: string; content: string;
  file_name: string; mime: string; size: number;
};

const icon = (k: string) => (k === "link" ? "🔗" : k === "note" ? "📝" : k === "file" ? "📎" : "🔑");

export default function Vault() {
  const [status, setStatus] = useState<{ exists: boolean; unlocked: boolean }>({ exists: false, unlocked: false });
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [items, setItems] = useState<Item[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState("");
  const [viewing, setViewing] = useState<Item | null>(null);
  const [sharing, setSharing] = useState<Item | null>(null);

  const refresh = async () => {
    const s: any = await invoke("vault_status");
    setStatus({ exists: !!s.exists, unlocked: !!s.unlocked });
    if (s.unlocked) { const r: any = await invoke("vault_list"); if (r?.ok) setItems(r.items); }
  };
  useEffect(() => { refresh(); }, []);
  useEffect(() => { if (toast) { const t = setTimeout(() => setToast(""), 2200); return () => clearTimeout(t); } }, [toast]);

  const unlock = async () => {
    if (pass.length < 6) { setErr("Use at least 6 characters"); return; }
    setBusy(true); setErr("");
    const cmd = status.exists ? "vault_unlock" : "vault_create";
    const r: any = await invoke(cmd, { passphrase: pass });
    setBusy(false);
    if (r?.ok) { setPass(""); await refresh(); }
    else setErr(r?.error ?? "failed");
  };

  const importFile = async () => {
    const sel = await openDialog({ multiple: false });
    if (!sel || Array.isArray(sel)) return;
    const r: any = await invoke("vault_import", { path: sel });
    if (r?.ok) setItems(r.items); else setToast(r?.error ?? "import failed");
  };

  const reveal = async (it: Item) => {
    const r: any = await invoke("vault_reveal", { id: it.id });
    if (r?.ok) { try { await openPath(r.path); } catch { setToast("Saved to: " + r.path); } }
    else setToast(r?.error ?? "couldn't open");
  };

  const del = async (id: string) => {
    const r: any = await invoke("vault_delete", { id });
    if (r?.ok) setItems(r.items);
  };

  if (!status.unlocked) {
    return (
      <div className="vault-gate">
        <div className="vg-lock">🔒</div>
        <h2>{status.exists ? "Unlock your vault" : "Create your vault"}</h2>
        <p className="foot">Encrypted with XChaCha20-Poly1305; the key is derived from your passphrase (Argon2id) and never leaves this device.</p>
        <input type="password" value={pass} placeholder="Passphrase"
          onChange={(e) => setPass(e.target.value)} onKeyDown={(e) => e.key === "Enter" && unlock()} />
        {err && <div className="berr">{err}</div>}
        <button className="newbtn wide" disabled={busy} onClick={unlock}>
          {busy ? "Working…" : status.exists ? "Unlock" : "Create vault"}
        </button>
      </div>
    );
  }

  return (
    <div className="vault">
      <div className="vault-top">
        <div className="vname">Vault</div>
        <div className="vactions">
          <button className="newbtn" style={{ margin: 0 }} onClick={importFile}>⬆ Import file</button>
          <button className="newbtn" style={{ margin: 0 }} onClick={() => setShowAdd(true)}>+ Add</button>
          <button className="iconbtn" title="Lock" onClick={async () => { await invoke("vault_lock"); refresh(); }}>🔒</button>
        </div>
      </div>
      {items.length === 0 ? (
        <div className="empty">Your vault is empty. Add links, notes, secrets, or import a file.</div>
      ) : (
        <div className="vlist">
          {items.map((it) => (
            <div key={it.id} className="vcard">
              <div className="vic">{icon(it.kind)}</div>
              <div className="vmeta" onClick={() => setViewing(it)} style={{ cursor: "pointer" }}>
                <div className="vtitle">{it.title || "(untitled)"}</div>
                <div className="vsub">{it.kind === "secret" ? "••••••••" : it.kind === "file" ? `${it.mime} · ${(it.size / 1024).toFixed(0)} KB` : it.content}</div>
              </div>
              <button className="iconbtn" title="Share over ΦNET" onClick={() => setSharing(it)}>⇪</button>
              <button className="iconbtn" title="Delete" onClick={() => del(it.id)}>🗑</button>
            </div>
          ))}
        </div>
      )}
      {viewing && <ViewSheet item={viewing} onClose={() => setViewing(null)}
                    onExternal={() => reveal(viewing)} />}
      {sharing && <ShareSheet item={sharing} onClose={() => setSharing(null)} onToast={setToast} />}
      {showAdd && <AddSheet onClose={() => setShowAdd(false)} onAdded={(list) => { setItems(list); setShowAdd(false); }} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function AddSheet({ onClose, onAdded }: { onClose: () => void; onAdded: (l: Item[]) => void }) {
  const [kind, setKind] = useState("link");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const save = async () => {
    if (!content.trim()) return;
    const r: any = await invoke("vault_add", { kind, title, content });
    if (r?.ok) onAdded(r.items);
  };
  return (
    <div className="modal" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card">
        <h3>Add to vault</h3>
        <div className="seg">
          {["link", "note", "secret"].map((k) => (
            <button key={k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
              {k[0].toUpperCase() + k.slice(1)}
            </button>
          ))}
        </div>
        <input placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
        <input placeholder={kind === "link" ? "URL" : kind === "note" ? "Note" : "Secret"}
          value={content} onChange={(e) => setContent(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()} />
        <button className="newbtn wide" onClick={save}>Save</button>
      </div>
    </div>
  );
}

// ── viewer ────────────────────────────────────────────────────────────
// Renders vault contents inside the app: images, video, audio, PDF, text and
// notes. Bytes arrive over the `vault://` protocol, which decrypts on demand
// and answers range requests — so media seeks properly, a large file costs no
// more memory than a small one, and nothing is written to disk. Opening
// externally is still offered, but it's an explicit choice with a warning,
// because that path does leave a decrypted copy behind.
function ViewSheet({ item, onClose, onExternal }:
  { item: Item; onClose: () => void; onExternal: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [show, setShow] = useState(false);
  // Set when the webview refuses the media. Distinct from `err`: the bytes
  // are fine, the decoder isn't.
  const [mediaErr, setMediaErr] = useState(false);

  // Media streams straight from the vault:// protocol — the webview asks for
  // byte ranges as it plays or scrolls, so a 2 GB video costs no more memory
  // than a thumbnail and never lands on disk as plaintext. Only text is
  // fetched up front, since we have to put it in the DOM anyway.
  // Custom schemes aren't spelled the same everywhere: Linux/macOS get
  // vault://…, Windows and Android get http://vault.localhost/…. Let Tauri
  // decide rather than hardcoding one and breaking the others.
  const src = convertFileSrc(item.id, "vault");
  const mime = item.mime || "";
  const is = (p: string) => mime.startsWith(p);

  const isImage = is("image/");
  const isVideo = is("video/");
  const isAudio = is("audio/");
  const isPdf   = mime === "application/pdf";
  const isText  = is("text/") || /json|xml|javascript|x-sh/.test(mime);

  useEffect(() => {
    if (item.kind !== "file" || !isText) return;
    let dead = false;
    (async () => {
      try {
        // 2 MB is plenty for a text file and keeps a mislabelled binary from
        // locking the UI while we stringify it.
        const r = await fetch(src, { headers: { Range: "bytes=0-2097151" } });
        const t = await r.text();
        if (!dead) setText(t);
      } catch (e: any) {
        if (!dead) setErr(String(e?.message ?? e));
      }
    })();
    return () => { dead = true; };
  }, [item.id, mime]);

  const sizeMb = (item.size / 1024 / 1024).toFixed(1);

  return (
    <div className="modal" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card wide">
        <h3>{item.title || item.file_name || "(untitled)"}</h3>
        <div className="vview">
          {item.kind === "secret" ? (
            <>
              <div className="vsecret">{show ? item.content : "••••••••••••"}</div>
              <button className="newbtn" style={{ margin: 0 }} onClick={() => setShow(!show)}>
                {show ? "Hide" : "Reveal"}
              </button>
            </>
          ) : item.kind === "link" ? (
            <>
              <div className="vlink">{item.content}</div>
              <button className="newbtn" style={{ margin: 0 }}
                onClick={() => invoke("open_web", { url: item.content })}>
                Open in web window
              </button>
              <div className="foot" style={{ padding: "8px 0 0" }}>
                Opens on the clearnet — a direct connection, not through ΦNET.
              </div>
            </>
          ) : item.kind === "note" ? (
            <pre className="vtext">{item.content}</pre>
          ) : err ? (
            <div className="berr">{err}</div>
          ) : isImage ? (
            <img className="vimg" src={src} alt={item.file_name} />
          ) : isVideo ? (
            mediaErr ? <CodecNote name={item.file_name} mime={mime} /> : (
              <video className="vmedia" src={src} controls preload="metadata"
                     onError={() => setMediaErr(true)} />
            )
          ) : isAudio ? (
            mediaErr ? <CodecNote name={item.file_name} mime={mime} /> : (
              <>
                <div className="foot" style={{ padding: 0 }}>{item.file_name}</div>
                <audio src={src} controls style={{ width: "100%" }}
                       onError={() => setMediaErr(true)} />
              </>
            )
          ) : isPdf ? (
            <>
              {/* WebView2 and WKWebView render PDFs natively; WebKitGTK
                  (Linux) does not, so this can come up blank there — hence the
                  fallback line rather than a bare grey box. */}
              <object className="vpdf" data={src} type="application/pdf">
                <div className="foot" style={{ padding: 0 }}>
                  This webview can't display PDFs inline. Open it externally instead.
                </div>
              </object>
            </>
          ) : isText ? (
            text === null ? <div className="spinner" /> : <pre className="vtext">{text}</pre>
          ) : (
            <div className="foot" style={{ padding: 0 }}>
              {mime || "unknown type"} · {sizeMb} MB — no in-app preview for this
              format. Office documents and archives need an external app.
            </div>
          )}
        </div>
        {item.kind === "file" && (
          <button className="newbtn wide" onClick={onExternal}>
            Open externally (writes a decrypted copy to disk)
          </button>
        )}
      </div>
    </div>
  );
}

/// Shown when the webview can't decode a file the vault handed it correctly.
///
/// This is a codec problem, not a vault problem, and the difference matters:
/// the bytes decrypted fine. On Linux the app runs inside WebKitGTK, which
/// leans on the system's GStreamer plugins — a stock Debian install often has
/// no H.264 decoder, so an ordinary MP4 fails here while playing fine in VLC.
/// Containers like MKV and AVI generally don't work in any webview.
function CodecNote({ name, mime }: { name: string; mime: string }) {
  return (
    <div className="foot" style={{ padding: 0, lineHeight: 1.5 }}>
      <strong>{name}</strong> decrypted fine, but this window can't decode it
      ({mime || "unknown format"}).
      <br /><br />
      On Linux the app uses the system's media plugins, and a stock install
      often lacks the H.264 decoder most MP4s need. MKV and AVI rarely play in
      any webview. Either install the codecs:
      <br />
      <code style={{ userSelect: "text" }}>
        sudo apt install gstreamer1.0-libav gstreamer1.0-plugins-good gstreamer1.0-plugins-bad
      </code>
      <br /><br />
      …or use <em>Open externally</em> below, which writes a decrypted copy to
      disk and hands it to your normal player.
    </div>
  );
}

// ── share ─────────────────────────────────────────────────────────────
// Mirrors the Android contract: a vault item is sent to a com contact as a
// tagged envelope so the other end renders it as a card, not raw text.
const VAULT_SHARE_PREFIX = "\u0001phinet-vault\u0001";
const FILE_SHARE_PREFIX  = "\u0001phinet-file\u0001";

function ShareSheet({ item, onClose, onToast }:
  { item: Item; onClose: () => void; onToast: (s: string) => void }) {
  const [targets, setTargets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const r: any = await invoke("com_threads");
      setTargets(r?.ok ? (r.threads ?? r.peers ?? []).map((t: any) => t.peer ?? t) : []);
      setLoading(false);
    })();
  }, []);

  const send = async (peer: string) => {
    if (item.kind === "file") {
      // com messages are size-capped, so a file goes as 12 KiB base64 chunks
      // with a small header — the same wire format the Android app uses, so a
      // file sent from either side arrives on the other.
      const r: any = await invoke("vault_read", { id: item.id });
      if (r?.too_large) {
        // Every chunk is a separate sealed com message; a 500 MB video is
        // ~40,000 of them. Refuse rather than wedge the thread for an hour.
        onToast(`${(item.size / 1024 / 1024).toFixed(0)} MB is too big to send over com — it'd be thousands of messages.`);
        onClose(); return;
      }
      if (!r?.ok) { onToast(`Couldn't read file: ${r?.error ?? "unknown"}`); onClose(); return; }
      const hex: string = r.hex;
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);

      const CHUNK = 12 * 1024;
      const total = Math.max(1, Math.ceil(bytes.length / CHUNK));
      const fileId = crypto.randomUUID();
      for (let i = 0; i < total; i++) {
        const slice = bytes.slice(i * CHUNK, (i + 1) * CHUNK);
        let bin = "";
        for (let j = 0; j < slice.length; j++) bin += String.fromCharCode(slice[j]);
        const head = btoa(JSON.stringify({
          fileId, name: r.name || item.title, mime: r.mime || "application/octet-stream",
          total, index: i,
        }));
        const body = FILE_SHARE_PREFIX + head + "|" + btoa(bin);
        const res: any = await invoke("com_send", { peer, text: body });
        if (!res?.ok) { onToast(`Send failed at chunk ${i + 1}/${total}`); onClose(); return; }
        onToast(`Sending… ${i + 1}/${total}`);
      }
      onToast("File sent over ΦNET");
      onClose();
      return;
    }
    const payload = VAULT_SHARE_PREFIX + JSON.stringify({
      kind: item.kind, title: item.title, content: item.content,
    });
    const r: any = await invoke("com_send", { peer, text: payload });
    onToast(r?.ok ? "Shared over ΦNET" : `Share failed: ${r?.error ?? "unknown"}`);
    onClose();
  };

  return (
    <div className="modal" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="card">
        <h3>Share “{item.title || item.kind}”</h3>
        <p className="foot">Sent over ΦNET, sealed to the contact you pick.</p>
        {loading ? <div className="spinner" /> : targets.length === 0 ? (
          <p className="foot">
            No contacts yet. Open Com and add someone by their address first.
          </p>
        ) : (
          <div className="plist">
            {targets.map((t) => (
              <div key={t} className="pitem" onClick={() => send(t)}>
                <span className="pid">{t}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
