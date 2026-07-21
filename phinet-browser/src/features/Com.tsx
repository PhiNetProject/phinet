import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

type Msg = { outgoing: boolean; timestamp: number; body: string };

// ── ΦNET envelopes ────────────────────────────────────────────────────
// com carries plain text, so richer payloads are tagged with a \u0001 prefix
// and rendered as cards. These formats are the Android app's — both clients
// must agree byte-for-byte or a share arrives as a wall of base64.
const VAULT_PREFIX = "\u0001phinet-vault\u0001";
const FILE_PREFIX  = "\u0001phinet-file\u0001";

type FileHeader = { fileId: string; name: string; mime: string; total: number; index: number };

const isFileChunk  = (b: string) => b.startsWith(FILE_PREFIX);
const isVaultShare = (b: string) => b.startsWith(VAULT_PREFIX);

/** `\u0001phinet-file\u0001 <base64(headerJson)> | <base64(chunk)>` */
function parseFileChunk(body: string): { header: FileHeader; bytes: Uint8Array } | null {
  if (!isFileChunk(body)) return null;
  const rest = body.slice(FILE_PREFIX.length);
  const sep = rest.indexOf("|");
  if (sep < 0) return null;
  try {
    const header: FileHeader = JSON.parse(atob(rest.slice(0, sep)));
    const bin = atob(rest.slice(sep + 1));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return { header, bytes };
  } catch { return null; }
}

function parseVaultShare(body: string): any | null {
  if (!isVaultShare(body)) return null;
  try { return JSON.parse(body.slice(VAULT_PREFIX.length)); } catch { return null; }
}

/**
 * Reassemble chunked files from a thread's messages. The sender splits a file
 * into 12 KiB base64 chunks; chunks are idempotent and may arrive more than
 * once, so index into a map rather than appending.
 */
function collectFiles(messages: Msg[]) {
  const acc = new Map<string, { header: FileHeader; parts: Map<number, Uint8Array>; outgoing: boolean; ts: number }>();
  for (const m of messages) {
    const c = parseFileChunk(m.body);
    if (!c) continue;
    const e = acc.get(c.header.fileId) ??
      { header: c.header, parts: new Map(), outgoing: m.outgoing, ts: m.timestamp };
    e.parts.set(c.header.index, c.bytes);
    e.ts = Math.max(e.ts, m.timestamp);
    acc.set(c.header.fileId, e);
  }
  return acc;
}

function joinChunks(parts: Map<number, Uint8Array>, total: number): Uint8Array {
  const ordered: Uint8Array[] = [];
  for (let i = 0; i < total; i++) ordered.push(parts.get(i) ?? new Uint8Array(0));
  const len = ordered.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const b of ordered) { out.set(b, o); o += b.length; }
  return out;
}


type Peer = { node_id: string; static_pub: string; host: string; port: number };
type Grp = { group_id: string; name: string; is_channel: boolean; thread_id: string };

const shortId = (id: string) => (id.length > 12 ? id.slice(0, 6) + "…" + id.slice(-4) : id);

function color(id: string): string {
  let h = 0;
  for (const c of id) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return `hsl(${h % 360} 55% 45%)`;
}

function Avatar({ id }: { id: string }) {
  return (
    <div className="avatar" style={{ background: color(id) }}>
      {id.slice(0, 2).toUpperCase()}
    </div>
  );
}

export default function Com() {
  const [me, setMe] = useState<string>("");
  const [online, setOnline] = useState(false);
  const [threads, setThreads] = useState<string[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [groups, setGroups] = useState<Grp[]>([]);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [addr, setAddr] = useState("");
  const [myAddr, setMyAddr] = useState("");
  const msgsRef = useRef<HTMLDivElement>(null);
  const [toast, setToast] = useState("");
  const [createKind, setCreateKind] = useState<null | boolean>(null); // null=closed, false=group, true=channel
  const [createName, setCreateName] = useState("");
  const [inviteFor, setInviteFor] = useState<string | null>(null);
  const [invitePeers, setInvitePeers] = useState<Peer[]>([]);

  const call = useCallback(async <T,>(cmd: string, args?: any): Promise<T | null> => {
    try {
      const r: any = await invoke(cmd, args);
      setOnline(!(r && r.error === "daemon offline"));
      return r as T;
    } catch {
      setOnline(false);
      return null;
    }
  }, []);

  const loadThreads = useCallback(async () => {
    const r = await call<{ threads: string[] }>("com_threads");
    if (r?.threads) setThreads(r.threads);
    const g = await call<{ groups: Grp[] }>("com_groups");
    if (g?.groups) setGroups(g.groups);
  }, [call]);

  const openGroup = async (g: Grp) => {
    setActive(g.thread_id);
    setActiveGroup(g.group_id);
    await loadMessages(g.thread_id);
  };

  const doCreateGroup = async () => {
    const name = createName.trim();
    if (name === "" || createKind === null) return;
    const r = await call<Grp>("com_create_group", { name, isChannel: createKind });
    setCreateKind(null); setCreateName("");
    if (r?.group_id) { await loadThreads(); openGroup(r as Grp); }
    else setToast("Couldn't create — daemon offline?");
  };

  const openInvite = async (groupId: string) => {
    const r = await call<{ peers: Peer[] }>("peers");
    setInvitePeers(r?.peers ?? []);
    setInviteFor(groupId);
  };
  const doInvite = async (peer: string) => {
    const gid = inviteFor; setInviteFor(null);
    if (!gid) return;
    const res = await call<{ ok?: boolean; error?: string }>("com_invite", { groupId: gid, peer });
    setToast(res?.ok ? "Invite sent" : "Invite failed: " + (res?.error ?? "offline"));
  };

  const loadMessages = useCallback(async (peer: string) => {
    const r = await call<{ messages: Msg[] }>("com_thread", { peer });
    if (r?.messages) setMessages(r.messages);
  }, [call]);

  useEffect(() => {
    (async () => {
      const w = await call<{ node_id: string }>("whoami");
      if (w?.node_id) setMe(w.node_id);
      await loadThreads();
    })();
  }, [call, loadThreads]);

  // Poll active thread + thread list.
  useEffect(() => {
    const t = setInterval(() => {
      loadThreads();
      if (active) loadMessages(active);
    }, 2000);
    return () => clearInterval(t);
  }, [active, loadThreads, loadMessages]);

  // Switching threads always lands at the newest message.
  useEffect(() => {
    const el = msgsRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [active]);

  useEffect(() => {
    const el = msgsRef.current;
    if (!el) return;
    // Only follow new messages if you're already at the bottom. The thread
    // re-polls every few seconds, so an unconditional scroll would drag you
    // back down mid-sentence every time you tried to read anything older.
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 140;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [messages]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 2400);
    return () => clearTimeout(t);
  }, [toast]);

  const openThread = async (peer: string) => {
    setActive(peer);
    setActiveGroup(null);
    await loadMessages(peer);
  };

  const send = async () => {
    const text = draft.trim();
    if (!text || !active) return;
    setDraft("");
    const r = activeGroup
      ? await call<{ ok?: boolean; error?: string }>("com_send_group", { groupId: activeGroup, text })
      : await call<{ ok?: boolean; error?: string }>("com_send", { peer: active, text });
    if (r?.error) setToast("Send failed: " + r.error);
    await loadMessages(active);
    await loadThreads();
  };

  const openNew = async () => {
    const r = await call<{ peers: Peer[] }>("peers");
    const list = r?.peers ?? [];
    setPeers(list);
    const nm: Record<string, string> = {};
    for (const p of list) nm[p.node_id] = `${p.host}:${p.port}`;
    setNames((prev) => ({ ...prev, ...nm }));
    const a = await call<{ address: string }>("com_my_address");
    setMyAddr(a?.address ?? "");
    setShowNew(true);
  };

  const addContact = async () => {
    const a = addr.trim();
    if (!a) return;
    const r = await call<{ node_id?: string; error?: string }>("com_add_contact", { address: a });
    if (r?.node_id) {
      setAddr("");
      setShowNew(false);
      openThread(r.node_id);
    } else {
      setToast(r?.error ?? "Invalid address");
    }
  };

  return (
    <div className="app">
      <aside className="side">
        <div className="me">
          <div className="name">com · ΦNET</div>
          <div className="id">{me ? shortId(me) : "connecting…"}</div>
        </div>
        <button className="newbtn" onClick={openNew}>+ New chat</button>
        <div style={{ display: "flex", gap: 8, margin: "0 12px 6px" }}>
          <button className="newbtn" style={{ flex: 1, margin: 0, background: "#2ea043" }}
            onClick={() => { setCreateKind(false); setCreateName(""); }}>+ Group</button>
          <button className="newbtn" style={{ flex: 1, margin: 0, background: "#1f6feb" }}
            onClick={() => { setCreateKind(true); setCreateName(""); }}>+ Channel</button>
        </div>
        <div className="threads">
          {groups.map((g) => (
            <div
              key={g.group_id}
              className={"thread" + (g.thread_id === active ? " active" : "")}
              onClick={() => openGroup(g)}
            >
              <Avatar id={g.group_id} />
              <div style={{ minWidth: 0 }}>
                <div className="tname">
                  {g.name} {g.is_channel ? "📢" : "👥"}
                </div>
                <div className="tsub">{g.is_channel ? "channel" : "group"}</div>
              </div>
            </div>
          ))}
          {threads
            .filter((id) => !groups.some((g) => g.thread_id === id))
            .map((id) => (
              <div
                key={id}
                className={"thread" + (id === active && !activeGroup ? " active" : "")}
                onClick={() => openThread(id)}
              >
                <Avatar id={id} />
                <div style={{ minWidth: 0 }}>
                  <div className="tname">{names[id] ?? shortId(id)}</div>
                  <div className="tsub">{shortId(id)}</div>
                </div>
              </div>
            ))}
        </div>
        <div className="status">
          <span className={"dot " + (online ? "ok" : "bad")} />
          {online ? "connected to daemon" : "daemon offline"}
        </div>
      </aside>

      <main className="main">
        {active ? (
          <>
            <div className="topbar">
              <Avatar id={active} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="tname">{names[active] ?? shortId(active)}</div>
                <div className="tsub">{active}</div>
              </div>
              {activeGroup && (
                <button className="newbtn" style={{ margin: 0, padding: "6px 12px" }}
                  onClick={() => openInvite(activeGroup)}>Invite</button>
              )}
            </div>
            <div className="msgs" ref={msgsRef}>
              {messages.length === 0 ? (
                <div className="empty">No messages yet. Say hi 👋</div>
              ) : (
                <>
                  {/* File chunks are collapsed into one card per file rather
                      than rendered as dozens of base64 bubbles. */}
                  {messages.filter((m) => !isFileChunk(m.body)).map((m, i) => {
                    const share = parseVaultShare(m.body);
                    return (
                      <div key={i} className={"bubble " + (m.outgoing ? "out" : "in")}>
                        {share ? <VaultCard item={share} /> : m.body}
                        <span className="t">
                          {new Date(m.timestamp * 1000).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      </div>
                    );
                  })}
                  {Array.from(collectFiles(messages).entries()).map(([id, f]) => (
                    <div key={id} className={"bubble " + (f.outgoing ? "out" : "in")}>
                      <FileCard header={f.header} parts={f.parts} />
                      <span className="t">
                        {new Date(f.ts * 1000).toLocaleTimeString([], {
                          hour: "2-digit", minute: "2-digit",
                        })}
                      </span>
                    </div>
                  ))}
                </>
              )}
            </div>
            <div className="composer">
              <input
                value={draft}
                placeholder="Message (encrypted end-to-end)…"
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && send()}
              />
              <button onClick={send}>Send</button>
            </div>
          </>
        ) : (
          <div className="empty">
            Pick a conversation or start a new chat.
            <br />
            Messages are end-to-end encrypted and routed over ΦNET.
          </div>
        )}
      </main>

      {showNew && (
        <div className="modal" onClick={(e) => e.target === e.currentTarget && setShowNew(false)}>
          <div className="card">
            <h3>New chat</h3>
            <div className="plist">
              {peers.length === 0 ? (
                <div className="foot">No linked peers. Add a contact by address below.</div>
              ) : (
                peers.map((p) => (
                  <div
                    key={p.node_id}
                    className="pitem"
                    onClick={() => {
                      setShowNew(false);
                      openThread(p.node_id);
                    }}
                  >
                    <Avatar id={p.node_id} />
                    <div style={{ minWidth: 0 }}>
                      <div className="tname">
                        {p.host}:{p.port}
                      </div>
                      <div className="pid">{p.node_id}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
              <input
                value={addr}
                onChange={(e) => setAddr(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addContact()}
                placeholder="Paste a phi: address"
                style={{ flex: 1, minWidth: 0, padding: 8, borderRadius: 8, border: "1px solid #334155", background: "#0f172a", color: "#e2e8f0" }}
              />
              <button className="newbtn" onClick={addContact}>Add</button>
            </div>
            <div className="foot">
              Message a linked peer above, or add someone by the address they gave you.
              There is no public list of users — you can only reach people whose address you hold.
            </div>
            <div className="foot" style={{ wordBreak: "break-all" }}>
              Your address (share out of band):{" "}
              <code>{myAddr}</code>{" "}
              <button
                className="newbtn"
                style={{ padding: "2px 8px" }}
                onClick={() => myAddr && navigator.clipboard?.writeText(myAddr)}
              >
                copy
              </button>
            </div>
          </div>
        </div>
      )}

      {createKind !== null && (
        <div className="modal" onClick={(e) => e.target === e.currentTarget && setCreateKind(null)}>
          <div className="card">
            <h3>{createKind ? "New channel" : "New group"}</h3>
            <p className="foot">{createKind
              ? "A channel broadcasts to members who join."
              : "A group is a shared, end-to-end encrypted thread."}</p>
            <input
              autoFocus
              value={createName}
              onChange={(e) => setCreateName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doCreateGroup()}
              placeholder={createKind ? "Channel name" : "Group name"}
            />
            <button className="newbtn wide" onClick={doCreateGroup}>
              {createKind ? "Create channel" : "Create group"}
            </button>
          </div>
        </div>
      )}

      {inviteFor !== null && (
        <div className="modal" onClick={(e) => e.target === e.currentTarget && setInviteFor(null)}>
          <div className="card">
            <h3>Invite a peer</h3>
            {invitePeers.length === 0 ? (
              <p className="foot">No connected peers to invite right now.</p>
            ) : (
              <div className="invite-list">
                {invitePeers.map((p) => (
                  <button key={p.node_id} className="invite-row" onClick={() => doInvite(p.node_id)}>
                    <span className="ir-host">{p.host}:{p.port}</span>
                    <span className="ir-id">{shortId(p.node_id)}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

/** A vault item shared over com — shown as a card, not raw JSON. */
function VaultCard({ item }: { item: any }) {
  const [show, setShow] = useState(false);
  const icon = item.kind === "link" ? "🔗" : item.kind === "secret" ? "🔑"
             : item.kind === "file" ? "📄" : "📝";
  return (
    <div className="vshare">
      <div className="vshare-head">{icon} {item.title || item.kind}</div>
      {item.kind === "secret" ? (
        <div className="vshare-body" onClick={() => setShow(!show)} style={{ cursor: "pointer" }}>
          {show ? item.content : "•••••••• (tap to reveal)"}
        </div>
      ) : (
        <div className="vshare-body">{item.content}</div>
      )}
    </div>
  );
}

/** A chunked file arriving over com: progress until complete, then save. */
function FileCard({ header, parts }: { header: FileHeader; parts: Map<number, Uint8Array> }) {
  const have = parts.size;
  const done = have >= header.total;
  const save = async () => {
    const bytes = joinChunks(parts, header.total);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    // Straight into the vault: a file that arrived over an anonymous circuit
    // shouldn't be dropped into the filesystem in the clear as a side effect
    // of viewing it.
    await invoke("vault_add_file_b64", {
      name: header.name, mime: header.mime, b64: btoa(bin),
    });
  };
  return (
    <div className="vshare">
      <div className="vshare-head">📄 {header.name}</div>
      <div className="vshare-body">
        {done ? `${header.mime} · ${(joinChunks(parts, header.total).length / 1024).toFixed(0)} KB`
              : `Receiving… ${have}/${header.total} chunks`}
      </div>
      {done && <button className="vshare-btn" onClick={save}>Save to vault</button>}
    </div>
  );
}
