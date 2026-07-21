import { useState } from "react";
import Com from "./features/Com";
import Browser from "./features/Browser";
import Vault from "./features/Vault";

type Tab = "com" | "browser" | "vault";

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "com", label: "Com", icon: "💬" },
  { id: "browser", label: "Browser", icon: "🌐" },
  { id: "vault", label: "Vault", icon: "🔒" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("com");
  return (
    <div className="shell">
      <nav className="rail">
        <div className="rail-brand"><span className="phi">Φ</span></div>
        {TABS.map((t) => (
          <button key={t.id} className={"rail-btn" + (tab === t.id ? " active" : "")}
            title={t.label} onClick={() => setTab(t.id)}>
            <span className="rail-ic">{t.icon}</span>
            <span className="rail-lbl">{t.label}</span>
          </button>
        ))}
      </nav>
      {/* All three stay mounted: unmounting on switch threw away their state,
          so a loaded .phinet page (or an in-progress fetch that took 20s to
          build a circuit) vanished the moment you glanced at Com. Hidden
          rather than removed. */}
      <div className="feature">
        <div style={{ display: tab === "com" ? "contents" : "none" }}><Com /></div>
        <div style={{ display: tab === "browser" ? "contents" : "none" }}><Browser /></div>
        <div style={{ display: tab === "vault" ? "contents" : "none" }}><Vault /></div>
      </div>
    </div>
  );
}
