import { useState, useEffect, useRef, useCallback } from "react";

// ── CONSTANTS ────────────────────────────────────────────────────────────────

const STORAGE_KEY = "homstock_v2";

const FOOD_CATEGORIES = [
  "All","Bakery","Dairy & Eggs","Pantry","Produce",
  "Meat & Fish","Snacks","Drinks","Condiments","Frozen","Other"
];

const FOOD_EMOJIS = [
  "🍞","🥚","🥛","🍎","🥩","🧀","🫙","🥫","🧂","🍚",
  "🥦","🍋","🧈","🫒","🥜","🍌","🥕","🧄","🧅","🍅",
  "🫐","🥐","🍵","☕","🧃","🥤","🍦","🧁","🥣","🍳"
];

const SEED_INVENTORY = [
  { id: 1, name:"Bread", emoji:"🍞", category:"Bakery", totalUnits:20, quantity:20, unit:"slices", portionLabel:"slice", lowAlert:4, note:"1 loaf = 20 slices", barcode:"" },
  { id: 2, name:"Eggs", emoji:"🥚", category:"Dairy & Eggs", totalUnits:12, quantity:12, unit:"eggs", portionLabel:"egg", lowAlert:3, note:"1 dozen", barcode:"" },
  { id: 3, name:"Milk", emoji:"🥛", category:"Dairy & Eggs", totalUnits:8, quantity:6, unit:"cups", portionLabel:"cup", lowAlert:2, note:"half gallon = 8 cups", barcode:"" },
];

// ── STYLES ───────────────────────────────────────────────────────────────────

const C = {
  bg:          "#0f0e0c",
  surface:     "#141310",
  card:        "#1a1916",
  border:      "#2e2c28",
  borderDark:  "#3a3834",
  accent:      "#e8c96d",
  accentLight: "#f0dc99",
  accentBg:    "#2a2310",
  accentBorder:"#a8893d",
  text:        "#f2ede4",
  muted:       "#7a7060",
  mutedLight:  "#9a9080",
  danger:      "#e06060",
  dangerBg:    "#2a1515",
  dangerBorder:"#5a2020",
  warn:        "#d4956a",
  warnBg:      "#2a1e10",
  warnBorder:  "#6a3a18",
  greenBg:     "#0f2015",
  shadow:      "0 1px 3px rgba(0,0,0,0.3), 0 1px 2px rgba(0,0,0,0.2)",
  shadowMd:    "0 4px 16px rgba(0,0,0,0.4)",
  shadowLg:    "0 8px 32px rgba(0,0,0,0.5)",
};

// ── HELPERS ──────────────────────────────────────────────────────────────────

const pct = (qty, total) => total > 0 ? Math.min(100, Math.round((qty / total) * 100)) : 0;
const loadStorage = () => { try { const d = localStorage.getItem(STORAGE_KEY); return d ? JSON.parse(d) : null; } catch { return null; } };
const saveStorage = (inv, log, shop) => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ inventory: inv, usageLog: log, shoppingList: shop })); } catch {} };

// ── SUB-COMPONENTS ───────────────────────────────────────────────────────────

function FillBar({ qty, total, lowAlert }) {
  const p = pct(qty, total);
  const isEmpty = qty === 0;
  const isLow = qty <= lowAlert && lowAlert > 0 && !isEmpty;
  const color = isEmpty ? C.danger : isLow ? C.warn : C.accentLight;
  return (
    <div style={{ height: "4px", background: C.surface, borderRadius: "2px", overflow: "hidden", margin: "10px 0 14px" }}>
      <div style={{ height: "100%", width: `${p}%`, background: color, borderRadius: "2px", transition: "width 0.5s cubic-bezier(.4,0,.2,1)" }} />
    </div>
  );
}

function Badge({ children, color, bg, border }) {
  return (
    <span style={{ background: bg, color, border: `1px solid ${border}`, borderRadius: "4px", fontSize: "9px", padding: "2px 7px", letterSpacing: "1px", fontWeight: 600 }}>
      {children}
    </span>
  );
}

// ── BARCODE LOOKUP ───────────────────────────────────────────────────────────

async function lookupBarcode(barcode) {
  try {
    const res = await fetch(`https://world.openfoodfacts.org/api/v0/product/${barcode}.json`);
    const data = await res.json();
    if (data.status !== 1) return null;
    const p = data.product;
    const name = p.product_name_en || p.product_name || "";
    const brand = p.brands || "";
    const category = p.categories_tags?.[0]?.replace("en:", "").replace(/-/g, " ") || "";
    return { name: name || brand, brand, rawCategory: category };
  } catch { return null; }
}

function mapCategory(raw) {
  if (!raw) return "Pantry";
  const r = raw.toLowerCase();
  if (r.includes("bread") || r.includes("bak") || r.includes("cereal")) return "Bakery";
  if (r.includes("dairy") || r.includes("milk") || r.includes("egg") || r.includes("cheese")) return "Dairy & Eggs";
  if (r.includes("meat") || r.includes("fish") || r.includes("seafood")) return "Meat & Fish";
  if (r.includes("produce") || r.includes("vegetable") || r.includes("fruit")) return "Produce";
  if (r.includes("snack") || r.includes("chip") || r.includes("cookie")) return "Snacks";
  if (r.includes("drink") || r.includes("beverage") || r.includes("juice") || r.includes("water")) return "Drinks";
  if (r.includes("sauce") || r.includes("condiment") || r.includes("oil")) return "Condiments";
  if (r.includes("frozen")) return "Frozen";
  return "Pantry";
}

// ── CAMERA SCANNER ───────────────────────────────────────────────────────────
// Uses the native BarcodeDetector API (Chrome 83+, Edge, Android Chrome).
// Falls back gracefully with a clear message on unsupported browsers.

function CameraScanner({ onDetected, onClose }) {
  const videoRef   = useRef(null);
  const canvasRef  = useRef(null);
  const streamRef  = useRef(null);
  const rafRef     = useRef(null);
  const doneRef    = useRef(false);
  const [status, setStatus] = useState("starting"); // starting | scanning | unsupported | error
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    async function start() {
      // 1. Check for native BarcodeDetector
      if (!("BarcodeDetector" in window)) {
        setStatus("unsupported");
        return;
      }
      // 2. Open camera
      let stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }
        });
      } catch (e) {
        setErrorMsg(e.message || "Camera permission denied");
        setStatus("error");
        return;
      }
      streamRef.current = stream;
      const video = videoRef.current;
      video.srcObject = stream;
      await video.play();
      setStatus("scanning");

      // 3. Set up detector
      const detector = new BarcodeDetector({
        formats: ["ean_13","ean_8","upc_a","upc_e","code_128","code_39","qr_code","itf","codabar"]
      });

      // 4. Poll frames via requestAnimationFrame
      const canvas = canvasRef.current;
      const ctx = canvas.getContext("2d");

      async function tick() {
        if (doneRef.current) return;
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width  = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          try {
            const barcodes = await detector.detect(canvas);
            if (barcodes.length > 0 && !doneRef.current) {
              doneRef.current = true;
              onDetected(barcodes[0].rawValue);
              return;
            }
          } catch (_) {}
        }
        rafRef.current = requestAnimationFrame(tick);
      }
      rafRef.current = requestAnimationFrame(tick);
    }

    start();
    return () => {
      doneRef.current = true;
      cancelAnimationFrame(rafRef.current);
      streamRef.current?.getTracks().forEach(t => t.stop());
    };
  }, [onDetected]);

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.93)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", zIndex: 300 }}>
      <div style={{ width: "100%", maxWidth: "400px", padding: "0 20px" }}>
        {/* Title bar */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div style={{ color: "#fff", fontFamily: "'Playfair Display', serif", fontSize: "20px", fontWeight: 700 }}>Scan Barcode</div>
          <button onClick={onClose} style={{ background: "rgba(255,255,255,0.12)", border: "none", borderRadius: "6px", color: "#fff", padding: "6px 14px", fontSize: "12px", cursor: "pointer" }}>✕ Close</button>
        </div>

        {/* Unsupported browser */}
        {status === "unsupported" && (
          <div style={{ background: C.warnBg, border: `1px solid ${C.warnBorder}`, borderRadius: "12px", padding: "28px", textAlign: "center" }}>
            <div style={{ fontSize: "36px", marginBottom: "12px" }}>🌐</div>
            <div style={{ fontSize: "14px", color: C.warn, marginBottom: "8px", fontFamily: "'Playfair Display', serif", fontWeight: 700 }}>Browser not supported</div>
            <div style={{ fontSize: "12px", color: C.muted, lineHeight: 1.6 }}>
              Camera scanning requires <strong style={{ color: C.text }}>Chrome</strong> or <strong style={{ color: C.text }}>Edge</strong> on desktop, or <strong style={{ color: C.text }}>Chrome on Android</strong>.<br /><br />
              Safari and Firefox don't support the BarcodeDetector API yet.
            </div>
            <button onClick={onClose} style={{ marginTop: "18px", background: C.accent, color: C.bg, border: "none", borderRadius: "8px", padding: "10px 22px", fontSize: "12px", cursor: "pointer", fontFamily: "'Playfair Display', serif", fontWeight: 700 }}>Type barcode instead</button>
          </div>
        )}

        {/* Camera error */}
        {status === "error" && (
          <div style={{ background: C.dangerBg, border: `1px solid ${C.dangerBorder}`, borderRadius: "12px", padding: "28px", textAlign: "center" }}>
            <div style={{ fontSize: "36px", marginBottom: "12px" }}>📷</div>
            <div style={{ fontSize: "14px", color: C.danger, marginBottom: "6px", fontFamily: "'Playfair Display', serif", fontWeight: 700 }}>Camera unavailable</div>
            <div style={{ fontSize: "11px", color: C.muted }}>{errorMsg}</div>
            <button onClick={onClose} style={{ marginTop: "16px", background: C.accent, color: C.bg, border: "none", borderRadius: "8px", padding: "10px 20px", fontSize: "12px", cursor: "pointer" }}>Type barcode instead</button>
          </div>
        )}

        {/* Starting */}
        {status === "starting" && (
          <div style={{ textAlign: "center", color: "rgba(255,255,255,0.5)", padding: "40px 0", fontSize: "12px", letterSpacing: "2px" }}>
            <div style={{ fontSize: "32px", marginBottom: "12px", animation: "spin 1.2s linear infinite", display: "inline-block" }}>⟳</div>
            <div>STARTING CAMERA…</div>
          </div>
        )}

        {/* Live viewfinder */}
        {(status === "scanning" || status === "starting") && (
          <div style={{ position: "relative", borderRadius: "12px", overflow: "hidden", background: "#000", display: status === "starting" ? "none" : "block" }}>
            <video ref={videoRef} style={{ width: "100%", display: "block", maxHeight: "320px", objectFit: "cover" }} muted playsInline />
            {/* Viewfinder overlay */}
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
              <div style={{ width: "72%", height: "88px", border: `2px solid ${C.accent}`, borderRadius: "8px", boxShadow: "0 0 0 9999px rgba(0,0,0,0.5)" }}>
                {/* Corner accents */}
                {[["0","0","top","left"],["0","0","top","right"],["auto","0","bottom","left"],["auto","0","bottom","right"]].map(([t,r,tb,lr], i) => (
                  <div key={i} style={{ position: "absolute", [tb]: -2, [lr]: -2, width: 16, height: 16,
                    borderTop: (tb === "top") ? `3px solid ${C.accent}` : "none",
                    borderBottom: (tb === "bottom") ? `3px solid ${C.accent}` : "none",
                    borderLeft: (lr === "left") ? `3px solid ${C.accent}` : "none",
                    borderRight: (lr === "right") ? `3px solid ${C.accent}` : "none",
                  }} />
                ))}
              </div>
            </div>
            <div style={{ position: "absolute", bottom: "12px", left: 0, right: 0, textAlign: "center", color: "rgba(255,255,255,0.6)", fontSize: "10px", letterSpacing: "2px" }}>
              ALIGN BARCODE IN FRAME
            </div>
          </div>
        )}

        {/* Hidden canvas for frame capture */}
        <canvas ref={canvasRef} style={{ display: "none" }} />

        <div style={{ marginTop: "14px", textAlign: "center", color: "rgba(255,255,255,0.3)", fontSize: "11px" }}>
          Or close and type the barcode manually
        </div>
      </div>
    </div>
  );
}

// ── RESTOCK MODAL ─────────────────────────────────────────────────────────────

function RestockModal({ item, onConfirm, onClose }) {
  const [amt, setAmt] = useState(item.totalUnits);
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)" }}>
      <div style={{ background: C.card, borderRadius: "16px", padding: "28px", width: "320px", boxShadow: C.shadowLg, animation: "fadeUp .2s ease" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "22px" }}>
          <span style={{ fontSize: "30px" }}>{item.emoji}</span>
          <div>
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "18px", fontWeight: 700 }}>Restock {item.name}</div>
            <div style={{ fontSize: "11px", color: C.muted, marginTop: "2px" }}>Currently {item.quantity} {item.unit}</div>
          </div>
        </div>
        <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "8px" }}>ADD HOW MANY {item.unit.toUpperCase()}?</div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
          <button onClick={() => setAmt(a => Math.max(1, a - 1))} style={{ width: "38px", height: "38px", borderRadius: "8px", border: `1px solid ${C.border}`, background: C.surface, color: C.text, fontSize: "20px", cursor: "pointer" }}>−</button>
          <input type="number" value={amt} onChange={e => setAmt(Math.max(1, parseInt(e.target.value) || 1))}
            style={{ flex: 1, textAlign: "center", background: C.surface, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "10px", color: C.text, fontSize: "20px", fontFamily: "'Playfair Display', serif", fontWeight: 700, outline: "none" }} />
          <button onClick={() => setAmt(a => a + 1)} style={{ width: "38px", height: "38px", borderRadius: "8px", border: `1px solid ${C.border}`, background: C.surface, color: C.text, fontSize: "20px", cursor: "pointer" }}>+</button>
        </div>
        {item.note && <div style={{ fontSize: "11px", color: C.muted, fontStyle: "italic", marginBottom: "16px" }}>{item.note}</div>}
        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={onClose} style={{ flex: 1, background: C.surface, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "11px", color: C.muted, fontSize: "12px", cursor: "pointer" }}>Cancel</button>
          <button onClick={() => onConfirm(item, amt)} style={{ flex: 2, background: C.accent, color: "#fff", border: "none", borderRadius: "8px", padding: "11px", fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "14px", cursor: "pointer" }}>Restock +{amt}</button>
        </div>
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────

export default function Homstock() {
  const saved = loadStorage();
  const [inventory, setInventory]       = useState(saved?.inventory    || SEED_INVENTORY);
  const [usageLog, setUsageLog]         = useState(saved?.usageLog     || []);
  const [shoppingList, setShoppingList] = useState(saved?.shoppingList || []);
  const [view, setView]                 = useState("pantry");
  const [filterCat, setFilterCat]       = useState("All");
  const [search, setSearch]             = useState("");
  const [useModal, setUseModal]         = useState(null);
  const [useAmount, setUseAmount]       = useState(1);
  const [restockModal, setRestockModal] = useState(null);
  const [addModal, setAddModal]         = useState(false);
  const [toast, setToast]               = useState(null);
  const [showCamera, setShowCamera]     = useState(false);

  const emptyForm = { name:"", emoji:"🫙", category:"Pantry", quantity:"", unit:"", lowAlert:"", note:"", barcode:"" };
  const [addForm, setAddForm]           = useState(emptyForm);
  const [barcodeInput, setBarcodeInput] = useState("");
  const [lookingUp, setLookingUp]       = useState(false);
  const [lookupStatus, setLookupStatus] = useState(null);
  const nextId = useRef(Math.max(0, ...inventory.map(i => i.id)) + 1);

  useEffect(() => { saveStorage(inventory, usageLog, shoppingList); }, [inventory, usageLog, shoppingList]);
  useEffect(() => { if (toast) { const t = setTimeout(() => setToast(null), 3200); return () => clearTimeout(t); } }, [toast]);
  const showToast = (msg, type = "ok") => setToast({ msg, type });

  const doLookup = useCallback(async (code) => {
    const trimmed = (code || "").trim();
    if (!trimmed) return;
    setLookingUp(true);
    setLookupStatus(null);
    const result = await lookupBarcode(trimmed);
    setLookingUp(false);
    if (result) {
      setLookupStatus("found");
      setAddForm(f => ({ ...f, barcode: trimmed, name: result.name || f.name, category: mapCategory(result.rawCategory), note: result.brand ? `Brand: ${result.brand}` : f.note }));
      showToast(`Found: ${result.name || "product"}`, "ok");
    } else {
      setLookupStatus("notfound");
      setAddForm(f => ({ ...f, barcode: trimmed }));
      showToast("Not found — fill in details manually", "warn");
    }
  }, []);

  const handleCameraDetected = useCallback((code) => {
    setShowCamera(false);
    setBarcodeInput(code);
    setAddModal(true);
    doLookup(code);
  }, [doLookup]);

  const addToShop = (item) => setShoppingList(prev => prev.find(s => s.itemId === item.id) ? prev : [...prev, { id: Date.now(), itemId: item.id, name: item.name, emoji: item.emoji, unit: item.unit, totalUnits: item.totalUnits, note: item.note, checked: false }]);

  const handleUse = () => {
    const amt = parseFloat(useAmount);
    if (!amt || amt <= 0) return showToast("Enter a valid amount", "err");
    if (amt > useModal.quantity) return showToast(`Only ${useModal.quantity} ${useModal.unit} left`, "err");
    const newQty = parseFloat((useModal.quantity - amt).toFixed(2));
    setInventory(prev => prev.map(i => i.id === useModal.id ? { ...i, quantity: newQty } : i));
    setUsageLog(prev => [{ id: Date.now(), itemId: useModal.id, itemName: useModal.name, emoji: useModal.emoji, amount: amt, unit: useModal.unit, date: new Date().toLocaleString(), remaining: newQty }, ...prev]);
    if (newQty === 0) { addToShop(useModal); showToast(`${useModal.name} is empty — added to shopping list 🛒`, "warn"); }
    else if (useModal.lowAlert > 0 && newQty <= useModal.lowAlert) { addToShop(useModal); showToast(`Running low on ${useModal.name} — added to list 🛒`, "warn"); }
    else showToast(`Used ${amt} ${useModal.unit} of ${useModal.name}`);
    setUseModal(null); setUseAmount(1);
  };

  const handleRestock = (item, amt) => {
    const newQty = parseFloat((item.quantity + amt).toFixed(2));
    setInventory(prev => prev.map(i => i.id === item.id ? { ...i, quantity: newQty, totalUnits: Math.max(item.totalUnits, newQty) } : i));
    setShoppingList(prev => prev.filter(s => s.itemId !== item.id));
    showToast(`${item.name} restocked — ${newQty} ${item.unit} available ✓`);
    setRestockModal(null);
  };

  const handleUndo = (entry) => {
    setInventory(prev => prev.map(i => {
      if (i.id !== entry.itemId) return i;
      const restored = parseFloat((i.quantity + entry.amount).toFixed(2));
      return { ...i, quantity: Math.min(restored, i.totalUnits) };
    }));
    setUsageLog(prev => prev.filter(e => e.id !== entry.id));
    const item = inventory.find(i => i.id === entry.itemId);
    if (item) {
      const restoredQty = parseFloat((item.quantity + entry.amount).toFixed(2));
      if (restoredQty > (item.lowAlert || 0)) {
        setShoppingList(prev => prev.filter(s => s.itemId !== entry.itemId));
      }
    }
    showToast(`Undone — +${entry.amount} ${entry.unit} returned to ${entry.itemName}`);
  };

  const handleAdd = () => {
    const { name, emoji, category, quantity, unit, lowAlert, note, barcode } = addForm;
    if (!name || !quantity || !unit) return showToast("Name, quantity and unit are required", "err");
    const qty = parseFloat(quantity);
    setInventory(prev => [...prev, { id: nextId.current++, name, emoji, category, unit, totalUnits: qty, quantity: qty, portionLabel: unit, lowAlert: parseFloat(lowAlert) || 0, note: note || "", barcode: barcode || "" }]);
    setAddForm(emptyForm); setBarcodeInput(""); setLookupStatus(null); setAddModal(false);
    showToast(`${emoji} ${name} added to pantry!`);
  };

  const filtered = inventory.filter(i => (filterCat === "All" || i.category === filterCat) && i.name.toLowerCase().includes(search.toLowerCase()));
  const lowItems   = inventory.filter(i => i.quantity <= i.lowAlert && i.lowAlert > 0 && i.quantity > 0);
  const emptyItems = inventory.filter(i => i.quantity === 0);
  const onList     = shoppingList.filter(s => !s.checked).length;

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: "'DM Mono', 'Courier New', monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Playfair+Display:wght@600;700;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 2px; }
        input, select { outline: none; font-family: 'DM Mono', monospace; }
        button { cursor: pointer; font-family: 'DM Mono', monospace; }
        @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
        @keyframes toastSlide { from { opacity:0; transform:translateX(16px); } to { opacity:1; transform:translateX(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        .card { transition: box-shadow .2s, transform .2s; }
        .card:hover { box-shadow: ${C.shadowMd}; transform: translateY(-1px); }
        .tab-btn { transition: all .15s; }
        .ghost-btn { transition: background .15s; }
        .ghost-btn:hover { background: ${C.surface} !important; }
        .qbtn { transition: transform .1s; }
        .qbtn:active { transform: scale(.93); }
        .emoji-opt { transition: transform .1s; cursor: pointer; }
        .emoji-opt:hover { transform: scale(1.2); }
        input[type=number]::-webkit-inner-spin-button { -webkit-appearance: none; }
      `}</style>

      {showCamera && <CameraScanner onDetected={handleCameraDetected} onClose={() => setShowCamera(false)} />}

      {/* HEADER */}
      <div style={{ background: C.card, borderBottom: `1px solid ${C.border}`, padding: "14px 24px", display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, zIndex: 50, boxShadow: C.shadow }}>
        <div>
          <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "22px", fontWeight: 900, color: C.accent }}>Homstock</div>
          <div style={{ fontSize: "9px", color: C.mutedLight, letterSpacing: "3px" }}>PANTRY TRACKER</div>
        </div>
        <div style={{ display: "flex", gap: "6px" }}>
          {[["pantry","PANTRY"],["shop", onList > 0 ? `SHOP (${onList})` : "SHOP"],["log","LOG"],["report","REPORT"]].map(([v, label]) => (
            <button key={v} className="tab-btn" onClick={() => setView(v)} style={{ background: view === v ? C.accent : "transparent", color: view === v ? "#fff" : C.muted, border: `1px solid ${view === v ? C.accent : C.border}`, borderRadius: "5px", padding: "6px 12px", fontSize: "10px", letterSpacing: "1.5px" }}>{label}</button>
          ))}
          <button onClick={() => setAddModal(true)} style={{ background: C.accentBg, color: C.accent, border: `1px solid ${C.accentBorder}`, borderRadius: "5px", padding: "6px 12px", fontSize: "10px", letterSpacing: "1.5px" }}>+ ADD</button>
        </div>
      </div>

      <div style={{ maxWidth: "900px", margin: "0 auto", padding: "24px 20px" }}>

        {/* ALERTS */}
        {view === "pantry" && (emptyItems.length > 0 || lowItems.length > 0) && (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "20px" }}>
            {emptyItems.length > 0 && (
              <div style={{ background: C.dangerBg, border: `1px solid ${C.dangerBorder}`, borderRadius: "8px", padding: "10px 16px", display: "flex", gap: "10px", alignItems: "center" }}>
                <span>🚫</span>
                <div style={{ flex: 1 }}><span style={{ color: C.danger, fontSize: "10px", letterSpacing: "1.5px", fontWeight: 600 }}>OUT OF STOCK · </span><span style={{ fontSize: "12px" }}>{emptyItems.map(i => i.emoji + " " + i.name).join("  ·  ")}</span></div>
                <span style={{ fontSize: "10px", color: C.muted }}>added to list</span>
              </div>
            )}
            {lowItems.length > 0 && (
              <div style={{ background: C.warnBg, border: `1px solid ${C.warnBorder}`, borderRadius: "8px", padding: "10px 16px", display: "flex", gap: "10px", alignItems: "center" }}>
                <span>⚠️</span>
                <div><span style={{ color: C.warn, fontSize: "10px", letterSpacing: "1.5px", fontWeight: 600 }}>RUNNING LOW · </span><span style={{ fontSize: "12px" }}>{lowItems.map(i => i.emoji + " " + i.name).join("  ·  ")}</span></div>
              </div>
            )}
          </div>
        )}

        {/* PANTRY */}
        {view === "pantry" && (
          <div style={{ animation: "fadeUp .25s ease" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "10px", marginBottom: "22px" }}>
              {[
                { label:"ITEMS",   val: inventory.length, color: C.text },
                { label:"STOCKED", val: inventory.filter(i => i.quantity > i.lowAlert).length, color: C.accent },
                { label:"LOW",     val: lowItems.length,   color: lowItems.length   ? C.warn   : C.mutedLight },
                { label:"EMPTY",   val: emptyItems.length, color: emptyItems.length ? C.danger : C.mutedLight },
              ].map(s => (
                <div key={s.label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "14px 10px", textAlign: "center", boxShadow: C.shadow }}>
                  <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "26px", fontWeight: 900, color: s.color, lineHeight: 1 }}>{s.val}</div>
                  <div style={{ fontSize: "8px", color: C.mutedLight, letterSpacing: "2px", marginTop: "5px" }}>{s.label}</div>
                </div>
              ))}
            </div>

            <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search pantry…"
                style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: "7px", padding: "9px 14px", color: C.text, fontSize: "12px", boxShadow: C.shadow }} />
              <select value={filterCat} onChange={e => setFilterCat(e.target.value)}
                style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "7px", padding: "9px 12px", color: C.muted, fontSize: "11px", boxShadow: C.shadow }}>
                {FOOD_CATEGORIES.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(255px,1fr))", gap: "12px" }}>
              {filtered.length === 0 && <div style={{ gridColumn: "1/-1", textAlign: "center", color: C.muted, padding: "60px", fontSize: "13px" }}>No items found</div>}
              {filtered.map(item => {
                const isEmpty = item.quantity === 0;
                const isLow   = item.quantity <= item.lowAlert && item.lowAlert > 0 && !isEmpty;
                return (
                  <div key={item.id} className="card" style={{ background: C.card, border: `1px solid ${isEmpty ? C.dangerBorder : isLow ? C.warnBorder : C.border}`, borderRadius: "12px", padding: "18px", boxShadow: C.shadow, animation: "fadeUp .25s ease", opacity: isEmpty ? 0.75 : 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span style={{ fontSize: "26px" }}>{item.emoji}</span>
                        <div>
                          <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "15px" }}>{item.name}</div>
                          <div style={{ fontSize: "9px", color: C.mutedLight, letterSpacing: "1.5px", marginTop: "2px" }}>{item.category}</div>
                        </div>
                      </div>
                      {isEmpty && <Badge color={C.danger} bg={C.dangerBg} border={C.dangerBorder}>EMPTY</Badge>}
                      {isLow   && <Badge color={C.warn}   bg={C.warnBg}   border={C.warnBorder}>LOW</Badge>}
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                      <div style={{ display: "flex", alignItems: "baseline", gap: "5px" }}>
                        <span style={{ fontFamily: "'Playfair Display', serif", fontSize: "30px", fontWeight: 900, color: isEmpty ? C.danger : C.text, lineHeight: 1 }}>{item.quantity}</span>
                        <span style={{ color: C.muted, fontSize: "11px" }}>/ {item.totalUnits} {item.unit}</span>
                      </div>
                      <span style={{ fontSize: "11px", color: isEmpty ? C.danger : isLow ? C.warn : C.accentLight }}>{pct(item.quantity, item.totalUnits)}%</span>
                    </div>
                    {item.note && <div style={{ fontSize: "10px", color: C.mutedLight, fontStyle: "italic", marginTop: "4px" }}>{item.note}</div>}
                    <FillBar qty={item.quantity} total={item.totalUnits} lowAlert={item.lowAlert} />
                    <div style={{ display: "flex", gap: "6px", marginBottom: "8px" }}>
                      {[1,2,3].map(n => (
                        <button key={n} className="qbtn" onClick={() => { if (n > item.quantity) return showToast(`Only ${item.quantity} left`, "err"); setUseModal(item); setUseAmount(n); }}
                          style={{ flex: 1, background: C.surface, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "7px 0", fontSize: "11px", color: C.muted }}>−{n}</button>
                      ))}
                      <button className="qbtn" onClick={() => { setUseModal(item); setUseAmount(1); }}
                        style={{ flex: 1, background: C.accentBg, border: `1px solid ${C.accentBorder}`, borderRadius: "6px", padding: "7px 0", fontSize: "11px", color: C.accent }}>…</button>
                    </div>
                    <button className="ghost-btn" onClick={() => setRestockModal(item)} style={{ width: "100%", background: "transparent", border: `1px solid ${C.border}`, borderRadius: "6px", padding: "7px", fontSize: "10px", color: C.muted, letterSpacing: "1.5px" }}>+ RESTOCK</button>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* SHOPPING LIST */}
        {view === "shop" && (
          <div style={{ animation: "fadeUp .25s ease" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "20px" }}>
              <div>
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "22px", fontWeight: 900 }}>Shopping List</div>
                <div style={{ fontSize: "10px", color: C.muted, letterSpacing: "2px", marginTop: "3px" }}>{onList} ITEM{onList !== 1 ? "S" : ""} TO BUY</div>
              </div>
              {shoppingList.some(s => s.checked) && (
                <button className="ghost-btn" onClick={() => setShoppingList(p => p.filter(s => !s.checked))} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: "6px", padding: "7px 14px", color: C.muted, fontSize: "10px", letterSpacing: "1.5px" }}>CLEAR DONE</button>
              )}
            </div>
            {shoppingList.length === 0 ? (
              <div style={{ textAlign: "center", padding: "80px 20px", color: C.muted }}>
                <div style={{ fontSize: "40px", marginBottom: "12px" }}>🛒</div>
                <div style={{ fontSize: "14px" }}>Shopping list is empty</div>
                <div style={{ fontSize: "11px", marginTop: "6px", color: C.mutedLight }}>Items appear automatically when stock runs out</div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {shoppingList.map(s => (
                  <div key={s.id} className="card" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "14px 18px", display: "flex", alignItems: "center", gap: "14px", opacity: s.checked ? 0.4 : 1, boxShadow: C.shadow }}>
                    <button onClick={() => setShoppingList(p => p.map(x => x.id === s.id ? { ...x, checked: !x.checked } : x))} style={{ width: "22px", height: "22px", borderRadius: "50%", flexShrink: 0, border: `2px solid ${s.checked ? C.accent : C.border}`, background: s.checked ? C.accent : "transparent", color: "#fff", fontSize: "11px", display: "flex", alignItems: "center", justifyContent: "center" }}>{s.checked ? "✓" : ""}</button>
                    <span style={{ fontSize: "22px" }}>{s.emoji}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "15px", textDecoration: s.checked ? "line-through" : "none" }}>{s.name}</div>
                      {s.note && <div style={{ fontSize: "10px", color: C.muted, marginTop: "2px" }}>{s.note}</div>}
                    </div>
                    <button className="ghost-btn" onClick={() => { const item = inventory.find(i => i.id === s.itemId); if (item) setRestockModal(item); }} style={{ background: C.accentBg, border: `1px solid ${C.accentBorder}`, borderRadius: "6px", padding: "6px 12px", color: C.accent, fontSize: "10px", letterSpacing: "1.5px" }}>RESTOCK</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* LOG */}
        {view === "log" && (
          <div style={{ animation: "fadeUp .25s ease" }}>
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "22px", fontWeight: 900, marginBottom: "4px" }}>Usage History</div>
            <div style={{ fontSize: "10px", color: C.muted, letterSpacing: "2px", marginBottom: "20px" }}>{usageLog.length} ENTRIES</div>
            {usageLog.length === 0 ? (
              <div style={{ textAlign: "center", padding: "80px 20px", color: C.muted }}>
                <div style={{ fontSize: "13px" }}>No usage logged yet</div>
                <div style={{ fontSize: "11px", marginTop: "6px" }}>Tap −1 / −2 / −3 on any pantry item</div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                {usageLog.map(entry => (
                  <div key={entry.id} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "12px 16px", display: "flex", alignItems: "center", gap: "12px", boxShadow: C.shadow }}>
                    <span style={{ fontSize: "20px" }}>{entry.emoji}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "14px" }}>{entry.itemName}</div>
                      <div style={{ fontSize: "10px", color: C.muted, marginTop: "2px" }}>{entry.date}</div>
                    </div>
                    <div style={{ textAlign: "right", marginRight: "10px" }}>
                      <div style={{ color: C.danger, fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "17px" }}>−{entry.amount}</div>
                      <div style={{ fontSize: "9px", color: C.muted }}>{entry.unit} · {entry.remaining} left</div>
                    </div>
                    <button className="ghost-btn" onClick={() => handleUndo(entry)} title="Undo this entry" style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "6px 10px", color: C.mutedLight, fontSize: "11px", letterSpacing: "1px", flexShrink: 0 }}>↩ UNDO</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* REPORT */}
        {view === "report" && (() => {
          // Build per-item usage stats from log
          const statsMap = {};
          usageLog.forEach(e => {
            if (!statsMap[e.itemId]) statsMap[e.itemId] = { itemId: e.itemId, itemName: e.itemName, emoji: e.emoji, unit: e.unit, totalUsed: 0, uses: 0 };
            statsMap[e.itemId].totalUsed += e.amount;
            statsMap[e.itemId].uses += 1;
          });
          // Merge with current inventory, sorted by totalUsed desc
          const reportRows = inventory.map(item => {
            const stats = statsMap[item.id] || { totalUsed: 0, uses: 0 };
            return { ...item, totalUsed: stats.totalUsed, uses: stats.uses };
          }).sort((a, b) => b.totalUsed - a.totalUsed);

          const totalUses = usageLog.length;
          const totalConsumed = usageLog.reduce((s, e) => s + e.amount, 0);
          const mostUsed = reportRows[0];
          const generated = new Date().toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
          const maxUsed = Math.max(...reportRows.map(r => r.totalUsed), 1);

          return (
            <div style={{ animation: "fadeUp .25s ease" }}>
              {/* Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px" }}>
                <div>
                  <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "22px", fontWeight: 900 }}>Inventory Report</div>
                  <div style={{ fontSize: "10px", color: C.muted, letterSpacing: "2px", marginTop: "3px" }}>GENERATED {generated.toUpperCase()}</div>
                </div>
                <div style={{ fontSize: "10px", color: C.muted, background: C.card, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "6px 12px" }}>
                  {inventory.length} ITEMS · {totalUses} USES
                </div>
              </div>

              {/* Summary cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "10px", marginBottom: "24px" }}>
                {[
                  { label: "TOTAL USES",     val: totalUses,                                              color: C.accent },
                  { label: "UNITS CONSUMED", val: totalConsumed % 1 === 0 ? totalConsumed : totalConsumed.toFixed(1), color: C.accentLight },
                  { label: "ITEMS TRACKED",  val: inventory.length,                                       color: C.text },
                  { label: "NEED RESTOCK",   val: lowItems.length + emptyItems.length,                    color: (lowItems.length + emptyItems.length) > 0 ? C.danger : C.muted },
                ].map(s => (
                  <div key={s.label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "14px 10px", textAlign: "center", boxShadow: C.shadow }}>
                    <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "24px", fontWeight: 900, color: s.color, lineHeight: 1 }}>{s.val}</div>
                    <div style={{ fontSize: "8px", color: C.mutedLight, letterSpacing: "2px", marginTop: "5px" }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Most used callout */}
              {mostUsed && mostUsed.totalUsed > 0 && (
                <div style={{ background: C.accentBg, border: `1px solid ${C.accentBorder}`, borderRadius: "10px", padding: "14px 18px", marginBottom: "20px", display: "flex", alignItems: "center", gap: "14px" }}>
                  <span style={{ fontSize: "28px" }}>{mostUsed.emoji}</span>
                  <div>
                    <div style={{ fontSize: "9px", color: C.accentBorder, letterSpacing: "2px", marginBottom: "2px" }}>MOST USED ITEM</div>
                    <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "16px", color: C.accent }}>{mostUsed.name}</div>
                    <div style={{ fontSize: "11px", color: C.mutedLight, marginTop: "2px" }}>{mostUsed.totalUsed} {mostUsed.unit} consumed across {mostUsed.uses} use{mostUsed.uses !== 1 ? "s" : ""}</div>
                  </div>
                </div>
              )}

              {/* Table header */}
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 2fr", gap: "10px", padding: "8px 14px", marginBottom: "4px" }}>
                {["ITEM", "STOCK", "USES", "CONSUMED", "USAGE BAR"].map(h => (
                  <div key={h} style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px" }}>{h}</div>
                ))}
              </div>

              {/* Rows */}
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {reportRows.map((item, idx) => {
                  const isEmpty  = item.quantity === 0;
                  const isLow    = item.quantity <= item.lowAlert && item.lowAlert > 0 && !isEmpty;
                  const barW     = maxUsed > 0 ? (item.totalUsed / maxUsed) * 100 : 0;
                  const rankColor = idx === 0 && item.totalUsed > 0 ? C.accent : idx === 1 && item.totalUsed > 0 ? C.accentLight : C.border;
                  return (
                    <div key={item.id} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 2fr", gap: "10px", alignItems: "center", background: C.card, border: `1px solid ${isEmpty ? C.dangerBorder : isLow ? C.warnBorder : C.border}`, borderRadius: "8px", padding: "12px 14px", boxShadow: C.shadow }}>
                      {/* Item name */}
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        {idx < 3 && item.totalUsed > 0 && (
                          <span style={{ fontSize: "10px", color: rankColor, fontWeight: 700, minWidth: "14px" }}>#{idx + 1}</span>
                        )}
                        <span style={{ fontSize: "18px" }}>{item.emoji}</span>
                        <div>
                          <div style={{ fontFamily: "'Playfair Display', serif", fontWeight: 700, fontSize: "13px" }}>{item.name}</div>
                          <div style={{ fontSize: "9px", color: C.mutedLight }}>{item.category}</div>
                        </div>
                      </div>
                      {/* Stock */}
                      <div>
                        <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "15px", fontWeight: 700, color: isEmpty ? C.danger : isLow ? C.warn : C.text }}>{item.quantity}</div>
                        <div style={{ fontSize: "9px", color: C.muted }}>/ {item.totalUnits} {item.unit}</div>
                      </div>
                      {/* Uses */}
                      <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "15px", fontWeight: 700, color: item.uses > 0 ? C.text : C.muted }}>{item.uses}</div>
                      {/* Consumed */}
                      <div>
                        <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "15px", fontWeight: 700, color: item.totalUsed > 0 ? C.text : C.muted }}>{item.totalUsed || "—"}</div>
                        {item.totalUsed > 0 && <div style={{ fontSize: "9px", color: C.muted }}>{item.unit}</div>}
                      </div>
                      {/* Usage bar */}
                      <div>
                        <div style={{ height: "6px", background: C.surface, borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${barW}%`, background: rankColor === C.border ? C.mutedLight : rankColor, borderRadius: "3px", transition: "width .6s ease" }} />
                        </div>
                        {isEmpty && <div style={{ fontSize: "8px", color: C.danger, marginTop: "3px", letterSpacing: "1px" }}>EMPTY</div>}
                        {isLow   && <div style={{ fontSize: "8px", color: C.warn,   marginTop: "3px", letterSpacing: "1px" }}>LOW STOCK</div>}
                      </div>
                    </div>
                  );
                })}
              </div>

              {usageLog.length === 0 && (
                <div style={{ textAlign: "center", color: C.muted, padding: "30px 20px", fontSize: "12px", marginTop: "8px" }}>
                  No usage data yet — start logging from the Pantry tab
                </div>
              )}
            </div>
          );
        })()}
      </div>

      {/* USE MODAL */}
      {useModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)", animation: "fadeIn .2s ease" }}>
          <div style={{ background: C.card, borderRadius: "16px", padding: "28px", width: "340px", boxShadow: C.shadowLg, animation: "fadeUp .2s ease" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "20px" }}>
              <span style={{ fontSize: "32px" }}>{useModal.emoji}</span>
              <div>
                <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "20px", fontWeight: 900 }}>{useModal.name}</div>
                <div style={{ fontSize: "11px", color: C.muted, marginTop: "2px" }}>{useModal.quantity} {useModal.unit} remaining</div>
              </div>
            </div>
            <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "8px" }}>HOW MANY {useModal.unit.toUpperCase()} USED?</div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
              <button onClick={() => setUseAmount(a => Math.max(1, a - 1))} style={{ width: "40px", height: "40px", borderRadius: "8px", border: `1px solid ${C.border}`, background: C.surface, color: C.text, fontSize: "20px" }}>−</button>
              <input type="number" value={useAmount} onChange={e => setUseAmount(Math.max(1, parseInt(e.target.value) || 1))}
                style={{ flex: 1, textAlign: "center", background: C.surface, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "10px", color: C.text, fontSize: "22px", fontFamily: "'Playfair Display', serif", fontWeight: 700 }} />
              <button onClick={() => setUseAmount(a => Math.min(useModal.quantity, a + 1))} style={{ width: "40px", height: "40px", borderRadius: "8px", border: `1px solid ${C.border}`, background: C.surface, color: C.text, fontSize: "20px" }}>+</button>
            </div>
            <div style={{ display: "flex", gap: "6px", marginBottom: "20px" }}>
              {[1,2,3,4,6].filter(n => n <= useModal.quantity).map(n => (
                <button key={n} className="qbtn" onClick={() => setUseAmount(n)} style={{ flex: 1, background: useAmount === n ? C.accentBg : C.surface, border: `1px solid ${useAmount === n ? C.accentBorder : C.border}`, borderRadius: "5px", padding: "6px 0", fontSize: "12px", color: useAmount === n ? C.accent : C.muted }}>{n}</button>
              ))}
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <button className="ghost-btn" onClick={() => { setUseModal(null); setUseAmount(1); }} style={{ flex: 1, background: C.surface, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "12px", color: C.muted, fontSize: "12px" }}>Cancel</button>
              <button onClick={handleUse} style={{ flex: 2, background: C.accent, color: "#fff", border: "none", borderRadius: "8px", padding: "12px", fontFamily: "'Playfair Display', serif", fontWeight: 900, fontSize: "15px" }}>Confirm Use</button>
            </div>
          </div>
        </div>
      )}

      {restockModal && <RestockModal item={restockModal} onConfirm={handleRestock} onClose={() => setRestockModal(null)} />}

      {/* ADD MODAL */}
      {addModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "flex-start", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)", overflowY: "auto", padding: "20px 20px 40px", animation: "fadeIn .2s ease" }}>
          <div style={{ background: C.card, borderRadius: "16px", padding: "28px", width: "100%", maxWidth: "480px", boxShadow: C.shadowLg, animation: "fadeUp .2s ease", marginTop: "20px" }}>
            <div style={{ fontFamily: "'Playfair Display', serif", fontSize: "20px", fontWeight: 900, color: C.accent, marginBottom: "22px" }}>Add Pantry Item</div>

            {/* Barcode section */}
            <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: "10px", padding: "16px", marginBottom: "20px" }}>
              <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "10px" }}>BARCODE LOOKUP</div>
              <div style={{ display: "flex", gap: "8px" }}>
                <input value={barcodeInput} onChange={e => setBarcodeInput(e.target.value)} onKeyDown={e => e.key === "Enter" && doLookup(barcodeInput)} placeholder="Type barcode + Enter…"
                  style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "9px 12px", color: C.text, fontSize: "12px" }} />
                <button onClick={() => doLookup(barcodeInput)} style={{ background: C.accent, color: "#fff", border: "none", borderRadius: "6px", padding: "9px 14px", fontSize: "11px", letterSpacing: "1px", minWidth: "72px" }}>
                  {lookingUp ? <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>⟳</span> : "LOOK UP"}
                </button>
                <button onClick={() => { setAddModal(false); setShowCamera(true); }} title="Use camera" style={{ background: C.accentBg, color: C.accent, border: `1px solid ${C.accentBorder}`, borderRadius: "6px", padding: "9px 12px", fontSize: "18px" }}>📷</button>
              </div>
              {lookupStatus === "found"    && <div style={{ fontSize: "11px", color: C.accent, marginTop: "8px" }}>✓ Product found — fields pre-filled below</div>}
              {lookupStatus === "notfound" && <div style={{ fontSize: "11px", color: C.warn,   marginTop: "8px" }}>Not in database — fill in details manually</div>}
            </div>

            {/* Emoji picker */}
            <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "8px" }}>EMOJI</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "5px", background: C.surface, borderRadius: "8px", padding: "10px", marginBottom: "10px" }}>
              {FOOD_EMOJIS.map(e => (
                <span key={e} className="emoji-opt" onClick={() => setAddForm(f => ({ ...f, emoji: e }))} style={{ fontSize: "18px", opacity: addForm.emoji === e ? 1 : 0.4 }}>{e}</span>
              ))}
            </div>
            <div style={{ fontSize: "24px", textAlign: "center", marginBottom: "16px" }}>{addForm.emoji}</div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {[
                { key:"name",     label:"PRODUCT NAME *",     ph:"e.g. Sourdough Bread" },
                { key:"quantity", label:"STARTING AMOUNT *",  ph:"e.g. 20", type:"number" },
                { key:"unit",     label:"UNIT *",             ph:"slices, eggs, cups…" },
                { key:"lowAlert", label:"LOW STOCK ALERT AT", ph:"e.g. 4 (optional)" },
                { key:"note",     label:"NOTE",               ph:"e.g. 1 loaf = 20 slices" },
              ].map(f => (
                <div key={f.key}>
                  <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "5px" }}>{f.label}</div>
                  <input type={f.type || "text"} value={addForm[f.key]} placeholder={f.ph}
                    onChange={e => setAddForm(p => ({ ...p, [f.key]: e.target.value }))}
                    style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "9px 12px", color: C.text, fontSize: "13px" }} />
                </div>
              ))}
              <div>
                <div style={{ fontSize: "9px", color: C.muted, letterSpacing: "2px", marginBottom: "5px" }}>CATEGORY</div>
                <select value={addForm.category} onChange={e => setAddForm(p => ({ ...p, category: e.target.value }))}
                  style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: "6px", padding: "9px 12px", color: C.text, fontSize: "13px" }}>
                  {FOOD_CATEGORIES.filter(c => c !== "All").map(c => <option key={c}>{c}</option>)}
                </select>
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px", marginTop: "20px" }}>
              <button className="ghost-btn" onClick={() => { setAddModal(false); setAddForm(emptyForm); setBarcodeInput(""); setLookupStatus(null); }} style={{ flex: 1, background: C.surface, border: `1px solid ${C.border}`, borderRadius: "8px", padding: "12px", color: C.muted, fontSize: "12px" }}>Cancel</button>
              <button onClick={handleAdd} style={{ flex: 2, background: C.accent, color: "#fff", border: "none", borderRadius: "8px", padding: "12px", fontFamily: "'Playfair Display', serif", fontWeight: 900, fontSize: "15px" }}>Add to Pantry</button>
            </div>
          </div>
        </div>
      )}

      {/* TOAST */}
      {toast && (
        <div style={{ position: "fixed", bottom: "24px", right: "20px", zIndex: 400,
          background: toast.type === "err" ? C.dangerBg : toast.type === "warn" ? C.warnBg : C.greenBg,
          border: `1px solid ${toast.type === "err" ? C.dangerBorder : toast.type === "warn" ? C.warnBorder : C.accentBorder}`,
          color: toast.type === "err" ? C.danger : toast.type === "warn" ? C.warn : C.accent,
          borderRadius: "10px", padding: "12px 18px", fontSize: "12px", animation: "toastSlide .25s ease", maxWidth: "320px", lineHeight: 1.5, boxShadow: C.shadowMd,
        }}>{toast.msg}</div>
      )}
    </div>
  );
}
