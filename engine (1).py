# -*- coding: utf-8 -*-
"""LC79 prediction engine v12.1 — Instant Reaction, Streak Breaker, Ép 58-72%."""
from __future__ import annotations
import json, math, os, sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/tmp/lc79.db")
TABLES = {
    "lc79_tx": {"name": "Bàn Hũ", "url": "https://wtx.tele68.com/v1/tx/sessions"},
    "lc79_md5": {"name": "Bàn MD5", "url": "https://wtxmd52.tele68.com/v1/txmd5/sessions"},
}

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def db():
    parent = Path(DATABASE_PATH).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
CREATE TABLE IF NOT EXISTS tables_ (
    code TEXT PRIMARY KEY, name TEXT NOT NULL,
    game_code TEXT NOT NULL, game_name TEXT NOT NULL,
    upstream_url TEXT NOT NULL, is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS table_states (
    table_code TEXT PRIMARY KEY REFERENCES tables_(code),
    history_json TEXT, last_seen_id INTEGER DEFAULT 0,
    last_poll_at TEXT, last_poll_error TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL,
    session_id INTEGER NOT NULL, prediction TEXT NOT NULL,
    confidence INTEGER NOT NULL, actual TEXT, result TEXT,
    resolved_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pred_unique ON predictions(table_code, session_id);
CREATE INDEX IF NOT EXISTS idx_pred_table ON predictions(table_code, session_id DESC);
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY, scope TEXT NOT NULL, note TEXT,
    is_active INTEGER DEFAULT 1, expires_at TEXT, days INTEGER DEFAULT 7,
    max_devices INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT, activated INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_key_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL REFERENCES api_keys(key),
    device_id TEXT NOT NULL, ip TEXT, user_agent TEXT, browser TEXT, os TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, released_at TEXT, released_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_key ON api_key_devices(key, released_at);
CREATE TABLE IF NOT EXISTS activation_codes (
    code TEXT PRIMARY KEY, scope TEXT NOT NULL, days INTEGER NOT NULL,
    max_uses INTEGER DEFAULT -1, used_count INTEGER DEFAULT 0,
    expires_at TEXT, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, code TEXT, success INTEGER,
    ip TEXT, user_agent TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user TEXT, action TEXT,
    target TEXT, detail_json TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS engine_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL,
    reason TEXT NOT NULL, accuracy_before REAL, sessions_at_reset INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT, window TEXT, count INTEGER, PRIMARY KEY (key, window)
);
""")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(predictions)").fetchall()}
    if "detail_json" not in cols:
        conn.execute("ALTER TABLE predictions ADD COLUMN detail_json TEXT")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS prediction_resolutions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL,
      session_id INTEGER NOT NULL, prediction TEXT, actual TEXT, result TEXT,
      regime TEXT, regime_conf REAL, confidence INTEGER, top_module TEXT,
      top_module_p REAL, module_votes_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_resol_unique ON prediction_resolutions(table_code,session_id);
    CREATE INDEX IF NOT EXISTS idx_resol_date ON prediction_resolutions(created_at);
    CREATE TABLE IF NOT EXISTS table_configs(table_code TEXT PRIMARY KEY,config_json TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS broadcasts(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS worker_control(key TEXT PRIMARY KEY,value TEXT,updated_at TEXT);
    """)
    for i, (code, meta) in enumerate(TABLES.items(), 1):
        conn.execute("INSERT OR IGNORE INTO tables_(code,name,game_code,game_name,upstream_url,is_active,sort_order) VALUES(?,?,?,?,?,1,?)",
                     (code, meta["name"], "lc79", "LC79", meta["url"], i))
        conn.execute("INSERT OR IGNORE INTO table_states(table_code) VALUES(?)", (code,))
    conn.commit(); conn.close()

def parse_upstream(raw):
    if not isinstance(raw, dict): return None
    items = raw.get("list")
    if not isinstance(items, list) or not items: return None
    sessions = []
    for item in items:
        if not isinstance(item, dict): continue
        try: sid = int(item.get("id", 0))
        except (TypeError, ValueError): continue
        if sid <= 0: continue
        rs = str(item.get("resultTruyenThong", "")).strip().upper()
        if rs == "TAI": result = 1
        elif rs == "XIU": result = 0
        else: continue
        dices = item.get("dices")
        if not isinstance(dices, list) or len(dices) != 3: dices = None
        point = item.get("point")
        if not isinstance(point, int) or not (3 <= point <= 18):
            point = sum(dices) if dices else None
        sessions.append({"session_id": sid, "result": result, "dices": dices, "tong": point})
    sessions.sort(key=lambda s: s["session_id"])
    if not sessions: return None
    return {"sessions": sessions, "latest_id": sessions[-1]["session_id"]}


# ============ 4 MODULE LÕI ============

class PatternModule:
    """Dò tìm Pattern từ 2-10 phiên trong quá khứ."""
    name = "pattern"
    def __init__(self):
        self.memory = {k: {} for k in range(2, 11)}
        self.idx = 0

    def update(self, hist, y):
        y = int(y)
        for order in range(2, 11):
            if len(hist) >= order:
                seq = tuple(hist[-order:])
                cell = self.memory[order].setdefault(seq, [0.0, 0.0, self.idx])
                cell[y] += 1.0
                cell[2] = self.idx
        self.idx += 1

    def predict(self, hist):
        if len(hist) < 2: return 0.5, 0.0
        p_num, w_sum = 0.0, 0.0
        for order in range(10, 1, -1):
            if len(hist) < order: continue
            cell = self.memory[order].get(tuple(hist[-order:]))
            if cell:
                c0, c1, last_idx = cell
                total = c0 + c1
                if total >= 2:
                    p = (c1 + 1.0) / (total + 2.0)
                    freshness = 1.0 if (self.idx - last_idx) < 50 else 0.5
                    w = total * freshness * (1.0 + order * 0.1)
                    p_num += p * w
                    w_sum += w
        if w_sum == 0: return 0.5, 0.0
        return p_num / w_sum, min(1.0, w_sum / 20.0)


class StreakModule:
    """CHỐNG BỆT NGU: Chỉ kích hoạt khi thực sự có xác suất bệt > 55%."""
    name = "streak"
    def __init__(self):
        self.stats = {}
    def update(self, hist, y):
        if not hist: return
        side = hist[-1]; run = 1
        for v in reversed(hist[:-1]):
            if v != side: break
            run += 1
        key = (side, min(run, 8))
        cell = self.stats.setdefault(key, [1.0, 1.0])
        cell[0 if y == side else 1] += 1.0

    def predict(self, hist):
        if not hist: return 0.5, 0.0
        side = hist[-1]; run = 1
        for v in reversed(hist[:-1]):
            if v != side: break
            run += 1
            
        cell = self.stats.get((side, min(run, 8)), [1.0, 1.0])
        p_cont = cell[0] / (cell[0] + cell[1])
        
        if run < 4: return 0.5, 0.0 # Bệt < 4 phiên đéo tin
        if p_cont < 0.55: return 0.5, 0.0 # Xác suất tiếp diễn phải > 55%
        
        p = p_cont if side == 1 else 1.0 - p_cont
        return p, min(1.0, sum(cell) / 15.0)


class AlternatingModule:
    """Bắt cầu đảo 1-1, 2-2."""
    name = "alternating"
    def predict(self, hist):
        if len(hist) < 6: return 0.5, 0.0
        if all(hist[-i] != hist[-i-1] for i in range(1, 6)):
            return (1.0 - hist[-1]), 0.85
            
        tail8 = hist[-8:]
        blocks = []
        cur = tail8[0]; cnt = 1
        for v in tail8[1:]:
            if v == cur: cnt += 1
            else: blocks.append(cnt); cur = v; cnt = 1
        blocks.append(cnt)
        if len(blocks) >= 3 and all(b == 2 for b in blocks[-3:]):
            return (1.0 - hist[-1]), 0.90
        return 0.5, 0.0


class TrendModule:
    """Trend rõ ràng mới đánh."""
    name = "trend"
    def __init__(self):
        self.fast_a = 1.0 - 0.5 ** (1.0/10.0)
        self.slow_a = 1.0 - 0.5 ** (1.0/30.0)
        self.fast = 0.5
        self.slow = 0.5

    def update(self, hist, y):
        y = int(y)
        self.fast = self.fast_a * y + (1 - self.fast_a) * self.fast
        self.slow = self.slow_a * y + (1 - self.slow_a) * self.slow

    def predict(self, hist):
        mom = self.fast - self.slow
        if abs(mom) < 0.1: return 0.5, 0.0 # Trend yếu đéo đánh
        p = self.fast + 0.5 * mom
        p = max(0.05, min(0.95, p))
        return p, min(1.0, abs(mom) * 4)


# ============ ENGINE V12 (INSTANT REACTION) ============

class PredictionEngine:
    EXPERTS = ("pattern", "streak", "alternating", "trend")
    
    def __init__(self, history=None, table_code=""):
        self.table_code = table_code
        self.history = []
        self.pattern = PatternModule()
        self.streak = StreakModule()
        self.alt = AlternatingModule()
        self.trend = TrendModule()
        
        # Track chuỗi thua liên tiếp để Auto-Invert
        self.fails = {n: 0 for n in self.EXPERTS}
        
        for v in list(history or []): self._update(1 if int(v) == 1 else 0)

    def _update(self, y):
        hist = self.history[:]
        
        # Đánh giá kết quả của phiên vừa rồi để cộng/trừ điểm phạt
        if len(hist) >= 15:
            p_pat, c_pat = self.pattern.predict(hist)
            p_st, c_st = self.streak.predict(hist)
            p_al, c_al = self.alt.predict(hist)
            p_tr, c_tr = self.trend.predict(hist)
            
            # Nếu module có tín hiệu, kiểm tra xem nó đúng hay sai
            if c_pat > 0:
                if (1 if p_pat >= 0.5 else 0) != y: self.fails["pattern"] += 1
                else: self.fails["pattern"] = 0
                
            if c_st > 0:
                if (1 if p_st >= 0.5 else 0) != y: self.fails["streak"] += 1
                else: self.fails["streak"] = 0
                
            if c_al > 0:
                if (1 if p_al >= 0.5 else 0) != y: self.fails["alternating"] += 1
                else: self.fails["alternating"] = 0
                
            if c_tr > 0:
                if (1 if p_tr >= 0.5 else 0) != y: self.fails["trend"] += 1
                else: self.fails["trend"] = 0

        self.pattern.update(hist, y)
        self.streak.update(hist, y)
        self.trend.update(hist, y)
        self.history.append(y)

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)
        if n < 15:
            last = self.history[-1] if self.history else 1
            return {
                "side": "TAI" if last == 1 else "XIU", "confidence": 58, 
                "p_internal": 0.6 if last == 1 else 0.4, "regime": "WARMUP", 
                "regime_conf": 0.0, "skip": False, "reason": None, 
                "modules": {}, "full": {"modules": {}, "p_internal": 0.5, "explanation": "Warmup"}
            }

        p_pat, c_pat = self.pattern.predict(self.history)
        p_st, c_st = self.streak.predict(self.history)
        p_al, c_al = self.alt.predict(self.history)
        p_tr, c_tr = self.trend.predict(self.history)

        # Logic Instant Reaction
        def apply_instant_reaction(name, p, c):
            if c == 0.0: return 0.5, 0.0
            fails = self.fails[name]
            
            # 1. Sai 2 phiên liên tiếp -> CÚT (Weight = 0)
            if fails == 2:
                return 0.5, 0.0
            
            # 2. Sai >= 3 phiên liên tiếp -> AUTO INVERT (Đảo ngược)
            if fails >= 3:
                return 1.0 - p, c  # Trả về xác suất đảo ngược
                
            return p, c

        p_pat, c_pat = apply_instant_reaction("pattern", p_pat, c_pat)
        p_st, c_st = apply_instant_reaction("streak", p_st, c_st)
        p_al, c_al = apply_instant_reaction("alternating", p_al, c_al)
        p_tr, c_tr = apply_instant_reaction("trend", p_tr, c_tr)

        # Lọc Bias: Nếu 10 phiên gần nhất lệch > 70% về 1 bên, phạt các module đi ngược
        if len(self.history) >= 10:
            recent_tai = sum(self.history[-10:])
            if recent_tai >= 7: # Thiên TÀI
                if p_pat < 0.5: p_pat = 0.5; c_pat = 0.0
                if p_st < 0.5: p_st = 0.5; c_st = 0.0
            elif recent_tai <= 3: # Thiên XỈU
                if p_pat > 0.5: p_pat = 0.5; c_pat = 0.0
                if p_st > 0.5: p_st = 0.5; c_st = 0.0

        total_w = c_pat + c_st + c_al + c_tr

        if total_w == 0.0:
            # Fallback: Nếu tất cả tịt, dùng Pattern 3 phiên
            cell3 = self.pattern.memory[3].get(tuple(self.history[-3:]))
            if cell3 and sum(cell3[:2]) >= 1:
                p_raw = (cell3[1] + 1.0) / (sum(cell3[:2]) + 2.0)
            else:
                p_raw = self.trend.slow
            if p_raw == 0.5: p_raw = 0.51 if self.history[-1] == 0 else 0.49
        else:
            p_raw = (p_pat*c_pat + p_st*c_st + p_al*c_al + p_tr*c_tr) / total_w

        p_raw = max(0.05, min(0.95, p_raw))
        edge = abs(p_raw - 0.5) * 2
        side = "TAI" if p_raw >= 0.5 else "XIU"

        # ÉP CHUẨN 58-72%
        confidence = int(round(58 + 14 * edge))
        confidence = max(58, min(72, confidence))

        mv = {
            "pattern": {"p": round(p_pat, 4), "w": round(c_pat, 2)},
            "streak": {"p": round(p_st, 4), "w": round(c_st, 2)},
            "alternating": {"p": round(p_al, 4), "w": round(c_al, 2)},
            "trend": {"p": round(p_tr, 4), "w": round(c_tr, 2)}
        }

        return {
            "side": side, "confidence": confidence, "p_internal": p_raw,
            "regime": "AUTO", "regime_conf": edge, "skip": False, "reason": None,
            "modules": mv, "full": {"modules": mv, "p_internal": round(p_raw, 4), "explanation": "Instant Reaction"}
        }

    def predict_detail(self, accuracy_100=.5, accuracy_500=.5):
        """Chi tiết dự đoán cho admin (/regime và trang bàn)."""
        pred = self.predict(accuracy_100, accuracy_500)
        mods = pred.get("modules", {})
        out = dict(pred)
        out["modules"] = {k: {"p": v.get("p", 0.5), "w": v.get("w", 0.0), "weight": v.get("w", 0.0)} for k, v in mods.items()}
        out["weights"] = {k: v.get("w", 0.0) for k, v in mods.items()}
        out["regime_details"] = {"label": pred.get("regime"), "edge": pred.get("regime_conf", 0.0), "history_len": len(self.history)}
        return out

    def observe(self, result):
        if result in ("TAI", "XIU"): self._update(1 if result == "TAI" else 0)
        elif isinstance(result, int): self._update(result)

    def to_dict(self):
        return {"history": list(self.history), "table_code": self.table_code}

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict): return cls()
        return cls(history=data.get("history", []), table_code=data.get("table_code", ""))


# ============ BACKTEST ============

class Backtest:
    """Chạy lại engine trên lịch sử (1=TAI, 0=XIU) để đo độ chính xác."""
    @staticmethod
    def run(history, warmup=30):
        eng = PredictionEngine()
        rows, correct = [], 0
        by_regime, by_conf, by_side = {}, {}, {}
        by_module = {n: [0, 0] for n in PredictionEngine.EXPERTS}
        wins = losses = bestw = bestl = 0
        for y in history:
            pred = eng.predict()
            if len(eng.history) >= warmup and not pred.get("skip"):
                side = pred.get("side")
                ok = side == ("TAI" if y else "XIU")
                correct += int(ok)
                wins = wins + 1 if ok else 0
                losses = losses + 1 if not ok else 0
                bestw, bestl = max(bestw, wins), max(bestl, losses)
                for mn, mv in pred.get("modules", {}).items():
                    if mn not in by_module:
                        continue
                    mok = (float(mv.get("p", 0.5)) >= 0.5) == bool(y)
                    by_module[mn][0] += 1
                    by_module[mn][1] += int(mok)
                r = pred.get("regime", "AUTO")
                bucket = str((pred.get("confidence", 50) // 5) * 5)
                for d, k in ((by_regime, r), (by_conf, bucket), (by_side, side)):
                    d.setdefault(k, [0, 0]); d[k][0] += 1; d[k][1] += int(ok)
                rows.append({"actual": y, "prediction": side, "correct": ok, "regime": r, "confidence": pred.get("confidence", 50)})
            eng.observe(y)
        total = len(rows)
        return {"total_predictions": total, "correct": correct, "accuracy": correct / total if total else 0.0,
                "by_regime": by_regime, "by_confidence_bucket": by_conf, "by_side": by_side,
                "by_module": {k: {"votes": v[0], "correct": v[1], "accuracy": v[1] / v[0] if v[0] else 0.0} for k, v in by_module.items()},
                "streak_wins": bestw, "streak_losses": bestl, "timeline": rows}


# ==============================================================================
# PERSISTENCE & HELPERS
# ==============================================================================
def resolve_actual(table_code, sessions):
    c = db(); count = 0
    for x in sessions:
        sid = int(x.get("session_id", 0)); actual = "TAI" if int(x.get("result", 0)) == 1 else "XIU"
        r = c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=? AND actual IS NULL", (table_code, sid)).fetchone()
        if not r: continue
        result = "win" if r["prediction"] == actual else "lose"
        detail = {}
        try: detail = json.loads(r["detail_json"] or "{}")
        except Exception: pass
        modules = detail.get("modules", {}); top = max(modules.items(), key=lambda z: z[1].get("w", 0)) if modules else (None, {})
        
        c.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?", (actual, result, now_iso(), r["id"]))
        c.execute("INSERT OR IGNORE INTO prediction_resolutions(table_code,session_id,prediction,actual,result,regime,regime_conf,confidence,top_module,top_module_p,module_votes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (table_code, sid, r["prediction"], actual, result, detail.get("regime"), detail.get("regime_conf"), r["confidence"], top[0], top[1].get("p"), json.dumps(modules)))
        count += 1
    c.commit(); c.close(); return count

def get_table_config(table_code): return {}
def save_table_config(table_code, config): pass

def accuracy_detail(table_code, days=7):
    c = db(); r = c.execute("SELECT COUNT(*) total,SUM(result='win') wins,SUM(result='lose') losses FROM predictions WHERE table_code=? AND result IN ('win','lose') AND resolved_at>=datetime('now',?)", (table_code, f"-{int(days)} days")).fetchone(); c.close()
    total = r["total"] or 0; wins = r["wins"] or 0
    return {"total": total, "wins": wins, "losses": r["losses"] or 0, "accuracy": wins / total if total else 0.0}

def get_broadcast():
    c = db(); r = c.execute("SELECT message FROM broadcasts WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone(); c.close(); return r[0] if r else ""

def set_worker_control(key, value):
    c = db(); c.execute("INSERT INTO worker_control(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", (key, str(value), now_iso())); c.commit(); c.close()

def get_worker_control(key, default=None):
    c = db(); r = c.execute("SELECT value FROM worker_control WHERE key=?", (key,)).fetchone(); c.close(); return r[0] if r else default

def load_engine(table_code):
    conn = db(); row = conn.execute("SELECT history_json FROM table_states WHERE table_code=?", (table_code,)).fetchone(); conn.close()
    try: state = json.loads(row["history_json"] or '{"history":[]}') if row else {"history": []}
    except (ValueError, TypeError): state = {"history": []}
    obj = PredictionEngine.from_dict(state); obj.table_code = table_code
    return obj

def save_engine(table_code, engine):
    conn = db(); conn.execute("UPDATE table_states SET history_json=?,updated_at=? WHERE table_code=?", (json.dumps(engine.to_dict(), separators=(",", ":")), now_iso(), table_code)); conn.commit(); conn.close()

def load_last_seen(table_code):
    conn = db(); row = conn.execute("SELECT last_seen_id FROM table_states WHERE table_code=?", (table_code,)).fetchone(); conn.close()
    return int(row[0]) if row else 0

def save_last_seen(table_code, session_id):
    conn = db(); conn.execute("UPDATE table_states SET last_seen_id=?,updated_at=? WHERE table_code=?", (int(session_id), now_iso(), table_code)); conn.commit(); conn.close()

def save_worker_state(table_code, engine, session_id):
    conn = db(); conn.execute("UPDATE table_states SET history_json=?,last_seen_id=?,updated_at=? WHERE table_code=?", (json.dumps(engine.to_dict(), separators=(",", ":")), int(session_id), now_iso(), table_code)); conn.commit(); conn.close()

def mark_poll_ok(table_code):
    conn = db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=NULL,updated_at=? WHERE table_code=?", (now_iso(), now_iso(), table_code)); conn.commit(); conn.close()

def mark_poll_error(table_code, error):
    conn = db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?",  (now_iso(), str(error)[:500], now_iso(), table_code)); conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    conn = db(); rows = conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IN ('win','lose') ORDER BY session_id DESC LIMIT ?", (table_code, int(limit))).fetchall(); conn.close()
    return (sum(r[0] == "win" for r in rows) / len(rows)) if rows else 0.5