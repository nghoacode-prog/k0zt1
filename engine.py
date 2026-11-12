# -*- coding: utf-8 -*-
"""LC79 prediction engine v16 — Short-Term Memory, Drift Killer, DB Anti-Lock."""
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
    """Khởi tạo kết nối SQLite với timeout cao để chống lỗi database is locked."""
    parent = Path(DATABASE_PATH).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False cho phép dùng kết nối trong Flask/Gunicorn
    conn = sqlite3.connect(DATABASE_PATH, timeout=60.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=60000")  # Chờ tối đa 60s nếu bị lock
    current_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if current_mode.lower() != "wal":
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


# ============ 8 MODULE LÕI (ALWAYS SIGNAL) ============

class PatternModule:
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
        if len(hist) < 2: return 0.5, 0.1
        for order in range(10, 1, -1):
            if len(hist) < order: continue
            cell = self.memory[order].get(tuple(hist[-order:]))
            if cell:
                c0, c1, last_idx = cell
                total = c0 + c1
                if total >= 1:
                    p = (c1 + 1.0) / (total + 2.0)
                    conf = min(1.0, total / 5.0) if (self.idx - last_idx) < 50 else 0.2
                    return p, max(0.1, conf)
        p = sum(hist[-3:]) / 3.0
        return max(0.1, min(0.9, p)), 0.1

class TrendModule:
    name = "trend"
    def __init__(self):
        self.fast = 0.5; self.slow = 0.5
    def update(self, hist, y):
        y = int(y)
        self.fast = 0.3 * y + 0.7 * self.fast
        self.slow = 0.05 * y + 0.95 * self.slow
    def predict(self, hist):
        p = self.fast
        conf = abs(self.fast - self.slow) * 5 + 0.1
        return p, max(0.1, min(1.0, conf))

class StreakModule:
    name = "streak"
    def __init__(self): self.stats = {}
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
        if not hist: return 0.5, 0.1
        side = hist[-1]; run = 1
        for v in reversed(hist[:-1]):
            if v != side: break
            run += 1
        cell = self.stats.get((side, min(run, 8)), [1.0, 1.0])
        p_cont = cell[0] / (cell[0] + cell[1])
        p = p_cont if side == 1 else 1.0 - p_cont
        conf = min(1.0, (cell[0] + cell[1]) / 10.0)
        return p, max(0.1, conf)

class AlternatingModule:
    name = "alternating"
    def predict(self, hist):
        if len(hist) < 4: return 0.5, 0.1
        if hist[-1] != hist[-2] and hist[-2] != hist[-3] and hist[-3] != hist[-4]:
            return (1.0 - hist[-1]), 0.85
        if len(hist) >= 6:
            if hist[-1] == hist[-2] and hist[-3] == hist[-4] and hist[-5] == hist[-6] and hist[-2] != hist[-3]:
                return (1.0 - hist[-1]), 0.9
        return 0.5, 0.1

class CycleModule:
    name = "cycle"
    def predict(self, hist):
        if len(hist) < 6: return 0.5, 0.1
        for lag in (2, 3, 4):
            if len(hist) >= lag * 2:
                if hist[-1] == hist[-1-lag] and hist[-2] == hist[-2-lag]:
                    return float(hist[-lag]), 0.75
        return 0.5, 0.1

class MomentumModule:
    name = "momentum"
    def predict(self, hist):
        if len(hist) < 5: return 0.5, 0.1
        p5 = sum(hist[-5:]) / 5.0
        p20 = sum(hist[-20:]) / len(hist[-20:])
        conf = abs(p5 - p20) * 4 + 0.1
        return p5, max(0.1, min(1.0, conf))

class FrequencyModule:
    name = "frequency"
    def predict(self, hist):
        if not hist: return 0.5, 0.1
        decay = 0.9; a = b = 0.0
        for v in hist:
            a *= decay; b *= decay
            if v: a += 1.0
            else: b += 1.0
        p = a / (a + b)
        conf = abs(p - 0.5) * 2 + 0.1
        return p, max(0.1, min(1.0, conf))

class BaseRateModule:
    name = "base_rate"
    def predict(self, hist):
        if not hist: return 0.5, 0.1
        p = (sum(hist) + 1.0) / (len(hist) + 2.0)
        return p, 0.2


# ============ ENGINE V16 ============

class PredictionEngine:
    EXPERTS = ("pattern", "trend", "streak", "alternating", "cycle", "momentum", "frequency", "base_rate")
    
    def __init__(self, history=None, table_code=""):
        self.table_code = table_code
        self.history = []
        self.pattern = PatternModule()
        self.trend = TrendModule()
        self.streak = StreakModule()
        self.alt = AlternatingModule()
        self.cycle = CycleModule()
        self.momentum = MomentumModule()
        self.frequency = FrequencyModule()
        self.base_rate = BaseRateModule()
        
        # Short-term memory (5 phiên) và đếm chuỗi thua
        self.memory_5 = {n: deque(maxlen=5) for n in self.EXPERTS}
        self.fails = {n: 0 for n in self.EXPERTS}
        
        for v in list(history or []): self._update(1 if int(v) == 1 else 0)

    def _update(self, y):
        hist = self.history[:]
        if len(hist) >= 10:
            preds = self._get_all_preds(hist)
            for name, (p, c) in preds.items():
                is_correct = int((1 if p >= 0.5 else 0) == y)
                self.memory_5[name].append((is_correct, c))
                if is_correct: self.fails[name] = 0
                else: self.fails[name] += 1

        self.pattern.update(hist, y)
        self.trend.update(hist, y)
        self.streak.update(hist, y)
        self.history.append(y)

    def _get_all_preds(self, hist):
        return {
            "pattern": self.pattern.predict(hist),
            "trend": self.trend.predict(hist),
            "streak": self.streak.predict(hist),
            "alternating": self.alt.predict(hist),
            "cycle": self.cycle.predict(hist),
            "momentum": self.momentum.predict(hist),
            "frequency": self.frequency.predict(hist),
            "base_rate": self.base_rate.predict(hist)
        }

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)
        if n < 10:
            last = self.history[-1] if self.history else 1
            return {
                "side": "TAI" if last == 1 else "XIU", "confidence": 58, 
                "p_internal": 0.6 if last == 1 else 0.4, "regime": "WARMUP", 
                "regime_conf": 0.0, "skip": False, "reason": None, 
                "modules": {}, "full": {"modules": {}, "p_internal": 0.5, "explanation": "Warmup"}
            }

        raw_preds = self._get_all_preds(self.history)
        final_preds = {}
        
        for name in self.EXPERTS:
            p, base_conf = raw_preds[name]
            
            # Auto-Invert: Sai >= 3 phiên và tự tin > 0.6 -> Đảo ngược kết quả
            if self.fails[name] >= 3 and base_conf >= 0.6:
                p = 1.0 - p
            
            # Short-Term Memory Weight: Bóp nghẹt trọng số nếu vừa sai
            weight = base_conf
            mem = self.memory_5[name]
            
            if mem:
                if mem[-1][0] == 0:
                    weight *= 0.1
                if len(mem) >= 2 and mem[-2][0] == 0:
                    weight *= 0.1
                recent_accuracy = sum(m[0] for m in mem) / len(mem)
                weight *= max(0.1, recent_accuracy * 2.0)

            final_preds[name] = [p, max(0.01, weight)]

        total_w = sum(final_preds[k][1] for k in self.EXPERTS)
        p_raw = sum(final_preds[k][0] * final_preds[k][1] for k in self.EXPERTS) / total_w

        if abs(p_raw - 0.5) < 1e-4:
            p_raw = 0.505 if self.history[-1] == 1 else 0.495

        p_raw = max(0.05, min(0.95, p_raw))
        edge = abs(p_raw - 0.5) * 2
        side = "TAI" if p_raw >= 0.5 else "XIU"

        # Ép chuẩn 58-72%
        confidence = int(round(58 + 14 * edge))
        confidence = max(58, min(72, confidence))

        mv = {name: {"p": round(final_preds[name][0], 4), "w": round(final_preds[name][1], 2)} for name in self.EXPERTS}

        return {
            "side": side, "confidence": confidence, "p_internal": p_raw,
            "regime": "AUTO", "regime_conf": edge, "skip": False, "reason": None,
            "modules": mv, "full": {"modules": mv, "p_internal": round(p_raw, 4), "explanation": "Short-Term Drift Killer"}
        }

    def observe(self, result):
        if result in ("TAI", "XIU"): self._update(1 if result == "TAI" else 0)
        elif isinstance(result, int): self._update(result)

    def to_dict(self):
        return {"history": list(self.history), "table_code": self.table_code}

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict): return cls()
        return cls(history=data.get("history", []), table_code=data.get("table_code", ""))


# ============ BACKTEST & HELPERS ============
class Backtest:
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
        return {"total_predictions": total, "correct": correct, "accuracy": correct / total if total else 0.0, "by_regime": by_regime, "by_confidence_bucket": by_conf, "by_side": by_side, "by_module": {k: {"votes": v[0], "correct": v[1], "accuracy": v[1] / v[0] if v[0] else 0.0} for k, v in by_module.items()}, "streak_wins": bestw, "streak_losses": bestl, "timeline": rows}

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
    conn = db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?", (now_iso(), str(error)[:500], now_iso(), table_code)); conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    conn = db(); rows = conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IN ('win','lose') ORDER BY session_id DESC LIMIT ?", (table_code, int(limit))).fetchall(); conn.close()
    return (sum(r[0] == "win" for r in rows) / len(rows)) if rows else 0.5
