# -*- coding: utf-8 -*-
"""LC79 prediction engine v22 — Meta-Ensemble Core (105-Session Optimized)."""
from __future__ import annotations
import json, math, os, sqlite3
from collections import deque, defaultdict
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
    conn = sqlite3.connect(DATABASE_PATH, timeout=60.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=60000")
    if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
        conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
CREATE TABLE IF NOT EXISTS tables_ (code TEXT PRIMARY KEY, name TEXT NOT NULL, game_code TEXT NOT NULL, game_name TEXT NOT NULL, upstream_url TEXT NOT NULL, is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS table_states (table_code TEXT PRIMARY KEY REFERENCES tables_(code), history_json TEXT, last_seen_id INTEGER DEFAULT 0, last_poll_at TEXT, last_poll_error TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS predictions (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, session_id INTEGER NOT NULL, prediction TEXT NOT NULL, confidence INTEGER NOT NULL, actual TEXT, result TEXT, resolved_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pred_unique ON predictions(table_code, session_id);
CREATE INDEX IF NOT EXISTS idx_pred_table ON predictions(table_code, session_id DESC);
CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, scope TEXT NOT NULL, note TEXT, is_active INTEGER DEFAULT 1, expires_at TEXT, days INTEGER DEFAULT 7, max_devices INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT, activated INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS api_key_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL REFERENCES api_keys(key), device_id TEXT NOT NULL, ip TEXT, user_agent TEXT, browser TEXT, os TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, released_at TEXT, released_reason TEXT);
CREATE INDEX IF NOT EXISTS idx_devices_key ON api_key_devices(key, released_at);
CREATE TABLE IF NOT EXISTS activation_codes (code TEXT PRIMARY KEY, scope TEXT NOT NULL, days INTEGER NOT NULL, max_uses INTEGER DEFAULT -1, used_count INTEGER DEFAULT 0, expires_at TEXT, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS activation_log (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, code TEXT, success INTEGER, ip TEXT, user_agent TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS admin_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user TEXT, action TEXT, target TEXT, detail_json TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS engine_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, reason TEXT NOT NULL, accuracy_before REAL, sessions_at_reset INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS rate_limits (key TEXT, window TEXT, count INTEGER, PRIMARY KEY (key, window));
""")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(predictions)").fetchall()}
    if "detail_json" not in cols: conn.execute("ALTER TABLE predictions ADD COLUMN detail_json TEXT")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS prediction_resolutions (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, session_id INTEGER NOT NULL, prediction TEXT, actual TEXT, result TEXT, regime TEXT, regime_conf REAL, confidence INTEGER, top_module TEXT, top_module_p REAL, module_votes_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_resol_unique ON prediction_resolutions(table_code,session_id);
    CREATE INDEX IF NOT EXISTS idx_resol_date ON prediction_resolutions(created_at);
    CREATE TABLE IF NOT EXISTS table_configs(table_code TEXT PRIMARY KEY,config_json TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS broadcasts(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS worker_control(key TEXT PRIMARY KEY,value TEXT,updated_at TEXT);
    """)
    for i, (code, meta) in enumerate(TABLES.items(), 1):
        conn.execute("INSERT OR IGNORE INTO tables_(code,name,game_code,game_name,upstream_url,is_active,sort_order) VALUES(?,?,?,?,?,1,?)", (code, meta["name"], "lc79", "LC79", meta["url"], i))
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
        if not isinstance(point, int) or not (3 <= point <= 18): point = sum(dices) if dices else None
        sessions.append({"session_id": sid, "result": result, "dices": dices, "tong": point})
    sessions.sort(key=lambda s: s["session_id"])
    if not sessions: return None
    return {"sessions": sessions, "latest_id": sessions[-1]["session_id"]}


# =========================================================
# CORE PREDICTION MODULES — V23
# Giữ nguyên tên class, method và giao kèo dữ liệu cũ.
# Chỉ thay cách ước lượng xác suất và cách tổng hợp tín hiệu.
# =========================================================

def _clip_prob(p, lo=0.02, hi=0.98):
    return max(lo, min(hi, float(p)))

def _smooth_rate(successes, total, prior=0.5, strength=8.0):
    """Beta-style smoothing: tránh xác suất cực đoan khi mẫu ít."""
    return (float(successes) + prior * strength) / (float(total) + strength)

def _effective_confidence(p, n, min_n=8):
    """Độ mạnh tín hiệu có co về 0 khi ít mẫu hoặc gần 50/50."""
    if n <= 0:
        return 0.0
    support = min(1.0, n / float(min_n * 3))
    return min(1.0, abs(float(p) - 0.5) * 2.0 * support)


class SequenceMatcher:
    """1. So khớp chuỗi lịch sử; chỉ tin mẫu lặp có đủ số lần hỗ trợ."""
    name = "sequence"

    def predict(self, hist):
        n = len(hist)
        if n < 12:
            return 0.5, 0.0

        # Ưu tiên chuỗi dài, nhưng không để một mẫu đơn lẻ quyết định.
        for length in (5, 4, 3):
            pattern = tuple(hist[-length:])
            outcomes = []
            # Chỉ dùng các mẫu đã có kết quả kế tiếp trong quá khứ.
            for i in range(0, n - length):
                if tuple(hist[i:i + length]) == pattern:
                    outcomes.append(hist[i + length])
            if len(outcomes) >= 4:
                p = _smooth_rate(sum(outcomes), len(outcomes), 0.5, 6.0)
                return p, _effective_confidence(p, len(outcomes), 8)
        return 0.5, 0.0


class CUSUMDetector:
    """2. Phát hiện lệch gần đây; không phát tín hiệu cực đoan từ vài phiên."""
    name = "cusum"

    def __init__(self):
        self.mean = 0.5

    def predict(self, hist):
        if len(hist) < 20:
            return 0.5, 0.0

        recent = hist[-30:]
        # So sánh cửa sổ gần với nền dài hơn; shrinkage giữ dự báo ổn định.
        baseline = _smooth_rate(sum(hist[:-min(30, len(hist))]), 
                                len(hist[:-min(30, len(hist))]), 0.5, 12.0)
        recent_rate = _smooth_rate(sum(recent), len(recent), baseline, 10.0)
        delta = recent_rate - baseline
        p = _clip_prob(0.5 + delta * 0.55)
        conf = _effective_confidence(p, len(recent), 20)
        return p, conf


class HazardRate:
    """3. Ước lượng xác suất tiếp diễn chuỗi theo các run lịch sử tương đương."""
    name = "hazard"

    def predict(self, hist):
        if len(hist) < 12:
            return 0.5, 0.0

        side = hist[-1]
        run = 1
        for x in reversed(hist[:-1]):
            if x == side:
                run += 1
            else:
                break

        # Tập hợp các chuỗi cùng phía đã từng đạt ít nhất độ dài hiện tại.
        at_risk = 0
        continued = 0
        for i in range(len(hist) - 1):
            if hist[i] != side:
                continue
            r = 1
            j = i
            while j > 0 and hist[j - 1] == side:
                r += 1
                j -= 1
            if r == run and i + 1 < len(hist):
                at_risk += 1
                if hist[i + 1] == side:
                    continued += 1

        if at_risk < 4:
            return 0.5, 0.0
        p_continue = _smooth_rate(continued, at_risk, 0.5, 8.0)
        # Output convention: probability of TAI.
        p_tai = p_continue if side == 1 else 1.0 - p_continue
        return p_tai, _effective_confidence(p_tai, at_risk, 10)


class TransitionMatrix:
    """4. Markov bậc 1/2 có smoothing và giảm trọng số bậc 2 khi ít mẫu."""
    name = "transition"

    def predict(self, hist):
        if len(hist) < 12:
            return 0.5, 0.0

        last = hist[-1]
        prev = hist[-2]

        c1_tai = sum(1 for i in range(1, len(hist))
                     if hist[i - 1] == last and hist[i] == 1)
        c1_tot = sum(1 for i in range(1, len(hist))
                     if hist[i - 1] == last)
        p1 = _smooth_rate(c1_tai, c1_tot, 0.5, 8.0)

        c2_tai = sum(1 for i in range(2, len(hist))
                     if hist[i - 2] == prev and hist[i - 1] == last and hist[i] == 1)
        c2_tot = sum(1 for i in range(2, len(hist))
                     if hist[i - 2] == prev and hist[i - 1] == last)
        p2 = _smooth_rate(c2_tai, c2_tot, p1, 10.0)

        # Bậc 2 chỉ có tiếng nói khi có đủ dữ liệu; tránh overfit.
        w2 = min(0.45, c2_tot / 20.0)
        p = _clip_prob(p1 * (1.0 - w2) + p2 * w2)
        support = c1_tot + min(c2_tot, 10)
        return p, _effective_confidence(p, support, 20)


class GlobalBias:
    """5. Nền xác suất dài hạn kết hợp cửa sổ gần, có shrinkage."""
    name = "bias"

    def predict(self, hist):
        if len(hist) < 20:
            return 0.5, 0.0

        long_p = _smooth_rate(sum(hist), len(hist), 0.5, 20.0)
        recent = hist[-50:]
        recent_p = _smooth_rate(sum(recent), len(recent), long_p, 15.0)
        p = _clip_prob(0.7 * long_p + 0.3 * recent_p)
        return p, _effective_confidence(p, len(hist), 60)


# =========================================================
# ENGINE TỔNG HỢP — giữ nguyên API V22
# =========================================================

class PredictionEngine:
    EXPERTS = ("sequence", "cusum", "hazard", "transition", "bias")

    def __init__(self, history=None, table_code=""):
        self.table_code = table_code
        self.history = []
        self.sequence = SequenceMatcher()
        self.cusum = CUSUMDetector()
        self.hazard = HazardRate()
        self.transition = TransitionMatrix()
        self.bias = GlobalBias()
        # Giữ thuộc tính memory để không phá code tích hợp cũ.
        # Mỗi phần tử lưu lỗi Brier (càng thấp càng tốt), tối đa 100 mẫu.
        self.memory = {n: deque(maxlen=100) for n in self.EXPERTS}
        for v in list(history or []):
            try:
                y = int(v)
            except (TypeError, ValueError):
                continue
            if y in (0, 1):
                self._update(y)

    def _get_all_preds(self, hist):
        return {
            "sequence": self.sequence.predict(hist),
            "cusum": self.cusum.predict(hist),
            "hazard": self.hazard.predict(hist),
            "transition": self.transition.predict(hist),
            "bias": self.bias.predict(hist)
        }

    def _update(self, y):
        # Chấm điểm dự báo tại thời điểm trước khi biết kết quả y.
        if len(self.history) >= 5:
            preds = self._get_all_preds(self.history)
            for name, (p, conf) in preds.items():
                if conf > 0:
                    self.memory[name].append((float(p) - int(y)) ** 2)
        self.history.append(int(y))

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)
        raw_preds = self._get_all_preds(self.history) if n >= 5 else {
            name: (0.5, 0.0) for name in self.EXPERTS
        }

        # Online weighting dựa trên Brier score; trọng số bị chặn để
        # một module không thể chi phối chỉ nhờ vài kết quả ngắn hạn.
        weighted = {}
        for name in self.EXPERTS:
            p, base_conf = raw_preds[name]
            if self.memory[name]:
                brier = sum(self.memory[name]) / len(self.memory[name])
                skill = max(0.20, min(1.20, 1.0 - brier))
            else:
                skill = 0.75
            weight = max(0.0, base_conf) * skill
            weighted[name] = [float(p), weight]

        total_w = sum(v[1] for v in weighted.values())
        if total_w > 1e-12:
            p_raw = sum(p * w for p, w in weighted.values()) / total_w
        else:
            # Khi chưa có module đủ bằng chứng, dùng prior trung tính
            # thay vì bịa hướng dự đoán.
            p_raw = 0.5

        p_raw = _clip_prob(p_raw, 0.02, 0.98)
        edge = abs(p_raw - 0.5) * 2.0
        side = "TAI" if p_raw >= 0.5 else "XIU"

        # Confidence là độ mạnh tín hiệu, không ép thành 58–72%.
        confidence = int(round(50.0 + edge * 30.0))
        confidence = max(50, min(80, confidence))

        # Giữ auto-predict và các key cũ để frontend/backend không gãy.
        # skip chỉ bật khi không có đủ lịch sử hoặc không có module hỗ trợ.
        supported = any(v[1] >= 0.025 for v in weighted.values())
        skip = (n < 12) or (not supported)
        reason = "WARMUP" if n < 12 else ("NO_RELIABLE_SIGNAL" if not supported else None)

        mv = {
            name: {"p": round(weighted[name][0], 4),
                   "w": round(weighted[name][1], 4)}
            for name in self.EXPERTS
        }

        return {
            "side": side,
            "confidence": confidence,
            "p_internal": round(p_raw, 6),
            "regime": "WARMUP" if n < 12 else "AUTO",
            "regime_conf": round(edge, 4),
            "skip": skip,
            "reason": reason,
            "modules": mv,
            "full": {
                "modules": mv,
                "p_internal": round(p_raw, 6),
                "explanation": "V23 calibrated Bayesian ensemble"
            }
        }

    def observe(self, result):
        if result in ("TAI", "XIU"):
            self._update(1 if result == "TAI" else 0)
        elif isinstance(result, int) and result in (0, 1):
            self._update(result)

    def to_dict(self):
        # Giữ nguyên schema lưu cũ; memory được dựng lại khi load.
        return {"history": list(self.history), "table_code": self.table_code}

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        return cls(history=data.get("history", []),
                   table_code=data.get("table_code", ""))


# ============ CÁC HÀM HELPER (Giữ nguyên) ============
class Backtest:
    @staticmethod
    def run(history, warmup=10):
        eng = PredictionEngine()
        rows, correct = [], 0
        for y in history:
            pred = eng.predict()
            if len(eng.history) >= warmup:
                ok = pred["side"] == ("TAI" if y else "XIU")
                correct += int(ok)
                rows.append({"actual": y, "prediction": pred["side"], "correct": ok})
            eng.observe(y)
        return {"total": len(rows), "correct": correct, "accuracy": correct/len(rows) if rows else 0}

def resolve_actual(table_code, sessions):
    c = db(); count = 0
    for x in sessions:
        sid = int(x.get("session_id", 0)); actual = "TAI" if int(x.get("result", 0)) == 1 else "XIU"
        r = c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=? AND actual IS NULL", (table_code, sid)).fetchone()
        if not r: continue
        result = "win" if r["prediction"] == actual else "lose"
        detail = json.loads(r["detail_json"] or "{}")
        modules = detail.get("modules", {}); top = max(modules.items(), key=lambda z: z[1].get("w", 0)) if modules else (None, {})
        c.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?", (actual, result, now_iso(), r["id"]))
        c.execute("INSERT OR IGNORE INTO prediction_resolutions(table_code,session_id,prediction,actual,result,regime,regime_conf,confidence,top_module,top_module_p,module_votes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (table_code, sid, r["prediction"], actual, result, detail.get("regime"), detail.get("regime_conf"), r["confidence"], top[0], top[1].get("p"), json.dumps(modules)))
        count += 1
    c.commit(); c.close(); return count

def get_table_config(table_code): return {}
def save_table_config(table_code, config): pass
def accuracy_detail(table_code, days=7): return {"total":0,"wins":0,"losses":0,"accuracy":0.0}
def get_broadcast(): return ""
def set_worker_control(key, value): pass
def get_worker_control(key, default=None): return default

def load_engine(table_code):
    conn = db(); row = conn.execute("SELECT history_json FROM table_states WHERE table_code=?", (table_code,)).fetchone(); conn.close()
    try: state = json.loads(row["history_json"] or '{"history":[]}') if row else {"history": []}
    except: state = {"history": []}
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
