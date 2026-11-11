
# -*- coding: utf-8 -*-
"""LC79 prediction engine v4 — features liên tục, meta-learning, drift detection, skip thông minh."""
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


def _fresh(age, soft=100, mid=300, hard=500):
    """Freshness decay: pattern càng cũ càng giảm weight."""
    if age > hard: return 0.0
    if age > mid: return 0.4
    if age > soft: return 0.7
    return 1.0


# ============ 8 MODULES ĐA DẠNG CẦU ============

class TransitionModule:
    """Variable-order Markov 1+2 step, freshness decay."""
    name = "transition"
    def __init__(self):
        self.one = {}; self.two = {}; self.idx = 0
    @staticmethod
    def bucket(run): return min(8, max(1, int(run)))
    @staticmethod
    def current(hist):
        if not hist: return None, 0
        v = hist[-1]; n = 1
        for x in reversed(hist[:-1]):
            if x != v: break
            n += 1
        return v, n
    def update(self, hist, y):
        prev, run = self.current(hist)
        if prev is None: return
        k = (int(prev), self.bucket(run))
        cell = self.one.setdefault(k, [2.0, 2.0, self.idx])
        cell[int(y)] += 1.0; cell[2] = self.idx
        if len(hist) >= 2:
            k2 = (int(hist[-2]), int(hist[-1]))
            cell = self.two.setdefault(k2, [2.0, 2.0, self.idx])
            cell[int(y)] += 1.0; cell[2] = self.idx
        self.idx += 1
    def predict(self, hist):
        prev, run = self.current(hist)
        if prev is None: return 0.5, 0.0, {}
        a = self.one.get((int(prev), self.bucket(run)), [2.0, 2.0, 0])
        b = self.two.get((int(hist[-2]), int(prev)), [2.0, 2.0, 0]) if len(hist) >= 2 else [2.0, 2.0, 0]
        fa = _fresh(self.idx - a[2]); fb = _fresh(self.idx - b[2])
        n1 = max(0.0, sum(a[:2]) - 4.0) * fa
        n2 = max(0.0, sum(b[:2]) - 4.0) * fb
        p1 = a[1] / sum(a[:2]) if sum(a[:2]) > 0 else 0.5
        p2 = b[1] / sum(b[:2]) if sum(b[:2]) > 0 else 0.5
        w2 = n2 / (n1 + n2) if (n1 + n2) > 0 else 0.0
        p = p1 * (1 - w2) + p2 * w2
        conf = min(1.0, abs(p - 0.5) * 2) * min(1.0, (n1 + n2) / 20.0)
        return p, conf, {"prev": prev, "run": run, "p_1step": round(p1, 4), "p_2step": round(p2, 4),
                         "samples_1step": int(n1), "samples_2step": int(n2), "freshness_1": round(fa, 2), "freshness_2": round(fb, 2)}


class StreakLengthModule:
    """Survival curve + hazard rate, freshness."""
    name = "streak_length"
    def __init__(self):
        self.reaching = {}; self.ending = {}; self.idx = 0
    _run = staticmethod(TransitionModule.current)
    def update(self, hist, y):
        prev, run = self._run(hist)
        if prev is None: return
        for L in range(1, min(run, 15) + 1):
            cell = self.reaching.setdefault(L, [0, 0]); cell[0] += 1; cell[1] = self.idx
        if int(y) != int(prev):
            cell = self.ending.setdefault(min(run, 15), [0, 0]); cell[0] += 1; cell[1] = self.idx
        self.idx += 1
    def predict(self, hist):
        prev, run = self._run(hist)
        if prev is None: return 0.5, 0.0, {}
        survival = {}; hazards = {}
        for L in range(1, 16):
            reach = self.reaching.get(L, [0, 0])
            end = self.ending.get(L, [0, 0])
            f = _fresh(self.idx - max(reach[1], end[1]))
            hazard = (end[0] * f + 1.5) / (reach[0] * f + 3.0)
            hazards[L] = hazard
            survival[str(L)] = round(max(0.0, 1.0 - hazard), 4)
        L = min(run, 15); hazard = hazards[L]
        remaining = sum(math.prod(1.0 - hazards[j] for j in range(L, i + 1)) for i in range(L, 16))
        p = (1.0 - hazard) if prev else hazard
        conf = min(1.0, abs(p - 0.5) * 2) * min(1.0, self.reaching.get(L, [0])[0] / 20.0)
        return p, conf, {"run": run, "hazard_rate": round(hazard, 4),
                         "expected_remaining": round(remaining, 2), "survival_curve": survival}


class BreakModule:
    """Break-after-run: sau khi bệt gãy, phiên sau tiếp hay quay lại."""
    name = "break"
    def __init__(self):
        self.break_after_run = {}; self.idx = 0
    @staticmethod
    def _state(hist):
        if len(hist) < 2: return None
        prev = hist[-1]; before = hist[-2]
        run = 1
        for x in reversed(hist[:-2]):
            if x != before: break
            run += 1
        return prev, before, run
    def update(self, hist, y):
        st = self._state(hist)
        if st:
            prev, _, run = st
            cell = self.break_after_run.setdefault(min(run, 15), [1.0, 1.0, self.idx])
            cell[0 if int(y) == int(prev) else 1] += 1.0
            cell[2] = self.idx
        self.idx += 1
    def predict(self, hist):
        st = self._state(hist)
        if not st: return 0.5, 0.0, {}
        prev, _, run = st
        c = self.break_after_run.get(min(run, 15), [1.0, 1.0, 0])
        f = _fresh(self.idx - c[2])
        keep_c = c[0] * f; break_c = c[1] * f
        keep = keep_c / (keep_c + break_c) if (keep_c + break_c) > 0 else 0.5
        p = keep if prev else 1.0 - keep
        n = int((keep_c + break_c) - 2.0)
        return p, min(1.0, abs(keep - 0.5) * 2) * min(1.0, max(0, n) / 15.0), {
            "run_before": run, "prev": prev, "p_keep": round(keep, 4), "samples": max(0, n)}


class FrequencyModule:
    """EWMA tần suất với half-life 15 + drift vs all-time."""
    name = "frequency"
    def predict(self, hist):
        if not hist: return 0.5, 0.0, {}
        decay = 0.5 ** (1.0 / 15.0)
        a = b = 0.0
        for v in hist:
            a *= decay; b *= decay
            if v: a += 1.0
            else: b += 1.0
        ew = a / (a + b); all_p = sum(hist) / len(hist)
        drift = ew - all_p
        p = max(0.05, min(0.95, 0.5 + drift * min(1.0, len(hist) / 50.0)))
        return p, min(1.0, abs(p - 0.5) * 2), {
            "p_tai_ewma": round(ew, 4), "p_tai_all": round(all_p, 4), "drift": round(drift, 4), "samples": len(hist)}


class StreakEndModule:
    """Block-size hazard rate (2, 3, 4, 5+)."""
    name = "streak_end"
    def __init__(self):
        self.attempts = {}; self.ends = {}; self.idx = 0
    @staticmethod
    def _bucket(run): return 2 if run <= 2 else 3 if run == 3 else 4 if run == 4 else 5
    def update(self, hist, y):
        prev, run = TransitionModule.current(hist)
        if prev is None: return
        b = self._bucket(run)
        cell = self.attempts.setdefault(b, [0, 0]); cell[0] += 1; cell[1] = self.idx
        if int(y) != int(prev):
            cell = self.ends.setdefault(b, [0, 0]); cell[0] += 1; cell[1] = self.idx
        self.idx += 1
    def predict(self, hist):
        prev, run = TransitionModule.current(hist)
        if prev is None: return 0.5, 0.0, {}
        b = self._bucket(run)
        att = self.attempts.get(b, [0, 0]); end = self.ends.get(b, [0, 0])
        f = _fresh(self.idx - max(att[1], end[1]))
        haz = (end[0] * f + 1.0) / (att[0] * f + 2.0)
        p = (1.0 - haz) if prev else haz
        return p, min(1.0, abs(p - 0.5) * 2) * min(1.0, att[0] / 20.0), {
            "run": run, "block_size": b, "hazard_rate": round(haz, 4), "samples": att[0]}


class StabilityModule:
    """Độ ổn định qua 3 cửa sổ 10/20/50, có trend."""
    name = "stability"
    def predict(self, hist):
        if len(hist) < 3: return 0.5, 0.0, {}
        vals = {}
        for w in (10, 20, 50):
            z = hist[-w:]
            vals[w] = sum(z[i] == z[i-1] for i in range(1, len(z))) / max(1, len(z) - 1)
        weights = {w: 1.0 / w for w in vals}
        same = sum(vals[w] * weights[w] for w in vals) / sum(weights.values())
        trend = vals[10] - vals[50]
        prev = hist[-1]
        p = same if prev else 1.0 - same
        state = "stable" if same > 0.55 else "unstable" if same < 0.45 else "neutral"
        return p, min(1.0, abs(same - 0.5) * 2), {
            "p_same_10": round(vals[10], 4), "p_same_20": round(vals[20], 4),
            "p_same_50": round(vals[50], 4), "trend": round(trend, 4), "state": state}


class MomentumModule:
    """Momentum 3 timeframes + acceleration."""
    name = "momentum"
    def predict(self, hist):
        if len(hist) < 5: return 0.5, 0.0, {}
        p5 = sum(hist[-5:]) / len(hist[-5:])
        p10 = sum(hist[-10:]) / len(hist[-10:])
        p20 = sum(hist[-20:]) / len(hist[-20:])
        m1 = p5 - p10; m2 = p5 - p20; m3 = p10 - p20
        momentum = (m1 + m2 + m3) / 3.0
        accel = (p5 - p10) - (p10 - p20)
        p = max(0.05, min(0.95, 0.5 + momentum * (1.0 + 0.5 * accel)))
        return p, min(1.0, abs(momentum) * 4), {
            "p_short": round(p5, 4), "p_mid": round(p10, 4), "p_long": round(p20, 4),
            "momentum_avg": round(momentum, 4), "acceleration": round(accel, 4)}


class BaseRateModule:
    """Hierarchical Beta 2 tầng — anchor ổn định."""
    name = "base_rate"
    def __init__(self):
        self.ag = self.bg = self.ar = self.br = 1.0; self.n = 0
    def update(self, hist, y):
        self.ag *= 0.998; self.bg *= 0.998
        self.ar *= 0.99; self.br *= 0.99
        if y: self.ag += 1.0; self.ar += 1.0
        else: self.bg += 1.0; self.br += 1.0
        self.n += 1
    def predict(self, hist):
        pg = self.ag / (self.ag + self.bg)
        pr = self.ar / (self.ar + self.br)
        sur = abs(pr - pg)
        blend = 0.35 + 0.5 * min(1.0, sur / 0.15) if sur > 0.15 else 0.35
        p = pg * (1.0 - blend) + pr * blend
        return p, min(1.0, abs(p - 0.5) * 2), {
            "p_global": round(pg, 4), "p_recent": round(pr, 4),
            "surprise": round(sur, 4), "samples_global": self.n, "samples_recent": self.n}


# ============ FEATURES + META-LEARNER ============

class RegimeFeatures:
    """12 đặc trưng liên tục — KHÔNG dùng nhãn cứng."""
    DIM = 12
    NAMES = ("current_run", "p_same_10", "p_same_20", "p_same_50",
             "autocorr_1", "autocorr_2", "autocorr_3",
             "entropy_10", "entropy_20", "bias_20", "bias_50", "block_reg")

    def extract(self, hist):
        if len(hist) < 5: return [0.5] * 12
        current_run = 1
        for v in reversed(hist[:-1]):
            if v != hist[-1]: break
            current_run += 1

        def p_same(w):
            h = hist[-w:]
            return sum(h[i] == h[i-1] for i in range(1, len(h))) / max(1, len(h) - 1)

        def entropy(w):
            h = hist[-w:]
            p1 = sum(h) / len(h); p0 = 1.0 - p1
            e = 0.0
            for p in (p0, p1):
                if p > 0: e -= p * math.log2(p)
            return e

        def bias(w):
            h = hist[-w:]
            return abs(sum(h) / len(h) - 0.5) * 2

        def autocorr(lag):
            if len(hist) <= lag: return 0.0
            n = len(hist); mean = sum(hist) / n
            var = sum((x - mean) ** 2 for x in hist) / n
            if var < 1e-9: return 0.0
            cov = sum((hist[i] - mean) * (hist[i - lag] - mean) for i in range(lag, n)) / (n - lag)
            return cov / var

        h30 = hist[-30:]
        blocks = []
        cur_v = h30[0]; cur_l = 1
        for v in h30[1:]:
            if v == cur_v: cur_l += 1
            else: blocks.append(cur_l); cur_v = v; cur_l = 1
        blocks.append(cur_l)
        if len(blocks) > 1:
            mean_b = sum(blocks) / len(blocks)
            var_b = sum((b - mean_b) ** 2 for b in blocks) / len(blocks)
            block_reg = math.sqrt(var_b) / max(1.0, mean_b)
        else:
            block_reg = 0.5

        return [
            min(1.0, current_run / 15.0),
            p_same(10), p_same(20), p_same(50),
            (autocorr(1) + 1.0) / 2.0,
            (autocorr(2) + 1.0) / 2.0,
            (autocorr(3) + 1.0) / 2.0,
            entropy(10), entropy(20),
            bias(20), bias(50),
            min(1.0, block_reg),
        ]


class MetaLearner:
    """Học module nào đáng tin trong vùng features nào.
    <5 obs/bin → weight 1.0 (fallback). >=5 obs → weight theo accuracy."""
    def __init__(self):
        self.bins = {}

    def _bin(self, features):
        run_bin = min(4, int(features[0] * 5))
        ps = features[2]
        ps_bin = 0 if ps < 0.4 else 1 if ps < 0.5 else 2 if ps < 0.6 else 3
        bias = features[10]
        bias_bin = 0 if bias < 0.1 else 1 if bias < 0.2 else 2
        return (run_bin, ps_bin, bias_bin)

    def update(self, features, module_preds, actual):
        b = self._bin(features)
        cell = self.bins.setdefault(b, {})
        for name, val in module_preds.items():
            p = val[0] if isinstance(val, (tuple, list)) else val
            c = cell.setdefault(name, [0, 0])
            c[0] += 1
            c[1] += int((1 if p >= 0.5 else 0) == actual)

    def weights(self, features, experts):
        b = self._bin(features)
        cell = self.bins.get(b, {})
        out = {}
        for name in experts:
            c = cell.get(name)
            if c and c[0] >= 5:
                acc = c[1] / c[0]
                out[name] = max(0.3, min(3.0, acc / 0.5))
            else:
                out[name] = 1.0
        return out


class RegimeClassifier:
    """Nhãn cầu cho ADMIN HIỂN THỊ. KHÔNG dùng cho weighting."""
    REGIMES = ("BET_2to4", "BET_5to7", "BET_8plus", "DAO_1_1", "DAO_2_2",
               "DAO_3_3", "CROSS_3", "BIAS_TAI", "BIAS_XIU", "RANDOM")
    def state(self, hist):
        if len(hist) < 10:
            return "WARMUP", 0.0, {"block_lengths": [], "dominant_pattern": "WARMUP", "pattern_strength": 0.0, "confidence": 0.0}
        h = hist[-30:]
        blocks = []
        for v in h:
            if not blocks or blocks[-1][0] != v: blocks.append([v, 1])
            else: blocks[-1][1] += 1
        lengths = [b[1] for b in blocks]; run = lengths[-1]
        same = sum(h[i] == h[i-1] for i in range(1, len(h))) / (len(h) - 1)
        bias = sum(h) / len(h)
        ac = {lag: sum(h[i] == h[i-lag] for i in range(lag, len(h))) / max(1, len(h) - lag) for lag in (1, 2, 3)}
        pair22 = len(lengths) >= 4 and all(x == 2 for x in lengths[-4:])
        triple33 = len(lengths) >= 3 and all(x == 3 for x in lengths[-3:])
        tail6 = len(h) >= 6 and all(h[i] != h[i-1] for i in range(len(h) - 5, len(h)))
        tail8 = len(h) >= 8 and all(h[i] != h[i-1] for i in range(len(h) - 7, len(h)))
        cross3 = tail6 and not tail8
        dao11 = len(lengths) >= 8 and all(x == 1 for x in lengths[-8:])
        if triple33: r = "DAO_3_3"; strength = 0.88
        elif pair22: r = "DAO_2_2"; strength = 0.84
        elif dao11: r = "DAO_1_1"; strength = 0.82
        elif cross3: r = "CROSS_3"; strength = 0.80
        elif run >= 8: r = "BET_8plus"; strength = min(1.0, run / 12.0)
        elif run >= 5: r = "BET_5to7"; strength = run / 7.0
        elif bias > 0.58: r = "BIAS_TAI"; strength = min(1.0, (bias - 0.5) * 3.0)
        elif bias < 0.42: r = "BIAS_XIU"; strength = min(1.0, (0.5 - bias) * 3.0)
        elif run >= 2: r = "BET_2to4"; strength = min(1.0, 0.45 + same * 0.5)
        else: r = "RANDOM"; strength = max(0.1, 1.0 - abs(same - 0.5) * 2.0)
        return r, float(max(0.0, min(1.0, strength))), {
            "block_lengths": lengths, "dominant_pattern": r,
            "pattern_strength": round(strength, 4), "confidence": round(strength, 4),
            "p_same": round(same, 4), "bias_tai": round(bias, 4),
            "autocorrelation_lag_1": round(ac[1], 4), "autocorrelation_lag_2": round(ac[2], 4),
            "autocorrelation_lag_3": round(ac[3], 4)}


# ============ ENGINE ============

class PredictionEngine:
    EXPERTS = ("transition", "streak_length", "break", "frequency",
               "streak_end", "stability", "momentum", "base_rate")

    def __init__(self, history=None, table_code=""):
        self.table_code = table_code
        self.config = dict(TABLE_CONFIG.get(table_code, {}))
        self.history = []
        if table_code:
            try: self.config = get_table_config(table_code)
            except Exception: pass
        self.transition = TransitionModule()
        self.streak_length = StreakLengthModule()
        self.break_module = BreakModule()
        self.frequency = FrequencyModule()
        self.streak_end = StreakEndModule()
        self.stability = StabilityModule()
        self.momentum = MomentumModule()
        self.base_rate = BaseRateModule()
        self.classifier = RegimeClassifier()
        self.features = RegimeFeatures()
        self.meta = MetaLearner()
        self.adaptive_weights = {n: 1.0 for n in self.EXPERTS}
        self.module_stats = {n: {"loss": 0.0, "n": 0} for n in self.EXPERTS}
        self.rolling_30 = {n: deque(maxlen=30) for n in self.EXPERTS}
        self.rolling_200 = {n: deque(maxlen=200) for n in self.EXPERTS}
        for v in list(history or []):
            self._update(1 if int(v) == 1 else 0, learn=True)

    def _modules(self):
        return {
            "transition": self.transition.predict(self.history),
            "streak_length": self.streak_length.predict(self.history),
            "break": self.break_module.predict(self.history),
            "frequency": self.frequency.predict(self.history),
            "streak_end": self.streak_end.predict(self.history),
            "stability": self.stability.predict(self.history),
            "momentum": self.momentum.predict(self.history),
            "base_rate": self.base_rate.predict(self.history),
        }

    def _update(self, y, learn=True):
        hist = self.history[:]
        if learn and len(hist) >= 30:
            preds = self._modules()
            features = self.features.extract(hist)
            # Meta học
            self.meta.update(features, {k: v for k, v in preds.items()}, y)
            # Rolling accuracy cho drift
            for name in self.EXPERTS:
                p = preds[name][0]
                predicted_side = 1 if p >= 0.5 else 0
                correct = int(predicted_side == y)
                self.rolling_30[name].append(correct)
                self.rolling_200[name].append(correct)
            # Adaptive weights (log-loss)
            losses = []
            for name, (p, _, _) in preds.items():
                loss = -(y * math.log(max(1e-6, p)) + (1 - y) * math.log(max(1e-6, 1 - p)))
                losses.append(loss)
                st = self.module_stats[name]; st["loss"] += loss; st["n"] += 1
            baseline = sum(losses) / len(losses) if losses else math.log(2)
            for name, loss in zip(self.EXPERTS, losses):
                st = self.module_stats[name]
                lr = 0.05 / math.sqrt(1.0 + st["n"] / 100.0)
                self.adaptive_weights[name] = max(0.2, min(3.0,
                    self.adaptive_weights[name] * math.exp(-lr * (loss - baseline))))
        self.transition.update(hist, y)
        self.streak_length.update(hist, y)
        self.break_module.update(hist, y)
        self.streak_end.update(hist, y)
        self.base_rate.update(hist, y)
        self.history.append(y)

    @staticmethod
    def _clamp(v, lo, hi): return max(lo, min(hi, v))

    def _regime_weights(self, regime):
        """Weights cũ cho admin hiển thị (không dùng trong predict)."""
        base = {n: 1.0 for n in self.EXPERTS}
        if regime.startswith("BET"):
            base.update({"transition": 1.8, "streak_length": 2.0, "streak_end": 1.8, "stability": 1.4, "break": 0.6})
        elif regime.startswith("DAO") or regime == "CROSS_3":
            base.update({"transition": 1.8, "break": 1.8, "streak_length": 0.5, "streak_end": 0.5, "momentum": 0.7})
        elif regime.startswith("BIAS"):
            base.update({"frequency": 2.0, "base_rate": 2.0, "momentum": 1.4})
        return base

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)
        regime, rc, rd = self.classifier.state(self.history)

        if n < 30:
            return {
                "side": None, "confidence": 50, "p_internal": 0.5,
                "regime": regime, "regime_conf": rc, "regime_details": rd,
                "modules": {}, "weights": {}, "adaptive_weights": dict(self.adaptive_weights),
                "skip": True, "reason": "warmup", "is_uncertain": True,
                "features": {}, "evidence_strength": 0.0, "drift_detected": [],
                "full": {"regime": regime, "regime_conf": rc, "regime_details": rd,
                         "modules": {}, "weights": {}, "p_internal": 0.5,
                         "explanation": "Chưa đủ dữ liệu (warmup <30 phiên)."},
            }

        mods = self._modules()
        features_list = self.features.extract(self.history)
        feature_dict = dict(zip(self.features.NAMES, [round(x, 4) for x in features_list]))
        meta_w = self.meta.weights(features_list, self.EXPERTS)
        cfg = self.config

        # Effective weights = meta × adaptive × (0.2 + 0.8 * module_conf)
        disabled = set(cfg.get("disabled_modules", []))
        effective = {}
        for name in self.EXPERTS:
            if name in disabled: continue
            p_m, c_m, _ = mods[name]
            w = meta_w[name] * self.adaptive_weights[name] * (0.2 + 0.8 * c_m)
            effective[name] = w

        # Drift detection: rolling_30 vs rolling_200
        drift = []
        for name in self.EXPERTS:
            if name in disabled: continue
            if len(self.rolling_30[name]) >= 10 and len(self.rolling_200[name]) >= 30:
                acc_30 = sum(self.rolling_30[name]) / len(self.rolling_30[name])
                acc_200 = sum(self.rolling_200[name]) / len(self.rolling_200[name])
                if acc_30 < acc_200 - 0.15:
                    effective[name] *= 0.5
                    drift.append(name)

        # Weighted average của module probabilities
        total_w = sum(effective.values())
        if total_w < 1e-9:
            p_raw = 0.5
        else:
            p_raw = sum(mods[name][0] * effective[name] for name in effective) / total_w

        # Evidence strength: dữ liệu + đồng thuận
        data_strength = min(1.0, n / 200.0)
        sides = [1 if mods[name][0] >= 0.5 else 0 for name in effective]
        ones = sum(sides)
        agreement = max(ones, len(sides) - ones) / max(1, len(sides))
        evidence = data_strength * agreement

        # Prior mạnh: evidence yếu → kéo p_raw về 0.5
        shrink = 0.4 + 0.6 * evidence
        shrink *= float(cfg.get("shrink_extra", 1.0))
        shrink = max(0.25, min(1.0, shrink))
        p = 0.5 + (p_raw - 0.5) * shrink
        p = self._clamp(p, 0.05, 0.95)

        edge = abs(p - 0.5) * 2
        side = "TAI" if p >= 0.5 else "XIU"

        # Skip logic — thận trọng
        skip_reason = None
        entropy_20 = features_list[8]
        if edge < 0.06:
            skip_reason = "low_edge"
        elif entropy_20 > 0.95 and edge < 0.15:
            skip_reason = "high_entropy"
        elif len(drift) >= 5 and edge < 0.12:
            skip_reason = "model_drift"

        confidence = 50 if skip_reason else max(
            int(cfg.get("min_confidence", 50)),
            min(85, int(round(50 + 35 * edge)))
        )

        # Module view cho admin
        regw = self._regime_weights(regime)
        mv = {k: {"p": round(float(mods[k][0]), 4), "conf": round(float(mods[k][1]), 4),
                  "weight": round(effective.get(k, 0.0), 4), "details": mods[k][2]}
              for k in self.EXPERTS}

        explanation = self.get_explanation({
            "regime": regime, "regime_conf": rc, "modules": mv, "side": side,
            "features": feature_dict, "evidence_strength": evidence,
            "drift_detected": drift,
        })

        full = {
            "regime": regime, "regime_conf": round(rc, 4), "regime_details": rd,
            "modules": mv, "weights": regw,
            "adaptive_weights": dict(self.adaptive_weights),
            "meta_weights": dict(meta_w),
            "p_internal": round(p, 6),
            "features": feature_dict,
            "evidence_strength": round(evidence, 4),
            "drift_detected": drift,
            "explanation": explanation,
        }

        return {
            "side": side,
            "confidence": confidence,
            "p_internal": p,
            "regime": regime, "regime_conf": rc, "regime_details": rd,
            "modules": mv, "weights": regw,
            "adaptive_weights": dict(self.adaptive_weights),
            "meta_weights": dict(meta_w),
            "features": feature_dict,
            "evidence_strength": round(evidence, 4),
            "drift_detected": drift,
            "skip": bool(skip_reason),
            "reason": skip_reason,
            "is_uncertain": bool(skip_reason) or regime == "RANDOM" or edge < 0.04,
            "full": full,
        }

    def predict_detail(self): return self.predict()

    def get_explanation(self, prediction_dict):
        ms = prediction_dict.get("modules", {})
        top = sorted(ms.items(), key=lambda x: x[1].get("weight", 0), reverse=True)[:3]
        labels = {"transition": "Chuyển tiếp", "streak_length": "Độ dài chuỗi",
                  "break": "Đảo chiều", "frequency": "Tần suất",
                  "streak_end": "Kết thúc chuỗi", "stability": "Ổn định",
                  "momentum": "Động lượng", "base_rate": "Tỷ lệ nền"}
        parts = [f"{labels.get(n, n)} {v.get('p', 0.5)*100:.1f}% (w={v.get('weight', 1):.2f})" for n, v in top]
        regime = prediction_dict.get("regime", "WARMUP")
        confidence = float(prediction_dict.get("regime_conf", 0) or 0) * 100
        side = prediction_dict.get("side") or "chờ"
        ev = prediction_dict.get("evidence_strength", 0)
        drift = prediction_dict.get("drift_detected", [])
        parts_str = "; ".join(parts) if parts else "không đủ dữ liệu"
        drift_str = f" | Drift: {', '.join(drift)}" if drift else ""
        return (f"Regime {regime} (conf {confidence:.0f}%) | Evidence {ev:.2f}{drift_str}. "
                f"Top module: {parts_str}. Kết luận: {side}.")

    def observe(self, result):
        self._update(1 if int(result) == 1 else 0, learn=True)

    def to_dict(self):
        return {
            "history": list(self.history),
            "adaptive_weights": dict(self.adaptive_weights),
            "module_stats": dict(self.module_stats),
            "table_code": self.table_code,
            "meta_bins": {f"{b[0]},{b[1]},{b[2]}": v for b, v in self.meta.bins.items()},
        }

    @classmethod
    def from_history(cls, history):
        return cls(history=history)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict): return cls()
        obj = cls(history=data.get("history", []), table_code=data.get("table_code", ""))
        obj.adaptive_weights.update({k: float(v) for k, v in data.get("adaptive_weights", {}).items() if k in obj.EXPERTS})
        obj.module_stats.update(data.get("module_stats", {}))
        for k_str, v in data.get("meta_bins", {}).items():
            try:
                k = tuple(int(x) for x in k_str.split(","))
                obj.meta.bins[k] = v
            except Exception:
                continue
        return obj


class Backtest:
    @staticmethod
    def run(history, warmup=30):
        eng = PredictionEngine()
        rows = []
        correct = skipped = 0
        by_regime = {}; by_conf = {}; by_side = {}
        by_module = {n: [0, 0] for n in PredictionEngine.EXPERTS}
        wins = losses = bestw = bestl = 0
        for y in history:
            pred = eng.predict()
            if len(eng.history) >= warmup:
                if pred.get("skip"):
                    skipped += 1
                else:
                    ok = pred.get("side") == ("TAI" if y else "XIU")
                    correct += int(ok)
                    wins = wins + 1 if ok else 0
                    losses = losses + 1 if not ok else 0
                    bestw = max(bestw, wins); bestl = max(bestl, losses)
                    for mn, mv in pred.get("modules", {}).items():
                        mok = (float(mv.get("p", 0.5)) >= 0.5) == bool(y)
                        by_module[mn][0] += 1; by_module[mn][1] += int(mok)
                    r = pred["regime"]; bucket = str((pred["confidence"] // 5) * 5)
                    by_regime.setdefault(r, [0, 0]); by_regime[r][0] += 1; by_regime[r][1] += int(ok)
                    by_conf.setdefault(bucket, [0, 0]); by_conf[bucket][0] += 1; by_conf[bucket][1] += int(ok)
                    side = pred.get("side") or "NAI"
                    by_side.setdefault(side, [0, 0]); by_side[side][0] += 1; by_side[side][1] += int(ok)
                    rows.append({"actual": y, "prediction": side, "correct": ok,
                                 "regime": r, "confidence": pred["confidence"]})
            eng.observe(y)
        total = len(rows)
        total_seen = total + skipped
        return {
            "total_predictions": total,
            "correct": correct,
            "accuracy": correct / total if total else 0.0,
            "skip_count": skipped,
            "skip_rate": skipped / total_seen if total_seen else 0.0,
            "by_regime": by_regime,
            "by_confidence_bucket": by_conf,
            "by_side": by_side,
            "by_module": {k: {"votes": v[0], "correct": v[1],
                              "accuracy": v[1] / v[0] if v[0] else 0.0} for k, v in by_module.items()},
            "streak_wins": bestw,
            "streak_losses": bestl,
            "timeline": rows,
        }


# ============ TABLE CONFIG + HELPERS (giữ nguyên) ============

TABLE_CONFIG = {
    "lc79_tx": {"disabled_modules": [], "shrink_extra": 1.0, "min_confidence": 50},
    "lc79_md5": {"disabled_modules": [], "shrink_extra": 1.0, "min_confidence": 50},
}

def get_table_config(table_code):
    c = db(); r = c.execute("SELECT config_json FROM table_configs WHERE table_code=?", (table_code,)).fetchone(); c.close()
    cfg = dict(TABLE_CONFIG.get(table_code, {}))
    if r:
        try: cfg.update(json.loads(r[0] or "{}"))
        except Exception: pass
    return cfg

def save_table_config(table_code, config):
    c = db()
    c.execute("INSERT INTO table_configs(table_code,config_json,updated_at) VALUES(?,?,?) ON CONFLICT(table_code) DO UPDATE SET config_json=excluded.config_json,updated_at=excluded.updated_at",
              (table_code, json.dumps(config), now_iso()))
    c.commit(); c.close()

def resolve_actual(table_code, sessions):
    c = db(); count = 0
    for x in sessions:
        sid = int(x.get("session_id", 0))
        actual = "TAI" if int(x.get("result", 0)) == 1 else "XIU"
        r = c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=? AND actual IS NULL", (table_code, sid)).fetchone()
        if not r: continue
        result = "win" if r["prediction"] == actual else "lose"
        detail = {}
        try: detail = json.loads(r["detail_json"] or "{}")
        except Exception: pass
        modules = detail.get("modules", {})
        top = max(modules.items(), key=lambda z: z[1].get("weight", 0)) if modules else (None, {})
        c.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?",
                  (actual, result, now_iso(), r["id"]))
        c.execute("INSERT OR IGNORE INTO prediction_resolutions(table_code,session_id,prediction,actual,result,regime,regime_conf,confidence,top_module,top_module_p,module_votes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (table_code, sid, r["prediction"], actual, result,
                   detail.get("regime"), detail.get("regime_conf"), r["confidence"],
                   top[0], top[1].get("p"), json.dumps(modules)))
        count += 1
    c.commit(); c.close(); return count

def accuracy_detail(table_code, days=7):
    c = db()
    r = c.execute("SELECT COUNT(*) total,SUM(result='win') wins,SUM(result='lose') losses FROM predictions WHERE table_code=? AND result IS NOT NULL AND confidence > 51 AND resolved_at>=datetime('now',?)",
                  (table_code, f"-{int(days)} days")).fetchone()
    c.close()
    total = r["total"] or 0; wins = r["wins"] or 0
    return {"total": total, "wins": wins, "losses": r["losses"] or 0,
            "accuracy": wins / total if total else 0.0}

def get_broadcast():
    c = db(); r = c.execute("SELECT message FROM broadcasts WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone(); c.close()
    return r[0] if r else ""

def set_worker_control(key, value):
    c = db()
    c.execute("INSERT INTO worker_control(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
              (key, str(value), now_iso()))
    c.commit(); c.close()

def get_worker_control(key, default=None):
    c = db(); r = c.execute("SELECT value FROM worker_control WHERE key=?", (key,)).fetchone(); c.close()
    return r[0] if r else default


# ============ PERSISTENCE (giữ nguyên) ============

def load_engine(table_code):
    conn = db()
    row = conn.execute("SELECT history_json FROM table_states WHERE table_code=?", (table_code,)).fetchone()
    conn.close()
    try: state = json.loads(row["history_json"] or '{"history":[]}') if row else {"history": []}
    except (ValueError, TypeError): state = {"history": []}
    obj = PredictionEngine.from_dict(state)
    obj.table_code = table_code
    obj.config = get_table_config(table_code)
    return obj

def save_engine(table_code, engine):
    conn = db()
    conn.execute("UPDATE table_states SET history_json=?,updated_at=? WHERE table_code=?",
                 (json.dumps(engine.to_dict(), separators=(",", ":")), now_iso(), table_code))
    conn.commit(); conn.close()

def load_last_seen(table_code):
    conn = db()
    row = conn.execute("SELECT last_seen_id FROM table_states WHERE table_code=?", (table_code,)).fetchone()
    conn.close()
    return int(row[0]) if row else 0

def save_last_seen(table_code, session_id):
    conn = db()
    conn.execute("UPDATE table_states SET last_seen_id=?,updated_at=? WHERE table_code=?",
                 (int(session_id), now_iso(), table_code))
    conn.commit(); conn.close()

def save_worker_state(table_code, engine, session_id):
    conn = db()
    conn.execute("UPDATE table_states SET history_json=?,last_seen_id=?,updated_at=? WHERE table_code=?",
                 (json.dumps(engine.to_dict(), separators=(",", ":")), int(session_id), now_iso(), table_code))
    conn.commit(); conn.close()

def mark_poll_ok(table_code):
    conn = db()
    conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=NULL,updated_at=? WHERE table_code=?",
                 (now_iso(), now_iso(), table_code))
    conn.commit(); conn.close()

def mark_poll_error(table_code, error):
    conn = db()
    conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?",
                 (now_iso(), str(error)[:500], now_iso(), table_code))
    conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    """Chỉ tính predictions confidence > 51 (loại skip)."""
    conn = db()
    rows = conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IS NOT NULL AND confidence > 51 ORDER BY session_id DESC LIMIT ?",
                        (table_code, int(limit))).fetchall()
    conn.close()
    return (sum(r[0] == "win" for r in rows) / len(rows)) if rows else 0.5

# === END engine.py ===
