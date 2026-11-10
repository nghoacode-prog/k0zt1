import math
import json
import sqlite3
import os
import time
from collections import defaultdict

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/var/data/app.db")

# ─── DB ───────────────────────────────────────────────────────────────────────

def db():
    # Ensure the parent directory exists on Render before opening SQLite.
    db_dir = os.path.dirname(os.path.abspath(DATABASE_PATH))
    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def init_db():
    conn = db()
    conn.executescript("""
CREATE TABLE IF NOT EXISTS tables_ (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    game_code TEXT NOT NULL,
    game_name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS table_states (
    table_code TEXT PRIMARY KEY REFERENCES tables_(code),
    history_json TEXT,
    last_seen_id INTEGER DEFAULT 0,
    last_poll_at TEXT,
    last_poll_error TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_code TEXT NOT NULL,
    session_id INTEGER NOT NULL,
    prediction TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    actual TEXT,
    result TEXT,
    resolved_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pred_unique ON predictions(table_code, session_id);
CREATE INDEX IF NOT EXISTS idx_pred_table ON predictions(table_code, session_id DESC);

CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    note TEXT,
    is_active INTEGER DEFAULT 1,
    expires_at TEXT,
    days INTEGER DEFAULT 7,
    max_devices INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    activated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS api_key_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL REFERENCES api_keys(key),
    device_id TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    browser TEXT,
    os TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    released_at TEXT,
    released_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_key ON api_key_devices(key, released_at);

CREATE TABLE IF NOT EXISTS activation_codes (
    code TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    days INTEGER NOT NULL,
    max_uses INTEGER DEFAULT -1,
    used_count INTEGER DEFAULT 0,
    expires_at TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS activation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT, code TEXT, success INTEGER,
    ip TEXT, user_agent TEXT, reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user TEXT, action TEXT, target TEXT,
    detail_json TEXT, ip TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS engine_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_code TEXT NOT NULL,
    reason TEXT NOT NULL,
    accuracy_before REAL,
    sessions_at_reset INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT, window TEXT, count INTEGER,
    PRIMARY KEY (key, window)
);
""")
    conn.commit()
    conn.close()

def seed_tables():
    conn = db()
    conn.execute("""
INSERT OR IGNORE INTO tables_ VALUES
  ('lc79_tx',  'Bàn Hũ',  'lc79', 'LC79', 'https://wtx.tele68.com/v1/tx/sessions', 1, 1)
""")
    conn.execute("""
INSERT OR IGNORE INTO tables_ VALUES
  ('lc79_md5', 'Bàn MD5', 'lc79', 'LC79', 'https://wtxmd52.tele68.com/v1/txmd5/sessions', 1, 2)
""")
    conn.commit()
    conn.close()

# ─── PARSER ───────────────────────────────────────────────────────────────────

def parse_upstream(raw):
    if not isinstance(raw, dict):
        return None
    items = raw.get("list")
    if not isinstance(items, list) or not items:
        return None

    sessions = []
    for item in items:
        try:
            sid = int(item.get("id", 0))
        except (ValueError, TypeError):
            continue
        if sid <= 0:
            continue

        rs = str(item.get("resultTruyenThong", "")).strip().upper()
        if rs == "TAI":
            result = 1
        elif rs == "XIU":
            result = 0
        else:
            continue

        dices = item.get("dices")
        if not isinstance(dices, list) or len(dices) != 3:
            dices = None

        point = item.get("point")
        if not isinstance(point, int) or not (3 <= point <= 18):
            point = sum(dices) if dices else None

        sessions.append({
            "session_id": sid,
            "result": result,
            "dices": dices,
            "tong": point,
        })

    sessions.sort(key=lambda s: s["session_id"])
    if not sessions:
        return None
    return {"sessions": sessions, "latest_id": sessions[-1]["session_id"]}

# ─── EXPERTS ──────────────────────────────────────────────────────────────────

class HierarchicalNgram:
    def __init__(self, max_k=10):
        self.max_k = max_k
        self.tables = {}  # k -> {ctx: [tai+1, xiu+1]}
        self.global_ = [1, 1]

    def update(self, history, y):
        if y == 1:
            self.global_[0] += 1
        else:
            self.global_[1] += 1

        for k in range(1, min(self.max_k, len(history)) + 1):
            ctx = tuple(history[-k:])
            if k not in self.tables:
                self.tables[k] = {}
            if ctx not in self.tables[k]:
                self.tables[k][ctx] = [1, 1]
            if y == 1:
                self.tables[k][ctx][0] += 1
            else:
                self.tables[k][ctx][1] += 1

    def predict(self, history):
        a, b = self.global_[0], self.global_[1]
        for k in range(1, min(self.max_k, len(history)) + 1):
            ctx = tuple(history[-k:])
            cell = self.tables.get(k, {}).get(ctx)
            if not cell:
                break
            a, b = cell
        total = a + b
        return a / total, total

    def to_dict(self):
        return {
            "global_": self.global_,
            "tables": {str(k): {str(list(ctx)): v for ctx, v in t.items()} for k, t in self.tables.items()}
        }

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.global_ = d.get("global_", [1, 1])
        for k_str, t in d.get("tables", {}).items():
            k = int(k_str)
            obj.tables[k] = {}
            for ctx_str, v in t.items():
                import ast
                ctx = tuple(ast.literal_eval(ctx_str))
                obj.tables[k][ctx] = v
        return obj


class StreakExpert:
    def __init__(self, max_len=10):
        self.max_len = max_len
        self.counts = {}  # (side, run_len) -> [continue+1, break+1]

    def _current_run(self, history):
        if not history:
            return None, 0
        side = history[-1]
        run = 1
        for i in range(len(history) - 2, -1, -1):
            if history[i] == side:
                run += 1
            else:
                break
        return side, min(run, self.max_len)

    def update(self, history, y):
        if not history:
            return
        side, run_len = self._current_run(history)
        if side is None:
            return
        key = (side, run_len)
        if key not in self.counts:
            self.counts[key] = [1, 1]
        if y == side:
            self.counts[key][0] += 1
        else:
            self.counts[key][1] += 1

    def predict(self, history):
        if not history:
            return 0.5, 1
        side, run_len = self._current_run(history)
        if side is None:
            return 0.5, 1
        c, br = self.counts.get((side, run_len), [1, 1])
        p_continue = c / (c + br)
        if side == 1:
            p_tai = p_continue
        else:
            p_tai = 1 - p_continue
        return p_tai, c + br

    def to_dict(self):
        return {"counts": {str(k): v for k, v in self.counts.items()}}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        import ast
        for k_str, v in d.get("counts", {}).items():
            k = ast.literal_eval(k_str)
            obj.counts[tuple(k)] = v
        return obj


class EMAExpert:
    def __init__(self, half_life=50):
        self.decay = 0.5 ** (1 / half_life)
        self.alpha = 1 - self.decay
        self.ema = 0.5

    def update(self, history, y):
        self.ema = self.alpha * y + (1 - self.alpha) * self.ema

    def predict(self, history):
        return self.ema, 1 / self.alpha

    def reset(self):
        self.ema = 0.5

    def to_dict(self):
        return {"ema": self.ema, "alpha": self.alpha, "decay": self.decay}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.ema = d.get("ema", 0.5)
        obj.alpha = d.get("alpha", obj.alpha)
        obj.decay = d.get("decay", obj.decay)
        return obj


class MarkovExpert:
    def __init__(self, order=1):
        self.order = order
        self.counts = {}  # prev_result -> [tai+1, xiu+1]

    def update(self, history, y):
        if not history:
            return
        prev = history[-1]
        if prev not in self.counts:
            self.counts[prev] = [1, 1]
        if y == 1:
            self.counts[prev][0] += 1
        else:
            self.counts[prev][1] += 1

    def predict(self, history):
        if not history:
            return 0.5, 1
        prev = history[-1]
        c = self.counts.get(prev, [1, 1])
        return c[0] / (c[0] + c[1]), c[0] + c[1]

    def to_dict(self):
        return {"counts": {str(k): v for k, v in self.counts.items()}}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        for k_str, v in d.get("counts", {}).items():
            obj.counts[int(k_str)] = v
        return obj


class CycleExpert:
    def __init__(self, periods=None, min_match=0.55):
        self.periods = periods or list(range(2, 9))
        self.min_match = min_match

    def update(self, history, y):
        pass

    def predict(self, history):
        best = None
        for p in self.periods:
            if len(history) < 3 * p:
                continue
            window = min(len(history), 5 * p)
            seg = history[-window:]
            matches = sum(1 for i in range(p, len(seg)) if seg[i] == seg[i - p])
            total = len(seg) - p
            if total <= 0:
                continue
            rate = matches / total
            if best is None or rate > best[0]:
                best = (rate, p, history[-p])

        if best is None:
            return 0.5, 1
        rate, p, pred_from_cycle = best
        if rate < self.min_match:
            return 0.5, 1
        strength = (rate - 0.5) * 2
        p_tai = 0.5 + strength * (pred_from_cycle - 0.5) * 1.5
        p_tai = max(0.01, min(0.99, p_tai))
        return p_tai, p * strength

    def to_dict(self):
        return {}

    @classmethod
    def from_dict(cls, d):
        return cls()


# ─── ENSEMBLE ─────────────────────────────────────────────────────────────────

class LogOddsEnsemble:
    def __init__(self, eta_base=0.10):
        self.eta_base = eta_base
        self.weights = {}
        self.sessions = 0

    def predict(self, experts):
        num = 0.0
        den = 0.0
        for name, (p, prec) in experts.items():
            w = self.weights.get(name, 1.0)
            p = max(0.01, min(0.99, p))
            logit = math.log(p / (1 - p))
            num += w * prec * logit
            den += w * prec
        if den == 0:
            return 0.5
        p_final = 1 / (1 + math.exp(-num / den))
        return p_final

    def update(self, experts, y):
        self.sessions += 1
        eta = self.eta_base / math.sqrt(max(1, self.sessions / 100))
        for name, (p, prec) in experts.items():
            self.weights.setdefault(name, 1.0)
            loss = (p - y) ** 2
            self.weights[name] *= math.exp(-eta * loss)
        # normalize
        total = sum(self.weights.values())
        if total > 0:
            for name in self.weights:
                self.weights[name] /= total / len(self.weights)

    def to_dict(self):
        return {"weights": self.weights, "sessions": self.sessions}

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.weights = d.get("weights", {})
        obj.sessions = d.get("sessions", 0)
        return obj


# ─── ENGINE ───────────────────────────────────────────────────────────────────

class Engine:
    def __init__(self):
        self.history = []
        self.ngram = HierarchicalNgram(max_k=10)
        self.streak = StreakExpert(max_len=10)
        self.ema = EMAExpert(half_life=50)
        self.markov = MarkovExpert(order=1)
        self.cycle = CycleExpert()
        self.ensemble = LogOddsEnsemble(eta_base=0.10)
        self._last_experts = None
        self._ll_buffer = []  # log-likelihood buffer for CUSUM R6

    def _compute_experts(self, hist):
        return {
            "ngram": self.ngram.predict(hist),
            "streak": self.streak.predict(hist),
            "ema": self.ema.predict(hist),
            "markov": self.markov.predict(hist),
            "cycle": self.cycle.predict(hist),
        }

    def _predict_on(self, hist):
        if len(hist) < 5:
            return 0.5
        experts = self._compute_experts(hist)
        return self.ensemble.predict(experts)

    def recent_accuracy(self, n=100):
        # Tính accuracy từ history (không có ground truth riêng → dùng predictions DB nếu cần)
        # Đây là stub — accuracy thực tính từ DB trong worker
        return 0.5

    def predict(self):
        if len(self.history) < 10:
            return {"side": None, "confidence": None, "p_internal": None}

        effective = self.history[-2000:]
        experts = self._compute_experts(effective)
        p_raw = self.ensemble.predict(experts)
        self._last_experts = experts

        # R2 — Multi-timeframe
        p_short = self._predict_on(self.history[-100:])
        p_long = self._predict_on(self.history[-500:])
        if (p_short - 0.5) * (p_long - 0.5) >= 0:
            p_raw = p_short
        else:
            p_raw = 0.5

        # R3 — Diversity
        n_tai = sum(1 for p, _ in experts.values() if p >= 0.5)
        acc_100 = self._db_accuracy(100)
        if (n_tai >= 4 or n_tai <= 1) and acc_100 < 0.50:
            p_raw = 1 - p_raw
            p_raw = 0.5 + (p_raw - 0.5) * 0.3

        # R7 — Confidence 58..72
        if p_raw >= 0.5:
            side, edge = "TAI", (p_raw - 0.5) * 2
        else:
            side, edge = "XIU", (0.5 - p_raw) * 2

        sessions = len(self.history)
        if sessions < 100:
            edge = min(edge, 0.3)
        elif sessions < 500:
            edge = min(edge, 0.5)
        elif sessions < 2000:
            edge = min(edge, 0.7)

        conf = round(58 + edge * 14)
        conf = max(58, min(72, conf))

        return {"side": side, "confidence": conf, "p_internal": p_raw}

    def _db_accuracy(self, n):
        # Placeholder — engine không có table_code context
        # Worker sẽ patch này sau khi load
        return getattr(self, "_cached_accuracy", 0.5)

    def observe(self, result):
        y = 1 if result == 1 else 0

        # Update experts trước khi append history
        hist_before = list(self.history)
        self.ngram.update(hist_before, y)
        self.streak.update(hist_before, y)
        self.ema.update(hist_before, y)
        self.markov.update(hist_before, y)
        # cycle không cần update

        # Ensemble update
        if self._last_experts:
            self.ensemble.update(self._last_experts, y)
        self._last_experts = None

        self.history.append(y)
        n = len(self.history)

        # R6 — CUSUM regime detector
        p = self.ema.ema
        p = max(0.01, min(0.99, p))
        ll = math.log(p if y == 1 else (1 - p))
        self._ll_buffer.append(ll)
        if len(self._ll_buffer) > 30:
            self._ll_buffer.pop(0)
        if len(self._ll_buffer) >= 30:
            old_mean = sum(self._ll_buffer[:15]) / 15
            new_mean = sum(self._ll_buffer[15:]) / 15
            if old_mean - new_mean > 2.0:
                self.ema.reset()
                for k in list(self.ngram.tables.keys()):
                    if k >= 5:
                        del self.ngram.tables[k]

        # R5 — Watchdog mỗi 50 phiên
        if n % 50 == 0:
            self._watchdog(n)

    def _watchdog(self, n):
        acc = self._db_accuracy(100)
        if acc < 0.45:
            for name in self.ensemble.weights:
                self.ensemble.weights[name] = 0.2
            for k in list(self.ngram.tables.keys()):
                if k >= 5:
                    del self.ngram.tables[k]
        elif acc < 0.48:
            for name in self.ensemble.weights:
                self.ensemble.weights[name] *= 0.8

    def to_dict(self):
        return {
            "history": self.history,
            "ngram": self.ngram.to_dict(),
            "streak": self.streak.to_dict(),
            "ema": self.ema.to_dict(),
            "markov": self.markov.to_dict(),
            "ensemble": self.ensemble.to_dict(),
        }

    @classmethod
    def from_dict(cls, d):
        e = cls()
        e.history = d.get("history", [])
        if "ngram" in d:
            e.ngram = HierarchicalNgram.from_dict(d["ngram"])
        if "streak" in d:
            e.streak = StreakExpert.from_dict(d["streak"])
        if "ema" in d:
            e.ema = EMAExpert.from_dict(d["ema"])
        if "markov" in d:
            e.markov = MarkovExpert.from_dict(d["markov"])
        if "ensemble" in d:
            e.ensemble = LogOddsEnsemble.from_dict(d["ensemble"])
        return e


# ─── ENGINE PERSISTENCE ───────────────────────────────────────────────────────

def load_engine(table_code):
    conn = db()
    row = conn.execute(
        "SELECT history_json FROM table_states WHERE table_code=?", (table_code,)
    ).fetchone()
    conn.close()
    if not row or not row["history_json"]:
        return Engine()
    try:
        d = json.loads(row["history_json"])
        return Engine.from_dict(d)
    except Exception:
        return Engine()

def save_engine(table_code, engine):
    conn = db()
    d = json.dumps(engine.to_dict(), separators=(",", ":"))
    conn.execute("""
INSERT INTO table_states (table_code, history_json, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(table_code) DO UPDATE SET history_json=excluded.history_json, updated_at=excluded.updated_at
""", (table_code, d, now_iso()))
    conn.commit()
    conn.close()

def load_last_seen(table_code):
    conn = db()
    row = conn.execute(
        "SELECT last_seen_id FROM table_states WHERE table_code=?", (table_code,)
    ).fetchone()
    conn.close()
    if not row:
        return 0
    return row["last_seen_id"] or 0

def save_last_seen(table_code, last_id):
    conn = db()
    conn.execute("""
INSERT INTO table_states (table_code, last_seen_id, last_poll_at, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(table_code) DO UPDATE SET
    last_seen_id=excluded.last_seen_id,
    last_poll_at=excluded.last_poll_at,
    updated_at=excluded.updated_at
""", (table_code, last_id, now_iso(), now_iso()))
    conn.commit()
    conn.close()

def mark_poll_ok(table_code):
    conn = db()
    conn.execute("""
INSERT INTO table_states (table_code, last_poll_at, last_poll_error, updated_at)
VALUES (?, ?, NULL, ?)
ON CONFLICT(table_code) DO UPDATE SET
    last_poll_at=excluded.last_poll_at,
    last_poll_error=NULL,
    updated_at=excluded.updated_at
""", (table_code, now_iso(), now_iso()))
    conn.commit()
    conn.close()

def mark_poll_error(table_code, error):
    conn = db()
    conn.execute("""
INSERT INTO table_states (table_code, last_poll_error, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(table_code) DO UPDATE SET
    last_poll_error=excluded.last_poll_error,
    updated_at=excluded.updated_at
""", (table_code, error[:500], now_iso()))
    conn.commit()
    conn.close()
