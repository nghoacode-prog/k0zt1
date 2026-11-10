# -*- coding: utf-8 -*-
"""LC79 deterministic prediction engine and SQLite persistence."""
from __future__ import annotations
import ast
import json
import math
import os
import sqlite3
import time
from collections import defaultdict, deque
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
    for i, (code, meta) in enumerate(TABLES.items(), 1):
        conn.execute("INSERT OR IGNORE INTO tables_(code,name,game_code,game_name,upstream_url,is_active,sort_order) VALUES(?,?,?,?,?,1,?)",
                     (code, meta["name"], "lc79", "LC79", meta["url"], i))
        conn.execute("INSERT OR IGNORE INTO table_states(table_code) VALUES(?)", (code,))
    conn.commit()
    conn.close()

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

# ---------------------------------------------------------------------------
# Tám module thống kê chuyên biệt
# ---------------------------------------------------------------------------
class TransitionModule:
    name = "transition"

    def __init__(self):
        self.counts = {}

    @staticmethod
    def _bucket(run):
        if run <= 1: return 1
        if run <= 3: return run
        return 5

    def _current(self, hist):
        if not hist:
            return None, 0
        prev = hist[-1]
        run = 1
        for v in reversed(hist[:-1]):
            if v != prev: break
            run += 1
        return prev, run

    def update(self, hist, y):
        prev, run = self._current(hist)
        if prev is None: return
        y = 1 if int(y) == 1 else 0
        key = (prev, self._bucket(run))
        cell = self.counts.setdefault(key, [1.0, 1.0])
        cell[y] += 1.0

    def predict(self, hist):
        prev, run = self._current(hist)
        if prev is None:
            return 0.5, 0.0, {}
        key = (prev, self._bucket(run))
        cell = self.counts.get(key, [1.0, 1.0])
        total = cell[0] + cell[1]
        p = cell[1] / total
        edge = abs(p - 0.5) * 2
        conf = edge * min(1.0, total / 20.0)
        return p, conf, {"prev": prev, "run": run, "samples": int(total)}


class StreakLengthModule:
    name = "streak_length"

    def __init__(self):
        self.reaching = {}
        self.ending = {}

    @staticmethod
    def _run(hist):
        if not hist: return None, 0
        prev = hist[-1]
        run = 1
        for v in reversed(hist[:-1]):
            if v != prev: break
            run += 1
        return prev, run

    def update(self, hist, y):
        prev, run = self._run(hist)
        if prev is None: return
        y = 1 if int(y) == 1 else 0
        bucket = min(run, 10)
        self.reaching[bucket] = self.reaching.get(bucket, 0.0) + 1.0
        if y != prev:
            self.ending[bucket] = self.ending.get(bucket, 0.0) + 1.0

    def predict(self, hist):
        prev, run = self._run(hist)
        if prev is None or run < 2:
            return 0.5, 0.0, {}
        bucket = min(run, 10)
        reached = self.reaching.get(bucket, 1.0)
        ended = self.ending.get(bucket, 0.5)
        p_end = ended / reached
        p_continue = 1.0 - p_end
        p_tai = p_continue if prev == 1 else 1.0 - p_continue
        edge = abs(p_continue - 0.5) * 2
        conf = edge * min(1.0, reached / 15.0)
        return p_tai, conf, {"run": run, "p_end": round(p_end, 3),
                             "reached": int(reached), "ended": int(ended)}


class BreakModule:
    name = "break"

    def __init__(self):
        self.counts = [1.0, 1.0]

    def _state(self, hist):
        if len(hist) < 3:
            return None
        prev, before = hist[-1], hist[-2]
        if prev == before:
            return None
        run_before = 1
        for v in reversed(hist[:-2]):
            if v != before: break
            run_before += 1
        if run_before < 2:
            return None
        return prev, before, run_before

    def update(self, hist, y):
        state = self._state(hist)
        if state is None: return
        prev = state[0]
        y = 1 if int(y) == 1 else 0
        if y == prev:
            self.counts[0] += 1.0
        else:
            self.counts[1] += 1.0

    def predict(self, hist):
        state = self._state(hist)
        if state is None:
            return 0.5, 0.0, {}
        prev = state[0]
        total = self.counts[0] + self.counts[1]
        p_keep = self.counts[0] / total
        p_tai = p_keep if prev == 1 else 1.0 - p_keep
        edge = abs(p_keep - 0.5) * 2
        conf = edge * min(1.0, total / 15.0)
        return p_tai, conf, {"p_keep": round(p_keep, 3), "samples": int(total)}


class FrequencyModule:
    name = "frequency"

    def __init__(self, windows=(10, 20, 50)):
        self.windows = windows

    def update(self, hist, y):
        return None

    def predict(self, hist):
        if len(hist) < 10:
            return 0.5, 0.0, {}
        p_num = 0.0
        w_sum = 0.0
        details = {}
        for w in self.windows:
            if len(hist) < w: continue
            recent = hist[-w:]
            p = sum(recent) / w
            weight = 1.0 / w
            p_num += p * weight
            w_sum += weight
            details[f"p_tai_{w}"] = round(p, 3)
        if w_sum < 1e-6:
            return 0.5, 0.0, {}
        p = p_num / w_sum
        edge = abs(p - 0.5) * 2
        return p, edge, details


class StreakEndModule:
    name = "streak_end"

    def __init__(self):
        self.attempts = {}
        self.ends = {}

    @staticmethod
    def _run(hist):
        if not hist: return None, 0
        prev = hist[-1]
        run = 1
        for v in reversed(hist[:-1]):
            if v != prev: break
            run += 1
        return prev, run

    def update(self, hist, y):
        prev, run = self._run(hist)
        if prev is None: return
        y = 1 if int(y) == 1 else 0
        bucket = min(run, 8)
        self.attempts[bucket] = self.attempts.get(bucket, 0.0) + 1.0
        if y != prev:
            self.ends[bucket] = self.ends.get(bucket, 0.0) + 1.0

    def predict(self, hist):
        prev, run = self._run(hist)
        if prev is None:
            return 0.5, 0.0, {}
        bucket = min(run, 8)
        attempts = self.attempts.get(bucket, 1.0)
        ends = self.ends.get(bucket, 0.5)
        p_end = ends / attempts
        p_continue = 1.0 - p_end
        p_tai = p_continue if prev == 1 else 1.0 - p_continue
        edge = abs(p_continue - 0.5) * 2
        conf = edge * min(1.0, attempts / 15.0)
        return p_tai, conf, {"run": run, "p_end": round(p_end, 3),
                             "samples": int(attempts)}


class StabilityModule:
    name = "stability"

    def update(self, hist, y):
        return None

    def predict(self, hist):
        if len(hist) < 10:
            return 0.5, 0.0, {}
        w = hist[-10:]
        p_same = sum(1 for i in range(1, len(w)) if w[i] == w[i-1]) / (len(w) - 1)
        prev = hist[-1]
        if p_same > 0.55:
            p_tai = 0.62 if prev == 1 else 0.38
            conf = min(1.0, (p_same - 0.5) * 3)
        elif p_same < 0.45:
            p_tai = 0.38 if prev == 1 else 0.62
            conf = min(1.0, (0.5 - p_same) * 3)
        else:
            return 0.5, 0.0, {"p_same_10": round(p_same, 3), "state": "neutral"}
        return p_tai, conf, {"p_same_10": round(p_same, 3)}


class MomentumModule:
    name = "momentum"

    def update(self, hist, y):
        return None

    def predict(self, hist):
        if len(hist) < 10:
            return 0.5, 0.0, {}
        short = hist[-5:]
        long = hist[-20:] if len(hist) >= 20 else hist
        p_short = sum(short) / len(short)
        p_long = sum(long) / len(long)
        diff = p_short - p_long
        p = max(0.05, min(0.95, 0.5 + diff))
        edge = abs(diff) * 2
        return p, edge, {"p_short": round(p_short, 3),
                         "p_long": round(p_long, 3), "diff": round(diff, 3)}


class BaseRateModule:
    name = "base_rate"

    def __init__(self, decay=0.995):
        self.tai = 1.0
        self.xiu = 1.0
        self.decay = float(decay)

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.tai *= self.decay
        self.xiu *= self.decay
        if y == 1: self.tai += 1.0
        else: self.xiu += 1.0

    def predict(self, hist):
        total = self.tai + self.xiu
        p = self.tai / total
        edge = abs(p - 0.5) * 2
        return p, edge, {"p_tai": round(p, 3), "samples": int(total)}


class RegimeClassifier:
    def state(self, hist):
        if len(hist) < 10:
            return "UNKNOWN", 0.0, {}

        w20 = hist[-20:]
        p_same = sum(1 for i in range(1, len(w20)) if w20[i] == w20[i-1]) / (len(w20) - 1)
        run = 1
        for v in reversed(hist[:-1]):
            if v != hist[-1]: break
            run += 1

        tail = hist[-6:]
        alts = sum(1 for i in range(1, len(tail)) if tail[i] != tail[i-1])

        details = {"p_same_20": round(p_same, 3), "current_run": run, "alts_6": alts}

        if len(tail) >= 5 and alts == len(tail) - 1:
            return "DAO_1_1", 0.85, details
        if run >= 5:
            return "BET_5plus", min(1.0, 0.5 + (run - 4) * 0.15), details
        if run >= 3 and p_same > 0.55:
            return "BET_3_4", 0.70, details
        if p_same > 0.58:
            return "BET", 0.60, details
        if p_same < 0.42:
            return "DAO", 0.60, details
        w50 = hist[-50:] if len(hist) >= 50 else hist
        bias = abs(sum(w50) / len(w50) - 0.5)
        if bias > 0.08:
            return "BIAS", min(1.0, bias * 5), details
        return "RANDOM", max(0.0, 1.0 - abs(p_same - 0.5) * 4), details


class PredictionEngine:
    """Ensemble 8 module thống kê + regime classifier."""

    EXPERTS = ("transition", "streak_length", "break", "frequency",
               "streak_end", "stability", "momentum", "base_rate")

    def __init__(self, history=None):
        self.history = []
        self.transition = TransitionModule()
        self.streak_length = StreakLengthModule()
        self.break_module = BreakModule()
        self.frequency = FrequencyModule()
        self.streak_end = StreakEndModule()
        self.stability = StabilityModule()
        self.momentum = MomentumModule()
        self.base_rate = BaseRateModule()
        self.classifier = RegimeClassifier()

        for value in list(history or []):
            y = 1 if int(value) == 1 else 0
            self._update(y)

    def _update(self, y):
        hist = self.history[:]
        self.transition.update(hist, y)
        self.streak_length.update(hist, y)
        self.break_module.update(hist, y)
        self.frequency.update(hist, y)
        self.streak_end.update(hist, y)
        self.stability.update(hist, y)
        self.momentum.update(hist, y)
        self.base_rate.update(hist, y)
        self.history.append(y)

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

    @staticmethod
    def _clamp(v, lo, hi):
        return max(lo, min(hi, v))

    def _regime_weights(self, regime):
        if regime == "BET_5plus":
            return {"transition": 2.5, "streak_length": 2.5, "break": 0.3,
                    "frequency": 0.5, "streak_end": 2.5, "stability": 1.5,
                    "momentum": 1.0, "base_rate": 0.5}
        if regime == "BET_3_4":
            return {"transition": 2.0, "streak_length": 2.0, "break": 0.5,
                    "frequency": 0.5, "streak_end": 2.0, "stability": 1.5,
                    "momentum": 1.0, "base_rate": 0.5}
        if regime == "BET":
            return {"transition": 1.5, "streak_length": 1.5, "break": 0.7,
                    "frequency": 0.7, "streak_end": 1.5, "stability": 1.2,
                    "momentum": 1.0, "base_rate": 0.7}
        if regime == "DAO_1_1":
            return {"transition": 2.5, "streak_length": 0.5, "break": 2.0,
                    "frequency": 0.5, "streak_end": 0.5, "stability": 1.0,
                    "momentum": 0.5, "base_rate": 0.5}
        if regime == "DAO":
            return {"transition": 2.0, "streak_length": 0.7, "break": 1.5,
                    "frequency": 0.7, "streak_end": 0.7, "stability": 1.0,
                    "momentum": 0.5, "base_rate": 0.7}
        if regime == "BIAS":
            return {"transition": 1.0, "streak_length": 0.7, "break": 0.7,
                    "frequency": 2.5, "streak_end": 0.7, "stability": 0.7,
                    "momentum": 1.5, "base_rate": 2.5}
        return {"transition": 1.0, "streak_length": 0.7, "break": 0.7,
                "frequency": 1.0, "streak_end": 0.7, "stability": 0.7,
                "momentum": 0.7, "base_rate": 1.5}

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)

        if n < 30:
            return {
                "side": None, "confidence": 50, "p_internal": 0.5,
                "regime": "WARMUP", "regime_conf": 0.0, "regime_details": {},
                "modules": {}, "weights": {},
                "skip": True, "reason": "warmup", "is_uncertain": True,
            }

        regime, regime_conf, reg_details = self.classifier.state(self.history)
        modules = self._modules()
        weights = self._regime_weights(regime)

        p_num = 0.0
        w_sum = 0.0
        for name, (p, conf, _) in modules.items():
            eff = weights[name] * (0.3 + 0.7 * conf)
            p_num += p * eff
            w_sum += eff

        p = p_num / w_sum if w_sum > 1e-6 else 0.5
        p = self._clamp(p, 0.05, 0.95)

        side = "TAI" if p >= 0.5 else "XIU"
        edge = abs(p - 0.5) * 2
        confidence = int(round(50 + 32 * edge * (0.5 + 0.5 * regime_conf)))
        confidence = self._clamp(confidence, 50, 85)
        is_uncertain = regime == "RANDOM" or edge < 0.04

        module_view = {}
        for name, (p_m, conf_m, details) in modules.items():
            module_view[name] = {
                "p": round(float(p_m), 3),
                "conf": round(float(conf_m), 3),
                "weight": float(weights[name]),
                "details": details,
            }

        return {
            "side": side,
            "confidence": confidence,
            "p_internal": float(p),
            "regime": regime,
            "regime_conf": float(regime_conf),
            "regime_details": reg_details,
            "modules": module_view,
            "weights": weights,
            "skip": False,
            "reason": None,
            "is_uncertain": bool(is_uncertain),
        }

    def observe(self, result):
        y = 1 if int(result) == 1 else 0
        self._update(y)

    def to_dict(self):
        return {"history": list(self.history)}

    @classmethod
    def from_history(cls, history):
        return cls(history=history)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        history = data.get("history", [])
        if not isinsdata.get("history", [])
        if not isinstance(history, list):
            history = []
        return cls(history=history)


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def load_engine(table_code):
    conn=db(); row=conn.execute("SELECT history_json FROM table_states WHERE table_code=?",(table_code,)).fetchone(); conn.close()
    try: state=json.loads(row["history_json"] or '{"history":[]}') if row else {"history":[]}
    except (ValueError,TypeError): state={"history":[]}
    return PredictionEngine.from_dict(state)

def save_engine(table_code, engine):
    conn=db(); conn.execute("UPDATE table_states SET history_json=?,updated_at=? WHERE table_code=?",
        (json.dumps(engine.to_dict(),separators=(",",":")),now_iso(),table_code)); conn.commit(); conn.close()

def load_last_seen(table_code):
    conn=db(); row=conn.execute("SELECT last_seen_id FROM table_states WHERE table_code=?",(table_code,)).fetchone(); conn.close()
    return int(row[0]) if row else 0

def save_last_seen(table_code, session_id):
    conn=db(); conn.execute("UPDATE table_states SET last_seen_id=?,updated_at=? WHERE table_code=?",(int(session_id),now_iso(),table_code)); conn.commit(); conn.close()

def save_worker_state(table_code, engine, session_id):
    """Ghi model và last_seen trong cùng transaction để tránh học lặp sau crash."""
    conn=db()
    conn.execute("UPDATE table_states SET history_json=?,last_seen_id=?,updated_at=? WHERE table_code=?",
        (json.dumps(engine.to_dict(),separators=(",",":")),int(session_id),now_iso(),table_code))
    conn.commit(); conn.close()

def mark_poll_ok(table_code):
    conn=db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=NULL,updated_at=? WHERE table_code=?",(now_iso(),now_iso(),table_code)); conn.commit(); conn.close()

def mark_poll_error(table_code,error):
    conn=db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?",(now_iso(),str(error)[:500],now_iso(),table_code)); conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    conn=db(); rows=conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IS NOT NULL ORDER BY session_id DESC LIMIT ?",(table_code,int(limit))).fetchall(); conn.close()
    return (sum(r[0]=="win" for r in rows)/len(rows)) if rows else .5

# === END engine.py ===