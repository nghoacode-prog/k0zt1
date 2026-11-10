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


def _cap_add(cell, y, cap):
    cell[y] += 1.0
    total = cell[0] + cell[1]
    if total > cap:
        scale = cap / total
        cell[0] *= scale
        cell[1] *= scale


class NgramExpert:
    name = "ngram"

    def __init__(self, max_order=4, alpha=1.0, cell_cap=50.0):
        self.max_order = int(max_order)
        self.alpha = float(alpha)
        self.cell_cap = float(cell_cap)
        self.counts = {}
        self.global_counts = [alpha, alpha]

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.global_counts[y] += 1.0
        total = self.global_counts[0] + self.global_counts[1]
        if total > 200.0:
            s = 200.0 / total
            self.global_counts[0] *= s
            self.global_counts[1] *= s
        for k in range(1, min(self.max_order, len(hist)) + 1):
            cell = self.counts.setdefault((k, tuple(hist[-k:])), [self.alpha, self.alpha])
            _cap_add(cell, y, self.cell_cap)

    def predict(self, hist):
        p_num = 0.0
        w_sum = 0.0
        for k in range(1, min(self.max_order, len(hist)) + 1):
            cell = self.counts.get((k, tuple(hist[-k:])))
            if not cell:
                continue
            n = cell[0] + cell[1] - 2.0 * self.alpha
            if n < 2:
                continue
            p = cell[1] / (cell[0] + cell[1])
            w = k * min(1.0, n / 10.0)
            p_num += p * w
            w_sum += w
        if w_sum < 1e-9:
            g = self.global_counts
            return g[1] / (g[0] + g[1]), 0.5
        return p_num / w_sum, w_sum


class StreakExpert:
    name = "streak"

    def __init__(self):
        self.counts = {}
        self.global_counts = [1.0, 1.0]

    @staticmethod
    def _run(hist):
        if not hist:
            return None, 0
        side = hist[-1]
        run = 1
        for value in reversed(hist[:-1]):
            if value != side:
                break
            run += 1
        return side, run

    @staticmethod
    def _scale(run):
        if run <= 3:
            return "short"
        if run <= 7:
            return "medium"
        return "long"

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.global_counts[y] += 1.0
        side, run = self._run(hist)
        if side is None:
            return
        key = (side, self._scale(run), min(run, 12))
        cell = self.counts.setdefault(key, [1.0, 1.0])
        _cap_add(cell, 0 if y == side else 1, 40.0)

    def predict(self, hist):
        side, run = self._run(hist)
        if side is None:
            return 0.5, 0.3
        key = (side, self._scale(run), min(run, 12))
        cell = self.counts.get(key, [1.0, 1.0])
        cont = cell[0] / (cell[0] + cell[1])
        p_tai = cont if side == 1 else 1.0 - cont
        w = {"short": 0.6, "medium": 1.2, "long": 0.4}[self._scale(run)]
        return p_tai, w


class AntiStreakExpert:
    name = "anti_streak"

    def __init__(self, base_decay=0.99):
        self.base_rate = 0.5
        self.decay = float(base_decay)

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.base_rate = self.decay * self.base_rate + (1 - self.decay) * y

    def predict(self, hist):
        side, run = StreakExpert._run(hist)
        if side is None or run < 4:
            return 0.5, 0.0
        p_side = self.base_rate if side == 1 else 1.0 - self.base_rate
        p_run = p_side ** run
        if p_run > 0.15:
            return 0.5, 0.0
        sig = min(1.0, (0.15 - p_run) / 0.15 + 0.3)
        p_tai = (1 - self.base_rate) if side == 1 else self.base_rate
        weight = min(2.0, 0.3 + sig * 1.5)
        return p_tai, weight


class EMAExpert:
    name = "ema"

    def __init__(self, fast_hl=10, slow_hl=50):
        self.fast_alpha = 1.0 - 0.5 ** (1.0 / fast_hl)
        self.slow_alpha = 1.0 - 0.5 ** (1.0 / slow_hl)
        self.fast = 0.5
        self.slow = 0.5

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.fast = self.fast_alpha * y + (1 - self.fast_alpha) * self.fast
        self.slow = self.slow_alpha * y + (1 - self.slow_alpha) * self.slow

    def predict(self, hist):
        momentum = self.fast - self.slow
        p = self.fast + 0.5 * momentum
        p = max(0.05, min(0.95, p))
        weight = 0.3 + 1.7 * min(1.0, abs(momentum) * 5)
        return p, weight


class MarkovExpert:
    name = "markov"

    def __init__(self, max_order=3):
        self.max_order = int(max_order)
        self.counts = {}
        self.global_counts = [1.0, 1.0]

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.global_counts[y] += 1.0
        for k in range(1, min(self.max_order, len(hist)) + 1):
            cell = self.counts.setdefault((k, tuple(hist[-k:])), [1.0, 1.0])
            _cap_add(cell, y, 40.0)

    def predict(self, hist):
        for k in range(min(self.max_order, len(hist)), 0, -1):
            cell = self.counts.get((k, tuple(hist[-k:])))
            if cell and sum(cell) >= 4:
                return cell[1] / sum(cell), sum(cell) / 2.0
        return self.global_counts[1] / sum(self.global_counts), 0.5


class CycleExpert:
    name = "cycle"

    def __init__(self, max_period=8, window=50):
        self.max_period = int(max_period)
        self.window = int(window)

    def update(self, hist, y):
        return None

    def predict(self, hist):
        if len(hist) < 15:
            return 0.5, 0.0
        recent = hist[-self.window:]
        n = len(recent)
        mean = sum(recent) / n
        var_sum = sum((x - mean) ** 2 for x in recent)
        if var_sum < 1e-9:
            return 0.5, 0.0
        var = var_sum / n

        best_lag = None
        best_corr = 0.0
        for period in range(2, self.max_period + 1):
            if n < period + 5:
                continue
            cov_sum = sum((recent[i] - mean) * (recent[i - period] - mean)
                          for i in range(period, n))
            cov = cov_sum / (n - period)
            corr = cov / var
            if abs(corr) > abs(best_corr):
                best_corr = corr
                best_lag = period

        if best_lag is None or abs(best_corr) < 0.15:
            return 0.5, 0.0

        reference = recent[-best_lag]
        if best_corr > 0:
            p_tai = 0.85 if reference == 1 else 0.15
        else:
            p_tai = 0.15 if reference == 1 else 0.85
        p_tai = 0.5 + (p_tai - 0.5) * min(1.0, abs(best_corr) * 1.5)
        weight = min(2.0, abs(best_corr) * 3.0)
        return p_tai, weight


class VolatilityExpert:
    name = "volatility"

    def __init__(self):
        self.entropy_short = 1.0
        self.entropy_long = 1.0

    @staticmethod
    def _entropy(values):
        if len(values) < 2:
            return 1.0
        n = len(values)
        p1 = sum(values) / n
        p0 = 1.0 - p1
        h = 0.0
        for p in (p0, p1):
            if p > 0:
                h -= p * math.log(p, 2)
        return h

    def update(self, hist, y):
        return None

    def predict(self, hist):
        if len(hist) < 10:
            return 0.5, 0.1
        self.entropy_short = self._entropy(hist[-10:])
        self.entropy_long = self._entropy(hist[-50:])
        recent = hist[-50:]
        trend = sum(recent) / len(recent)
        if self.entropy_long < 0.85:
            strength = 1.0 - self.entropy_long
            p = 0.5 + (trend - 0.5) * strength
            return p, 0.5 + strength
        p = 0.5 + (trend - 0.5) * 0.3
        return p, 0.3


class BayesianExpert:
    name = "bayesian"

    def __init__(self, decay=0.995, recent_decay=0.985):
        self.alpha = 1.0
        self.beta = 1.0
        self.recent_alpha = 1.0
        self.recent_beta = 1.0
        self.decay = float(decay)
        self.recent_decay = float(recent_decay)

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.alpha *= self.decay
        self.beta *= self.decay
        self.recent_alpha *= self.recent_decay
        self.recent_beta *= self.recent_decay
        if y == 1:
            self.alpha += 1.0
            self.recent_alpha += 1.0
        else:
            self.beta += 1.0
            self.recent_beta += 1.0

    def predict(self, hist):
        total = self.alpha + self.beta
        recent_total = self.recent_alpha + self.recent_beta
        p_global = self.alpha / total
        p_recent = self.recent_alpha / recent_total
        surprise = abs(p_recent - p_global)
        blend = min(0.7, 0.3 + surprise * 2.0)
        p = (1 - blend) * p_global + blend * p_recent
        weight = min(2.0, 0.5 + math.log(max(1.0, total)) / 5.0)
        return p, weight


class PredictionEngine:
    EXPERTS = ("ngram", "streak", "anti_streak", "ema",
               "markov", "cycle", "volatility", "bayesian")
    EARLY_EXPERTS = ("ema", "ngram", "bayesian")
    MID_EXPERTS = ("ema", "ngram", "bayesian", "markov", "streak")

    WEIGHT_MIN = 0.3
    WEIGHT_MAX = 2.5

    def __init__(self, history=None):
        self.history = []
        self.ngram = NgramExpert(max_order=4)
        self.streak = StreakExpert()
        self.anti_streak = AntiStreakExpert()
        self.ema = EMAExpert(fast_hl=10, slow_hl=50)
        self.markov = MarkovExpert(max_order=3)
        self.cycle = CycleExpert(max_period=8, window=50)
        self.volatility = VolatilityExpert()
        self.bayesian = BayesianExpert()

        self.weights = {name: 1.0 for name in self.EXPERTS}
        self.lr = 0.12
        self.rolling_accuracy = {name: deque(maxlen=25) for name in self.EXPERTS}
        self.calibration_history = []
        self.losses = []
        self.cusum = 0.0
        self.watchdog_count = 0.0
        self._pred_counter = 0
        self._last_probs = None
        self._last_expert_sides = None
        self._last_ensemble_p = None
        self._last_confidence = None
        self._last_side = None
        self._last_meta = {}

        for value in list(history or []):
            y = 1 if int(value) == 1 else 0
            self.predict()
            self.observe(y)

    def _experts(self):
        return {
            "ngram": self.ngram.predict(self.history),
            "streak": self.streak.predict(self.history),
            "anti_streak": self.anti_streak.predict(self.history),
            "ema": self.ema.predict(self.history),
            "markov": self.markov.predict(self.history),
            "cycle": self.cycle.predict(self.history),
            "volatility": self.volatility.predict(self.history),
            "bayesian": self.bayesian.predict(self.history),
        }

    @staticmethod
    def _clamp(value, low, high):
        return max(low, min(high, value))

    @staticmethod
    def _logit(prob):
        prob = max(0.01, min(0.99, float(prob)))
        return math.log(prob / (1.0 - prob))

    @staticmethod
    def _sigmoid(value):
        value = max(-20.0, min(20.0, float(value)))
        return 1.0 / (1.0 + math.exp(-value))

    def _active_experts(self, n):
        if n < 200:
            return self.EARLY_EXPERTS
        if n < 500:
            return self.MID_EXPERTS
        return self.EXPERTS

    def _calibration_factor(self):
        if not self.calibration_history:
            return 1.0
        observed_acc = sum(1 for _, correct in self.calibration_history if correct) / len(self.calibration_history)
        expected_conf = sum(conf for conf, _ in self.calibration_history) / len(self.calibration_history) / 100.0
        if expected_conf <= 0:
            return 1.0
        return self._clamp(observed_acc / expected_conf, 0.5, 1.2)

    def predict(self, accuracy_100=.5, accuracy_500=.5):
        self._pred_counter += 1
        n = len(self.history)

        if n < 50:
            self._last_probs = None
            self._last_expert_sides = None
            self._last_ensemble_p = None
            self._last_confidence = None
            self._last_side = None
            return {
                "side": None, "confidence": 50, "p_internal": 0.5,
                "experts": {}, "weights": dict(self.weights),
                "is_uncertain": True, "reason": "warmup", "skip": True,
            }

        exp = self._experts()
        active = self._active_experts(n)
        self.lr = max(0.02, 0.12 / math.sqrt(max(1.0, n / 100.0)))

        raw = {}
        for name in active:
            prob, intrinsic = exp[name]
            if intrinsic <= 0.01:
                continue
            meta = self._clamp(self.weights[name], self.WEIGHT_MIN, self.WEIGHT_MAX)
            combined = min(self.WEIGHT_MAX, meta * intrinsic)
            raw[name] = combined

        if not raw:
            raw = {name: 1.0 for name in self.EARLY_EXPERTS}

        avg = sum(raw.values()) / len(raw)
        cap = avg * 1.5
        for k in list(raw.keys()):
            raw[k] = min(raw[k], cap)

        total = sum(raw.values())
        weighted_logit = sum(raw[name] * self._logit(exp[name][0]) for name in raw) / total
        p = self._sigmoid(weighted_logit)

        shrink = 1.0
        if n < 200:
            shrink *= 0.60
        elif n < 500:
            shrink *= 0.80
        sides = [1 if exp[name][0] >= 0.5 else 0 for name in raw]
        ones = sum(sides)
        unanimity = max(ones, len(sides) - ones) / len(sides) if sides else 0.0
        if unanimity > 0.85 and n < 1000:
            shrink *= 0.80
        if self.watchdog_count > 0.78:
            shrink *= 0.80
        if self.cusum > 2.5:
            shrink *= 0.75
        shrink = max(0.35, shrink)

        p = 0.5 + (p - 0.5) * shrink
        p = 0.5 + (p - 0.5) * self._calibration_factor()
        p = self._clamp(p, 0.01, 0.99)

        edge = abs(p - 0.5) * 2.0
        is_uncertain = edge < 0.03

        if abs(p - 0.5) < 1e-9:
            side_bit = 1 if self._pred_counter % 2 else 0
        else:
            side_bit = 1 if p > 0.5 else 0
        side = "TAI" if side_bit else "XIU"
        confidence = 52 if is_uncertain else int(round(self._clamp(50.0 + 35.0 * edge, 50.0, 85.0)))

        reason = None
        if is_uncertain:
            reason = "high_entropy" if self.volatility.entropy_long >= 0.92 else "disagreement"

        self._last_probs = {name: exp[name][0] for name in raw}
        self._last_expert_sides = {name: (1 if exp[name][0] >= 0.5 else 0) for name in raw}
        self._last_ensemble_p = p
        self._last_confidence = confidence
        self._last_side = side_bit
        self._last_meta = {
            "weights": dict(self.weights),
            "effective": dict(raw),
            "unanimity": unanimity,
            "shrink": shrink,
            "cap": cap,
            "active": list(raw),
            "lr": self.lr,
        }

        expert_view = {}
        for name in self.EXPERTS:
            if name not in raw:
                expert_view[name] = (0.5, float(self.weights[name]), None)
            else:
                acc_list = self.rolling_accuracy[name]
                expert_view[name] = (
                    float(exp[name][0]),
                    float(self.weights[name]),
                    sum(acc_list) / len(acc_list) if acc_list else 0.5,
                )

        return {
            "side": side,
            "confidence": confidence,
            "p_internal": float(p),
            "experts": expert_view,
            "weights": dict(self.weights),
            "is_uncertain": bool(is_uncertain),
            "reason": reason,
            "skip": False,
        }

    def observe(self, result):
        y = 1 if int(result) == 1 else 0
        hist = self.history[:]
        probs = self._last_probs
        expert_sides = self._last_expert_sides

        if self._last_ensemble_p is not None:
            ep = self._clamp(self._last_ensemble_p, 0.01, 0.99)
            self.losses.append(-(y * math.log(ep) + (1 - y) * math.log(1 - ep)))
            self.losses = self.losses[-500:]

        if probs:
            for name, prob in probs.items():
                q = self._clamp(prob, 0.01, 0.99)
                loss = -(y * math.log(q) + (1 - y) * math.log(1 - q))
                self.weights[name] = self._clamp(
                    self.weights[name] * math.exp(-self.lr * (loss - 0.693)),
                    self.WEIGHT_MIN, self.WEIGHT_MAX
                )
                predicted_bit = expert_sides.get(name, 1 if prob >= 0.5 else 0)
                acc = self.rolling_accuracy[name]
                acc.append(predicted_bit == y)
                rolling = sum(acc) / len(acc)
                if rolling < 0.42:
                    self.weights[name] = self._clamp(self.weights[name] * 0.80, self.WEIGHT_MIN, self.WEIGHT_MAX)
                elif rolling > 0.58:
                    self.weights[name] = self._clamp(self.weights[name] * 1.12, self.WEIGHT_MIN, self.WEIGHT_MAX)

            if self._last_confidence is not None and self._last_side is not None:
                self.calibration_history.append((int(self._last_confidence), self._last_side == y))
                self.calibration_history = self.calibration_history[-100:]

        self.ngram.update(hist, y)
        self.streak.update(hist, y)
        self.anti_streak.update(hist, y)
        self.ema.update(hist, y)
        self.markov.update(hist, y)
        self.cycle.update(hist, y)
        self.volatility.update(hist, y)
        self.bayesian.update(hist, y)
        self.history.append(y)

        prior = self._clamp(self.ema.slow, 0.05, 0.95)
        surprise = -(y * math.log(prior) + (1 - y) * math.log(1 - prior))
        self.cusum = max(0.0, self.cusum + surprise - 0.693 - 0.08)

        if len(self.history) % 50 == 0:
            recent = self.losses[-50:]
            self.watchdog_count = (sum(recent) / len(recent)) if recent else 0.693
            if self.watchdog_count > 0.78:
                self.weights = {k: self._clamp(v * 0.92, self.WEIGHT_MIN, self.WEIGHT_MAX)
                                for k, v in self.weights.items()}

        self._last_probs = None
        self._last_expert_sides = None
        self._last_ensemble_p = None
        self._last_confidence = None
        self._last_side = None

    def to_dict(self):
        return {
            "history": list(self.history),
            "expert_weights": dict(self.weights),
            "calibration_history": [[int(conf), bool(correct)]
                                    for conf, correct in self.calibration_history],
        }

    @classmethod
    def from_history(cls, history):
        return cls(history=history)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        history = data.get("history", [])
        if not isinstance(history, list):
            history = []
        engine = cls(history=history)
        saved_weights = data.get("expert_weights")
        if isinstance(saved_weights, dict):
            for name in cls.EXPERTS:
                try:
                    if name in saved_weights:
                        engine.weights[name] = engine._clamp(
                            float(saved_weights[name]), cls.WEIGHT_MIN, cls.WEIGHT_MAX
                        )
                except (TypeError, ValueError):
                    pass
        saved_calibration = data.get("calibration_history")
        if isinstance(saved_calibration, list):
            parsed = []
            for item in saved_calibration[-100:]:
                try:
                    conf, correct = item
                    parsed.append((int(engine._clamp(float(conf), 50, 85)), bool(correct)))
                except (TypeError, ValueError):
                    continue
            if parsed:
                engine.calibration_history = parsed
        return engine


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