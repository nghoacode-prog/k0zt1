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
# Bảy expert thích nghi cho giai đoạn ít dữ liệu
# ---------------------------------------------------------------------------
class NgramExpert:
    """Học chuỗi ngắn order-3; phù hợp khi dữ liệu ít và tự lùi về n-gram ngắn hơn khi thiếu mẫu."""
    name = "ngram"

    def __init__(self, order=3, alpha=1.0):
        self.order = int(order)
        self.alpha = float(alpha)
        self.counts = {}
        self.global_counts = [0.0, 0.0]

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.global_counts[y] += 1.0
        for k in range(1, min(self.order, len(hist)) + 1):
            key = tuple(hist[-k:])
            cell = self.counts.setdefault(key, [0.0, 0.0])
            cell[y] += 1.0

    def predict(self, hist):
        # Chỉ dùng pattern đã có ít nhất hai quan sát thật; alpha chỉ làm mượt xác suất.
        for k in range(min(self.order, len(hist)), 0, -1):
            cell = self.counts.get(tuple(hist[-k:]))
            if cell and sum(cell) >= 2:
                total = sum(cell) + 2.0 * self.alpha
                return (cell[1] + self.alpha) / total, sum(cell)
        total = sum(self.global_counts) + 2.0 * self.alpha
        return (self.global_counts[1] + self.alpha) / total, sum(self.global_counts)


class StreakExpert:
    """Theo xu hướng tiếp diễn của streak ngắn 1-5; streak dài không đủ mẫu sẽ lùi về base rate."""
    name = "streak"

    def __init__(self, max_len=5):
        self.max_len = int(max_len)
        self.counts = {}
        self.global_counts = [0.0, 0.0]

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

    def update(self, hist, y):
        y = 1 if int(y) == 1 else 0
        self.global_counts[y] += 1.0
        side, run = self._run(hist)
        if side is None or run > self.max_len:
            return
        cell = self.counts.setdefault((side, run), [0.0, 0.0])
        cell[0 if y == side else 1] += 1.0

    def predict(self, hist):
        side, run = self._run(hist)
        if side is None:
            return 0.5, 0.0
        if run > self.max_len:
            total = sum(self.global_counts) + 2.0
            return (self.global_counts[1] + 1.0) / total, total
        cell = self.counts.get((side, run), [0.0, 0.0])
        # Hai pseudo-count giữ xác suất ổn định khi một streak mới chỉ có ít mẫu.
        cont = (cell[0] + 1.0) / (sum(cell) + 2.0)
        p_tai = cont if side == 1 else 1.0 - cont
        return p_tai, sum(cell)


class AntiStreakExpert:
    """Expert contrarian stateless; chỉ phản ứng khi streak đạt ít nhất 5 phiên liên tiếp."""
    name = "anti_streak"

    def __init__(self):
        self.last_run = 0

    def update(self, hist, y):
        # Stateless: không lưu kết quả để tránh tự khuếch đại streak vừa quan sát.
        self.last_run = 0

    def predict(self, hist):
        side, run = StreakExpert._run(hist)
        self.last_run = run
        if side is None or run < 5:
            return 0.5, 0.0
        p_continue = max(0.20, 0.50 - 0.05 * (run - 5))
        # p_continue là xác suất giữ side hiện tại; phần còn lại là xác suất đảo chiều.
        p_tai = p_continue if side == 1 else 1.0 - p_continue
        return p_tai, float(run * 3)


class EMAExpert:
    """Theo xu hướng gần đây bằng trung bình mũ; half-life 50 phiên giúp giảm nhiễu ngắn hạn."""
    name = "ema"

    def __init__(self, half_life=50):
        self.half_life = int(half_life)
        self.alpha = 1.0 - 0.5 ** (1.0 / self.half_life)
        self.value = 0.5

    def update(self, hist, y):
        self.value = self.alpha * int(y) + (1.0 - self.alpha) * self.value

    def predict(self, hist):
        return self.value, 1.0 / self.alpha


class MarkovExpert:
    """Học xác suất chuyển trạng thái từ phiên trước sang phiên kế tiếp."""
    name = "markov"

    def __init__(self, order=1):
        self.order = int(order)
        self.counts = {}

    def update(self, hist, y):
        if len(hist) >= self.order:
            key = tuple(hist[-self.order:])
            cell = self.counts.setdefault(key, [0.0, 0.0])
            cell[int(y)] += 1.0

    def predict(self, hist):
        if len(hist) < self.order:
            return 0.5, 0.0
        cell = self.counts.get(tuple(hist[-self.order:]), [0.0, 0.0])
        total = sum(cell) + 2.0
        return (cell[1] + 1.0) / total, sum(cell)


class CycleExpert:
    """Tìm nhịp lặp ngắn chu kỳ 2-5; trung bình có trọng số để tránh chọn nhầm chu kỳ thắng lớn nhất."""
    name = "cycle"

    def __init__(self):
        self.counts = {}

    def update(self, hist, y):
        for period in range(2, 6):
            if len(hist) >= period:
                key = (period, tuple(hist[-period:]))
                cell = self.counts.setdefault(key, [0.0, 0.0])
                cell[int(y)] += 1.0

    def predict(self, hist):
        candidates = []
        for period in range(2, 6):
            if len(hist) < period:
                continue
            cell = self.counts.get((period, tuple(hist[-period:])))
            if not cell:
                continue
            total = sum(cell)
            # Chỉ chu kỳ đã từng được quan sát mới tham gia; smoothing tránh xác suất cực đoan.
            prob = (cell[1] + 1.0) / (total + 2.0)
            candidates.append((prob, total))
        if not candidates:
            return 0.5, 0.0
        denom = sum(max(1.0, weight) for _, weight in candidates)
        prob = sum(p * max(1.0, weight) for p, weight in candidates) / denom
        return prob, sum(weight for _, weight in candidates)


class VolatilityExpert:
    """Đo entropy 20 phiên; entropy cao báo hiệu khó dự đoán, entropy thấp cho phép theo base trend."""
    name = "volatility"

    def __init__(self, window=20):
        self.window = int(window)
        self.entropy = 1.0

    def update(self, hist, y):
        # Expert dùng trực tiếp cửa sổ history ở predict nên update không cần giữ state.
        return None

    def predict(self, hist):
        recent = hist[-self.window:]
        if len(recent) < 2:
            self.entropy = 1.0
            return 0.5, 0.10
        ones = sum(recent)
        zeros = len(recent) - ones
        n = len(recent)
        p1, p0 = ones / n, zeros / n
        entropy = 0.0
        for prob in (p0, p1):
            if prob > 0:
                entropy -= prob * math.log(prob, 2)
        self.entropy = max(0.0, min(1.0, entropy))
        # Entropy cao thì xác suất co về 0.5 và intrinsic weight cũng thấp.
        trend = (ones + 1.0) / (n + 2.0)
        strength = max(0.0, 1.0 - self.entropy)
        prob = 0.5 + (trend - 0.5) * strength
        intrinsic_weight = 0.10 + 0.90 * strength
        return prob, intrinsic_weight


class PredictionEngine:
    """Ensemble online bảy expert; có warmup, adaptive weight và calibration theo kết quả thật."""

    EXPERTS = ("ngram", "streak", "anti_streak", "ema", "markov", "cycle", "volatility")
    EARLY_EXPERTS = ("ema", "ngram", "markov")

    def __init__(self, history=None):
        self.history = []
        self.ngram = NgramExpert(order=3, alpha=1.0)
        self.streak = StreakExpert(max_len=5)
        self.anti_streak = AntiStreakExpert()
        self.ema = EMAExpert(half_life=50)
        self.markov = MarkovExpert(order=1)
        self.cycle = CycleExpert()
        self.volatility = VolatilityExpert(window=20)

        self.weights = {name: 1.0 for name in self.EXPERTS}
        self.lr = 0.10
        self.rolling_accuracy = {name: deque(maxlen=50)
                                 for name in self.EXPERTS}
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

        # Replay theo thứ tự: dự báo từ dữ liệu cũ trước, rồi mới nạp kết quả phiên đó.
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
        # Ít dữ liệu thì chỉ bật các expert có inductive bias ổn định, tránh overfit.
        if n < 200:
            return self.EARLY_EXPERTS
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

        # Warmup: 50 phiên trở xuống chưa đủ nền để phát tín hiệu đáng tin.
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
        self.lr = 0.10 / math.sqrt(max(1.0, n / 100.0))

        # Intrinsic weight của expert (ví dụ anti-streak theo độ dài run) nhân với meta weight đã học.
        effective = {}
        for name in active:
            prob, intrinsic = exp[name]
            if name == "anti_streak":
                # Anti-streak chỉ có lực khi run >= 5; lực đúng bằng run * 3.
                intrinsic_factor = intrinsic if intrinsic > 0 else 0.001
            elif name == "volatility":
                # Entropy cao làm expert này có trọng số nhỏ, entropy thấp thì tăng trọng số.
                intrinsic_factor = max(0.001, intrinsic)
            else:
                # Số mẫu của expert là metadata, không được biến thành trọng số áp đảo.
                intrinsic_factor = 1.0
            effective[name] = max(0.15, self.weights[name]) * intrinsic_factor

        total_weight = sum(effective.values())
        weighted_logit = sum(effective[name] * self._logit(exp[name][0]) for name in active) / total_weight
        p = self._sigmoid(weighted_logit)

        # Giai đoạn ít mẫu cần co về 0.5 để tránh biến dao động base-rate thành tín hiệu mạnh.
        shrink = 0.60 if n < 200 else (0.80 if n < 500 else 1.0)
        p = 0.5 + (p - 0.5) * shrink

        # Khi đa số expert đồng thuận, vẫn giảm nhẹ edge vì đồng thuận có thể là overfit trên mẫu nhỏ.
        expert_sides = {name: (1 if exp[name][0] >= 0.5 else 0) for name in active}
        ones = sum(expert_sides.values())
        unanimous_ratio = max(ones, len(active) - ones) / max(1, len(active))
        if unanimous_ratio > 0.85 and n < 1000:
            p = 0.5 + (p - 0.5) * 0.75

        # Giữ lại bộ giảm chấn CUSUM/watchdog cũ để xử lý giai đoạn mô hình mất ổn định.
        if self.watchdog_count > 0.78:
            p = 0.5 + (p - 0.5) * 0.75
        if self.cusum > 2.5:
            p = 0.5 + (p - 0.5) * 0.65

        # Calibration chỉ dùng các phiên đã quan sát trước đó, không nhìn trước kết quả hiện tại.
        p = 0.5 + (p - 0.5) * self._calibration_factor()
        p = self._clamp(p, 0.01, 0.99)

        edge = abs(p - 0.5) * 2.0
        is_uncertain = edge < 0.03
        if abs(p - 0.5) < 1e-9:
            # Tie-break xen kẽ để tránh mặc định thiên TÀI khi xác suất bằng nhau.
            side_bit = 1 if self._pred_counter % 2 else 0
        else:
            side_bit = 1 if p > 0.5 else 0
        side = "TAI" if side_bit else "XIU"
        confidence = 52 if is_uncertain else int(round(self._clamp(50.0 + 35.0 * edge, 50.0, 85.0)))

        entropy = self.volatility.entropy
        reason = None
        if is_uncertain and entropy >= 0.92:
            reason = "high_entropy"
        elif is_uncertain:
            reason = "disagreement"

        # Chỉ lưu dự báo của expert đang hoạt động để observe chấm đúng cùng tập expert.
        self._last_probs = {name: exp[name][0] for name in active}
        self._last_expert_sides = dict(expert_sides)
        self._last_ensemble_p = p
        self._last_confidence = confidence
        self._last_side = side_bit
        self._last_meta = {
            "weights": dict(self.weights),
            "effective_weights": effective,
            "unanimous_ratio": unanimous_ratio,
            "entropy": entropy,
            "shrink": shrink,
        }

        expert_view = {
            name: (float(exp[name][0]), float(self.weights[name]),
                   (sum(self.rolling_accuracy[name]) / len(self.rolling_accuracy[name])
                    if self.rolling_accuracy[name] else 0.5))
            for name in self.EXPERTS
        }
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
        prior_ema = self._clamp(self.ema.value, 0.05, 0.95)

        # Cập nhật loss bằng đúng xác suất đã phát ra trước khi biết kết quả.
        if self._last_ensemble_p is not None:
            ep = self._clamp(self._last_ensemble_p, 0.01, 0.99)
            ensemble_loss = -(y * math.log(ep) + (1 - y) * math.log(1 - ep))
            self.losses.append(ensemble_loss)
            self.losses = self.losses[-500:]

        if probs:
            # Log-loss reward/penalty giúp expert tốt dần có trọng số cao hơn nhưng luôn bị giới hạn.
            for name, prob in probs.items():
                q = self._clamp(prob, 0.01, 0.99)
                loss = -(y * math.log(q) + (1 - y) * math.log(1 - q))
                self.weights[name] = self._clamp(
                    self.weights[name] * math.exp(-self.lr * (loss - 0.693)), 0.15, 3.0
                )
                predicted_bit = expert_sides.get(name, 1 if prob >= 0.5 else 0)
                acc = self.rolling_accuracy[name]
                acc.append(predicted_bit == y)
                # Rolling accuracy là tín hiệu chậm; chỉ điều chỉnh nhẹ để tránh weight dao động.
                rolling = sum(acc) / len(acc)
                if rolling < 0.45:
                    self.weights[name] = self._clamp(self.weights[name] * 0.7, 0.15, 3.0)
                elif rolling > 0.55:
                    self.weights[name] = self._clamp(self.weights[name] * 1.1, 0.15, 3.0)

            if self._last_confidence is not None and self._last_side is not None:
                # Lưu calibration của dự báo vừa được chấm; warmup không lọt vào mẫu calibration.
                self.calibration_history.append((int(self._last_confidence), self._last_side == y))
                self.calibration_history = self.calibration_history[-200:]

        # Tất cả expert đều nhận cùng context cũ; expert stateless vẫn giữ interface update().
        self.ngram.update(hist, y)
        self.streak.update(hist, y)
        self.anti_streak.update(hist, y)
        self.ema.update(hist, y)
        self.markov.update(hist, y)
        self.cycle.update(hist, y)
        self.volatility.update(hist, y)
        self.history.append(y)

        # CUSUM theo EMA trước khi cập nhật giúp phát hiện thay đổi regime mà không nhìn trước.
        surprise = -(y * math.log(prior_ema) + (1 - y) * math.log(1 - prior_ema))
        self.cusum = max(0.0, self.cusum + surprise - 0.693 - 0.08)

        if len(self.history) % 50 == 0:
            recent = self.losses[-50:]
            self.watchdog_count = (sum(recent) / len(recent)) if recent else 0.693
            if self.watchdog_count > 0.78:
                # Watchdog giảm đồng đều trọng số khi loss gần đây tăng cao.
                self.weights = {k: self._clamp(v * 0.90, 0.15, 3.0)
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
        """Dựng model bằng replay predict→observe theo thứ tự lịch sử thật."""
        return cls(history=history)

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        history = data.get("history", [])
        if not isinstance(history, list):
            history = []
        # Format cũ chỉ có history: replay đầy đủ để tái tạo expert và meta-state.
        engine = cls(history=history)
        saved_weights = data.get("expert_weights")
        if isinstance(saved_weights, dict):
            for name in cls.EXPERTS:
                try:
                    if name in saved_weights:
                        engine.weights[name] = engine._clamp(float(saved_weights[name]), 0.15, 3.0)
                except (TypeError, ValueError):
                    pass
        saved_calibration = data.get("calibration_history")
        if isinstance(saved_calibration, list):
            parsed = []
            for item in saved_calibration[-200:]:
                try:
                    conf, correct = item
                    parsed.append((int(engine._clamp(float(conf), 50, 85)), bool(correct)))
                except (TypeError, ValueError):
                    continue
            if parsed:
                engine.calibration_history = parsed
        return engine


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
