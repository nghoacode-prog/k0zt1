# -*- coding: utf-8 -*-
"""LC79 deterministic prediction engine and SQLite persistence."""
from __future__ import annotations
import ast
import json
import math
import os
import sqlite3
import time
from collections import defaultdict
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
# Five deterministic experts
# ---------------------------------------------------------------------------
class NgramExpert:
    name = "ngram"
    def __init__(self, order=10): self.order, self.counts, self.global_counts = order, {}, [1.0, 1.0]
    def update(self, hist, y):
        self.global_counts[y] += 1
        for k in range(1, min(self.order, len(hist)) + 1):
            key = tuple(hist[-k:]); cell = self.counts.setdefault(key, [1.0, 1.0]); cell[y] += 1
    def predict(self, hist):
        for k in range(min(self.order, len(hist)), 0, -1):
            cell = self.counts.get(tuple(hist[-k:]))
            if cell and sum(cell) >= 3: return cell[1] / sum(cell), sum(cell)
        a, b = self.global_counts
        return b / (a + b), a + b

class StreakExpert:
    name = "streak"
    def __init__(self, max_len=10): self.max_len, self.counts = max_len, {}
    def update(self, hist, y):
        if not hist: return
        side = hist[-1]; run = 1
        for v in reversed(hist[:-1]):
            if v != side: break
            run += 1
        cell = self.counts.setdefault((side, min(run, self.max_len)), [1.0, 1.0])
        cell[0 if y == side else 1] += 1
    def predict(self, hist):
        if not hist: return .5, 1
        side = hist[-1]; run = 1
        for v in reversed(hist[:-1]):
            if v != side: break
            run += 1
        a, b = self.counts.get((side, min(run, self.max_len)), [1.0, 1.0])
        p_continue = a / (a + b)
        return (p_continue if side == 1 else 1-p_continue), a+b

class EMAExpert:
    name = "ema"
    def __init__(self, half_life=50): self.alpha = 1 - 0.5 ** (1 / half_life); self.value = .5
    def update(self, hist, y): self.value = self.alpha*y + (1-self.alpha)*self.value
    def predict(self, hist): return self.value, 1/self.alpha

class MarkovExpert:
    name = "markov"
    def __init__(self, order=1): self.order, self.counts = order, {}
    def update(self, hist, y):
        if len(hist) >= self.order:
            cell = self.counts.setdefault(tuple(hist[-self.order:]), [1.0, 1.0]); cell[y] += 1
    def predict(self, hist):
        if len(hist) < self.order: return .5, 1
        a,b = self.counts.get(tuple(hist[-self.order:]), [1.0,1.0]); return b/(a+b), a+b

class CycleExpert:
    name = "cycle"
    def __init__(self): self.counts = {}
    def update(self, hist, y):
        for period in range(2, 9):
            if len(hist) >= period:
                key = (period, tuple(hist[-period:]))
                cell = self.counts.setdefault(key, [1.0,1.0]); cell[y] += 1
    def predict(self, hist):
        candidates=[]
        for period in range(2,9):
            if len(hist)>=period:
                cell=self.counts.get((period,tuple(hist[-period:])))
                if cell: candidates.append((cell[1]/sum(cell),sum(cell)))
        if not candidates: return .5,1
        return max(candidates,key=lambda x:x[1])

class PredictionEngine:
    """Online ensemble. All state is reproducible by replaying history."""
    EXPERTS = ("ngram", "streak", "ema", "markov", "cycle")
    def __init__(self, history=None):
        self.history=[]; self.ngram=NgramExpert(10); self.streak=StreakExpert(10)
        self.ema=EMAExpert(50); self.markov=MarkovExpert(1); self.cycle=CycleExpert()
        self.weights={name:1.0 for name in self.EXPERTS}; self.lr=.10
        # losses là log-loss của ensemble theo từng phiên (không phải từng expert).
        self.losses=[]; self.cusum=0.0; self.watchdog_count=0
        self._last_probs=None; self._last_meta={}; self._last_ensemble_p=None
        # Replay đúng chuỗi: dự báo trước, quan sát kết quả sau.
        for y in list(history or []):
            self.predict()
            self.observe(int(y))
    def _experts(self): return {"ngram":self.ngram.predict(self.history),"streak":self.streak.predict(self.history),
        "ema":self.ema.predict(self.history),"markov":self.markov.predict(self.history),"cycle":self.cycle.predict(self.history)}
    @staticmethod
    def _logit(p): p=max(.01,min(.99,p)); return math.log(p/(1-p))
    @staticmethod
    def _sigmoid(x): return 1/(1+math.exp(-max(-20,min(20,x))))
    def predict(self, accuracy_100=.5, accuracy_500=.5):
        exp=self._experts(); n=len(self.history)
        # R1: bounded sliding window (the experts use only the latest 2,000 observations).
        # R2: multi-timeframe reliability adjustment.
        a100=max(.35,min(.65,accuracy_100)); a500=max(.35,min(.65,accuracy_500))
        timeframe=(a100*.65+a500*.35)
        eta=.10/math.sqrt(max(1,n/100))
        self.lr=eta
        # R3: diversity — disagreement is retained, but weak experts are damped.
        sides=[1 if p>=.5 else 0 for p,_ in exp.values()]
        diversity=len(set(sides))
        raw_weights={k:max(.15,self.weights[k]) for k in self.EXPERTS}
        if diversity<=1 and n>=100:
            raw_weights={k:v*.92 for k,v in raw_weights.items()}
        # R4: adaptive learning rate, modulated by multi-timeframe accuracy.
        weighted=sum(raw_weights[k]*self._logit(exp[k][0]) for k in self.EXPERTS)/sum(raw_weights.values())
        p=self._sigmoid(weighted)
        p=.5+(p-.5)*(0.85+0.30*(timeframe-.5))
        # R5 watchdog state: after 50-observation checks, temper confidence during poor calibration.
        if self.watchdog_count and self.watchdog_count > .78: p=.5+(p-.5)*.75
        # R6 CUSUM regime alarm tempers stale edge.
        if self.cusum>2.5: p=.5+(p-.5)*.65
        # R7 confidence clamp based on model age; confidence is always integer 58..72.
        side="TAI" if p>=.5 else "XIU"; edge=abs(p-.5)*2
        age_cap=.30 if n<100 else (.50 if n<500 else (.70 if n<2000 else .90))
        edge=min(edge,age_cap)
        confidence=max(58,min(72,int(round(58+14*edge))))
        self._last_probs={k:v[0] for k,v in exp.items()}
        self._last_ensemble_p=p
        self._last_meta={"weights":raw_weights,"probability":p,"diversity":diversity,"eta":eta}
        return {"side":side,"confidence":confidence,"p_internal":p,"experts":exp,"weights":raw_weights}
    def observe(self, result):
        y=1 if int(result)==1 else 0
        hist=self.history[-2000:]
        probs=self._last_probs
        # Đo log-loss bằng xác suất đã phát ra TRƯỚC khi biết kết quả.
        prior_ema=max(.05,min(.95,self.ema.value))
        if self._last_ensemble_p is not None:
            ep=max(.01,min(.99,self._last_ensemble_p))
            ensemble_loss=-(y*math.log(ep)+(1-y)*math.log(1-ep))
            self.losses.append(ensemble_loss)
            self.losses=self.losses[-500:]
        if probs:
            # Exponential/log-loss expert weighting, deterministic and bounded.
            for name,p in probs.items():
                q=max(.01,min(.99,p))
                loss=-(y*math.log(q)+(1-y)*math.log(1-q))
                self.weights[name]=max(.15,min(3.0,self.weights[name]*math.exp(-self.lr*(loss-.693))))
        # Update predictors from pre-observation context.
        self.ngram.update(hist,y); self.streak.update(hist,y); self.ema.update(hist,y)
        self.markov.update(hist,y); self.cycle.update(hist,y)
        self.history.append(y)
        # R1: khi vượt 2.000 phiên, tái dựng năm chuyên gia trên cửa sổ 2.000 phiên gần nhất.
        if len(self.history) > 2000:
            window = self.history[-2000:]
            self.ngram=NgramExpert(10); self.streak=StreakExpert(10)
            self.ema=EMAExpert(50); self.markov=MarkovExpert(1); self.cycle=CycleExpert()
            replay=[]
            for value in window:
                self.ngram.update(replay,value); self.streak.update(replay,value)
                self.ema.update(replay,value); self.markov.update(replay,value)
                self.cycle.update(replay,value); replay.append(value)
        # CUSUM dùng xác suất EMA trước khi cập nhật phiên hiện tại.
        surprise=-(y*math.log(prior_ema)+(1-y)*math.log(1-prior_ema))
        self.cusum=max(0.0,self.cusum + surprise - .693 - .08)
        if len(self.history)%50==0:
            recent=self.losses[-50:]
            self.watchdog_count=(sum(recent)/len(recent)) if recent else .693
            if self.watchdog_count>0.78:
                self.weights={k:max(.15,v*.90) for k,v in self.weights.items()}
        self._last_probs=None
        self._last_ensemble_p=None
    def to_dict(self): return {"history":list(self.history)}
    @classmethod
    def from_dict(cls, data):
        if not isinstance(data,dict): return cls()
        return cls(data.get("history",[]))

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
