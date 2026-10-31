#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PAWNOVA PREDICT API
Endpoints:
  GET /lc79/api/tx           → dự đoán bàn Hũ
  GET /lc79/api/md5          → dự đoán bàn MD5
  GET /lc79/api/tx/history   → lịch sử 10 phiên bàn Hũ
  GET /lc79/api/md5/history  → lịch sử 10 phiên bàn MD5
  GET /health                → status
"""
import os, time, threading
from datetime import datetime
from flask import Flask, jsonify
import engine

app = Flask(__name__)

# ── CONFIG ────────────────────────────────────────────────────────
TUNNEL_BASE = os.environ.get("PAW_TUNNEL_BASE", "http://180.93.102.202:5000").rstrip("/")
CACHE_TTL   = int(os.environ.get("PAW_CACHE_TTL", "28"))
MAX_HISTORY = 10

ENDPOINTS = {
    "tx":  TUNNEL_BASE + "/lc79/api/tx",
    "md5": TUNNEL_BASE + "/lc79/api/md5",
}

# ── CACHE ─────────────────────────────────────────────────────────
_cache: dict = {}
_lock = threading.Lock()

# ── HISTORY ───────────────────────────────────────────────────────
_history: dict[str, list] = {"tx": [], "md5": []}
_last_sid: dict[str, int | None] = {"tx": None, "md5": None}
_hist_lock = threading.Lock()

def _now():
    return datetime.now().strftime("%H:%M:%S %d/%m/%Y")

def _cached(key, ttl, fn):
    with _lock:
        e = _cache.get(key)
        if e and (time.time() - e["ts"]) < ttl:
            return e["data"], True
    data = fn()
    with _lock:
        _cache[key] = {"data": data, "ts": time.time()}
    return data, False

# ── UPDATE HISTORY ────────────────────────────────────────────────
def _update_history(game: str, sessions: list, pred: dict):
    if not sessions or not pred: return
    sid = engine.get_session_id(sessions[0])
    smap = {}
    for s in sessions:
        k = engine.get_session_id(s)
        v = engine.parse_result(s)
        if k and v: smap[k] = v

    with _hist_lock:
        hist = _history[game]
        # Check win/lose phiên cũ
        for entry in hist:
            if entry["outcome"] is None:
                actual = smap.get(entry["session_id"])
                if actual:
                    entry["outcome"] = "win" if actual == entry["predicted"] else "lose"
                    entry["actual"]  = actual
        # Thêm phiên mới
        if sid and sid != _last_sid[game]:
            _last_sid[game] = sid
            hist.append({
                "session_id": sid,
                "predicted":  pred["prediction"],
                "confidence": pred["confidence"],
                "p_tai":      pred["p_tai"],
                "p_xiu":      pred["p_xiu"],
                "outcome":    None,
                "actual":     None,
                "time":       _now(),
            })
            if len(hist) > MAX_HISTORY:
                _history[game] = hist[-MAX_HISTORY:]

# ── BUILD RESPONSE ────────────────────────────────────────────────
def _build(game: str, sessions: list, pred: dict, cached: bool) -> dict:
    if not sessions:
        return {"ok": False, "error": "Không lấy được dữ liệu API nguồn", "game": game}
    if not pred:
        return {"ok": False, "error": "Không đủ dữ liệu dự đoán (cần ≥16 phiên)", "game": game}

    cur   = sessions[0]
    sid   = engine.get_session_id(cur)
    recent = []
    for s in sessions[1:6]:
        r = engine.parse_result(s)
        recent.append({
            "session_id": engine.get_session_id(s),
            "result":     r,
            "icon":       "🔴 TÀI" if r == "TAI" else "🔵 XỈU",
            "dices":      engine.get_dices(s),
            "point":      engine.get_point(s),
        })

    conf = pred["confidence"]
    return {
        "ok":              True,
        "game":            game,
        "cached":          cached,
        "timestamp":       _now(),
        "current_session": sid,
        "next_session":    (sid + 1) if sid else None,

        # ── KẾT QUẢ ──────────────────────────────────────────
        "result":          pred["prediction"],
        "icon":            "🔴 TÀI" if pred["prediction"] == "TAI" else "🔵 XỈU",
        "confidence":      conf,
        "confidence_label": (
            "🔥 Rất cao"    if conf >= 75 else
            "✅ Cao"        if conf >= 65 else
            "⚠️ Trung bình" if conf >= 58 else
            "❓ Thấp"
        ),

        # ── XÁC SUẤT ─────────────────────────────────────────
        "probability": {
            "tai":  pred["p_tai"],
            "xiu":  pred["p_xiu"],
        },

        # ── PHÂN TÍCH ─────────────────────────────────────────
        "reason":          pred["reason"],

        # ── CẦU GẦN NHẤT ──────────────────────────────────────
        "recent":          recent,
        "sample_size":     len(sessions),
    }

def _build_history(game: str) -> dict:
    with _hist_lock:
        hist = list(reversed(_history[game]))
    win = lose = pending = 0
    rows = []
    for h in hist:
        o = h["outcome"]
        if o == "win":   icon = "✅ WIN";  win += 1
        elif o == "lose":icon = "❌ LOSE"; lose += 1
        else:            icon = "⏳ Chờ";  pending += 1
        rows.append({
            "session_id":      h["session_id"],
            "predicted":       h["predicted"],
            "predicted_icon":  "🔴 TÀI" if h["predicted"] == "TAI" else "🔵 XỈU",
            "confidence":      h["confidence"],
            "p_tai":           h["p_tai"],
            "p_xiu":           h["p_xiu"],
            "actual":          h.get("actual"),
            "outcome":         o,
            "outcome_icon":    icon,
            "time":            h["time"],
        })
    total = win + lose
    return {
        "ok":      True,
        "game":    game,
        "summary": {
            "total":   len(rows),
            "win":     win,
            "lose":    lose,
            "pending": pending,
            "winrate": f"{round(win/total*100,1)}%" if total else "Chưa có",
        },
        "history": rows,
    }

# ── PREDICT ───────────────────────────────────────────────────────
def _predict(game: str):
    def _do():
        sessions = engine.fetch_sessions(ENDPOINTS[game])
        history  = engine.get_history(sessions)
        pred     = engine.predict_tai_xiu(history) if len(history) >= 16 else None
        _update_history(game, sessions, pred)
        return _build(game, sessions, pred, False)
    data, cached = _cached(f"pred_{game}", CACHE_TTL, _do)
    return jsonify(data)

# ── ROUTES ────────────────────────────────────────────────────────
@app.route("/lc79/api/tx")
def tx():       return _predict("tx")

@app.route("/lc79/api/md5")
def md5():      return _predict("md5")

@app.route("/lc79/api/tx/history")
def tx_hist():  return jsonify(_build_history("tx"))

@app.route("/lc79/api/md5/history")
def md5_hist(): return jsonify(_build_history("md5"))

@app.route("/health")
def health():
    return jsonify({
        "ok":        True,
        "time":      _now(),
        "tunnel":    TUNNEL_BASE,
        "cache_ttl": CACHE_TTL,
        "history":   {g: len(v) for g, v in _history.items()},
    })

@app.route("/")
def index():
    return jsonify({
        "service":   "PAWNOVA Predict API",
        "endpoints": {
            "tx":         "/lc79/api/tx",
            "md5":        "/lc79/api/md5",
            "tx_history": "/lc79/api/tx/history",
            "md5_history":"/lc79/api/md5/history",
            "health":     "/health",
        }
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
