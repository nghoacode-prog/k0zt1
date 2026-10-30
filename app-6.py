#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PAWNOVA PREDICT API
Deploy: Render (gunicorn app:app)
Endpoints:
  GET /lc79/api/tx       → dự đoán bàn Hũ
  GET /lc79/api/md5      → dự đoán bàn MD5
  GET /lc79/api/tx/history   → lịch sử 10 phiên bàn Hũ
  GET /lc79/api/md5/history  → lịch sử 10 phiên bàn MD5
  GET /health            → status check
"""
import os, time, threading, json
from datetime import datetime
from flask import Flask, jsonify
import engine

app = Flask(__name__)

# ── CONFIG ────────────────────────────────────────────────────────
TUNNEL_BASE   = os.environ.get("PAW_TUNNEL_BASE", "http://180.93.102.202:5000").rstrip("/")
API_KEY       = os.environ.get("PAW_API_KEY", "")          # optional bearer auth
CACHE_TTL     = int(os.environ.get("PAW_CACHE_TTL", "28")) # giây cache mỗi endpoint
MAX_HISTORY   = 10                                          # số phiên lịch sử lưu

ENDPOINTS = {
    "tx":  TUNNEL_BASE + "/lc79/api/tx",
    "md5": TUNNEL_BASE + "/lc79/api/md5",
}

# ── CACHE ─────────────────────────────────────────────────────────
_cache: dict = {}       # key → {data, ts}
_lock = threading.Lock()

# ── PREDICTION HISTORY ────────────────────────────────────────────
# lưu tối đa MAX_HISTORY phiên gần nhất cho mỗi bàn
# format: {session_id, predicted, result(khi biết), win/lose, time}
_history: dict[str, list] = {"tx": [], "md5": []}
_last_session: dict[str, int | None] = {"tx": None, "md5": None}
_hist_lock = threading.Lock()

# ── HELPERS ───────────────────────────────────────────────────────
def _now_str():
    return datetime.now().strftime("%H:%M:%S %d/%m/%Y")

def _cached(key: str, ttl: int, fn):
    with _lock:
        entry = _cache.get(key)
        if entry and (time.time() - entry["ts"]) < ttl:
            return entry["data"], True
    data = fn()
    with _lock:
        _cache[key] = {"data": data, "ts": time.time()}
    return data, False

def _fetch_and_predict(game: str):
    url = ENDPOINTS[game]
    sessions = engine.fetch_sessions(url, timeout=4, retries=1, budget=10.0)
    if not sessions or len(sessions) < 5:
        return None, sessions

    runs = engine.get_runs([s["result"] for s in sessions])
    result = engine.ensemble_vote(runs)
    return result, sessions

def _update_history(game: str, sessions: list, pred: dict):
    """Cập nhật lịch sử: check win/lose phiên trước, thêm phiên mới."""
    if not sessions or not pred:
        return
    with _hist_lock:
        current_id = sessions[0]["id"]
        hist = _history[game]

        # Check win/lose cho phiên đã dự đoán trước đó
        session_map = {s["id"]: s["result"] for s in sessions}
        for entry in hist:
            if entry.get("outcome") is None:
                sid = entry.get("session_id")
                actual = session_map.get(sid)
                if actual:
                    correct = (actual == entry["predicted"])
                    entry["outcome"] = "win" if correct else "lose"
                    entry["actual"] = actual
                    engine.record_bot_result(correct)

        # Thêm phiên mới nếu chưa có
        if current_id != _last_session[game]:
            _last_session[game] = current_id
            new_entry = {
                "session_id": current_id,
                "predicted":  pred["prediction"],
                "confidence": pred["confidence"],
                "p_tai":      round(pred.get("p_tai", 0.5) * 100, 1),
                "p_xiu":      round((1 - pred.get("p_tai", 0.5)) * 100, 1),
                "outcome":    None,
                "actual":     None,
                "time":       _now_str(),
            }
            hist.append(new_entry)
            # Giữ tối đa MAX_HISTORY
            if len(hist) > MAX_HISTORY:
                _history[game] = hist[-MAX_HISTORY:]

def _build_response(game: str, pred: dict, sessions: list, cached: bool) -> dict:
    """Tạo JSON response chuẩn."""
    if not sessions:
        return {"ok": False, "error": "Không lấy được dữ liệu từ API nguồn", "game": game}

    current = sessions[0]
    prev5 = sessions[1:6]

    # Cầu gần nhất (5 phiên)
    cau = []
    for s in prev5:
        cau.append({
            "session_id": s["id"],
            "result": s["result"],
            "icon": "🔴 TÀI" if s["result"] == "TAI" else "🔵 XỈU",
            "dices": s.get("dices"),
            "point": s.get("point"),
        })

    if not pred:
        return {
            "ok": False,
            "error": "Chưa đủ dữ liệu để dự đoán (cần ≥15 phiên)",
            "game": game,
            "current_session": current["id"],
            "cau": cau,
        }

    p_tai = pred.get("p_tai", 0.5)
    prediction = pred["prediction"]
    confidence = pred["confidence"]

    return {
        "ok":            True,
        "game":          game,
        "cached":        cached,
        "timestamp":     _now_str(),
        "current_session": current["id"],
        "next_session":  current["id"] + 1,

        # ── KẾT QUẢ DỰ ĐOÁN ──────────────────────────────────
        "result":        prediction,
        "icon":          "🔴 TÀI" if prediction == "TAI" else "🔵 XỈU",
        "confidence":    confidence,
        "confidence_label": (
            "🔥 Rất cao" if confidence >= 75 else
            "✅ Cao"     if confidence >= 65 else
            "⚠️ Trung bình" if confidence >= 55 else
            "❓ Thấp"
        ),

        # ── XÁC SUẤT ─────────────────────────────────────────
        "probability": {
            "tai":  round(p_tai * 100, 1),
            "xiu":  round((1 - p_tai) * 100, 1),
        },

        # ── PHÂN TÍCH ─────────────────────────────────────────
        "analysis": {
            "state":      pred.get("state", "—"),
            "last_side":  pred.get("last_side", "—"),
            "last_len":   pred.get("last_len", 0),
            "p_break":    round((pred.get("p_break", 0.5)) * 100, 1),
            "stability":  round((pred.get("stability", 0.5)) * 100, 1),
            "modules":    pred.get("n_votes", 0),
            "reasons":    (pred.get("reasons") or [])[:4],
        },

        # ── CẦU GẦN NHẤT ──────────────────────────────────────
        "recent":        cau,
        "sample_size":   len(sessions),
    }

def _build_history_response(game: str) -> dict:
    with _hist_lock:
        hist = list(reversed(_history[game]))  # mới nhất trước

    rows = []
    win = lose = pending = 0
    for h in hist:
        outcome = h.get("outcome")
        if outcome == "win":
            icon = "✅ WIN"; win += 1
        elif outcome == "lose":
            icon = "❌ LOSE"; lose += 1
        else:
            icon = "⏳ Chờ"; pending += 1
        rows.append({
            "session_id": h["session_id"],
            "predicted":  h["predicted"],
            "predicted_icon": "🔴 TÀI" if h["predicted"] == "TAI" else "🔵 XỈU",
            "confidence": h["confidence"],
            "p_tai":      h["p_tai"],
            "p_xiu":      h["p_xiu"],
            "actual":     h.get("actual"),
            "outcome":    outcome,
            "outcome_icon": icon,
            "time":       h["time"],
        })

    total_decided = win + lose
    winrate = round(win / total_decided * 100, 1) if total_decided > 0 else None

    return {
        "ok":      True,
        "game":    game,
        "summary": {
            "total":   len(rows),
            "win":     win,
            "lose":    lose,
            "pending": pending,
            "winrate": winrate,
            "winrate_label": f"{winrate}%" if winrate is not None else "Chưa có",
        },
        "history": rows,
    }

# ── ROUTES ────────────────────────────────────────────────────────

def _predict_route(game: str):
    def _do():
        pred, sessions = _fetch_and_predict(game)
        _update_history(game, sessions or [], pred)
        return _build_response(game, pred, sessions or [], False)

    data, from_cache = _cached(f"pred_{game}", CACHE_TTL, _do)
    return jsonify(data)

@app.route("/lc79/api/tx")
def route_tx():
    return _predict_route("tx")

@app.route("/lc79/api/md5")
def route_md5():
    return _predict_route("md5")

@app.route("/lc79/api/tx/history")
def route_tx_history():
    return jsonify(_build_history_response("tx"))

@app.route("/lc79/api/md5/history")
def route_md5_history():
    return jsonify(_build_history_response("md5"))

@app.route("/health")
def health():
    return jsonify({
        "ok":        True,
        "time":      _now_str(),
        "tunnel":    TUNNEL_BASE,
        "cache_ttl": CACHE_TTL,
        "history":   {g: len(v) for g, v in _history.items()},
    })

@app.route("/")
def index():
    return jsonify({
        "service": "PAWNOVA Predict API",
        "endpoints": {
            "tx_predict":   "/lc79/api/tx",
            "md5_predict":  "/lc79/api/md5",
            "tx_history":   "/lc79/api/tx/history",
            "md5_history":  "/lc79/api/md5/history",
            "health":       "/health",
        }
    })

# ── MAIN ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
