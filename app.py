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
def _update_history_simple(game: str, phien: int, ket_qua: str, pred: dict):
    if not pred or not phien: return
    with _hist_lock:
        hist = _history[game]
        # Check win/lose phiên trước (phiên hiện tại = kết quả phiên trước đã dự đoán)
        for entry in hist:
            if entry["outcome"] is None and entry["session_id"] == phien:
                entry["outcome"] = "win" if ket_qua == entry["predicted"] else "lose"
                entry["actual"]  = ket_qua
        # Thêm dự đoán cho phiên tiếp theo
        next_phien = phien + 1
        if next_phien != _last_sid[game]:
            _last_sid[game] = next_phien
            hist.append({
                "session_id": next_phien,
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
def _build_simple(game, phien, tong, xuc_xac, tg, ket_qua, cau_str, full_history, pred) -> dict:
    # Cầu 5 phiên gần nhất để hiển thị
    recent_cau = []
    for c in cau_str[-5:]:
        cu = c.upper()
        if cu == "T":   recent_cau.append({"result": "TAI", "icon": "🔴 TÀI"})
        elif cu == "X": recent_cau.append({"result": "XIU", "icon": "🔵 XỈU"})
    recent_cau = list(reversed(recent_cau))

    if not pred:
        return {
            "ok":              False,
            "error":           "Chưa đủ 16 phiên lịch sử để dự đoán",
            "game":            game,
            "current_session": phien,
            "current_result":  ket_qua,
            "current_icon":    "🔴 TÀI" if ket_qua == "TAI" else "🔵 XỈU",
            "dices":           xuc_xac,
            "point":           tong,
            "recent":          recent_cau,
        }

    conf = pred["confidence"]
    return {
        "ok":              True,
        "game":            game,
        "timestamp":       _now(),

        # ── PHIÊN HIỆN TẠI ───────────────────────────────────
        "current_session": phien,
        "current_result":  ket_qua,
        "current_icon":    "🔴 TÀI" if ket_qua == "TAI" else "🔵 XỈU",
        "dices":           xuc_xac,
        "point":           tong,
        "time":            tg,

        # ── DỰ ĐOÁN PHIÊN TIẾP THEO ──────────────────────────
        "next_session":    phien + 1,
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
        "recent":          recent_cau,
        "cau_raw":         cau_str,
        "sample_size":     len(full_history),
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
        data = engine.fetch_data(ENDPOINTS[game])
        if not data:
            return {"ok": False, "error": "Không lấy được dữ liệu API nguồn", "game": game}

        # Parse thông tin phiên hiện tại
        phien    = int(data.get("phien", 0))
        tong     = data.get("tong")
        ket_qua  = engine.parse_ket_qua(str(data.get("ket_qua", "")))
        xuc_xac  = [data.get("xuc_xac1"), data.get("xuc_xac2"), data.get("xuc_xac3")]
        tg       = data.get("thoi_gian", "")

        # Parse lịch sử từ chuỗi cầu
        cau_str  = data.get("cau", "")
        history  = engine.parse_cau(cau_str)   # index 0 = mới nhất

        # Thêm kết quả hiện tại vào đầu nếu chưa có trong cầu
        full_history = [ket_qua] + history if history else [ket_qua]

        pred = engine.predict_tai_xiu(full_history) if len(full_history) >= 16 else None

        # Update history
        _update_history_simple(game, phien, ket_qua, pred)

        return _build_simple(game, phien, tong, xuc_xac, tg, ket_qua, cau_str, full_history, pred)
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
