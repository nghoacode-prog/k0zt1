#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PAWNOVA ENGINE — Thuật toán dự đoán Tài Xỉu
"""
import os, requests, socket
from math import log2

socket.setdefaulttimeout(5.0)

_TUNNEL_BASE = os.environ.get("PAW_TUNNEL_BASE", "http://180.93.102.202:5000").rstrip("/")
HEADERS = {"User-Agent": "Mozilla/5.0", "Origin": "https://lc79b.bet"}

_N    = 16
_FLIP = {"TAI": "XIU", "XIU": "TAI"}

# ── THUẬT TOÁN ────────────────────────────────────────────────────

def _ema(history, period=5):
    if not history: return 0.5
    mul = 2.0 / (period + 1)
    ema = 1.0 if history[0] == "TAI" else 0.0
    for r in history[1:]:
        ema = ((1.0 if r == "TAI" else 0.0) - ema) * mul + ema
    return ema

def _entropy(history):
    p = history.count("TAI") / len(history)
    if p in (0.0, 1.0): return 0.0
    return -(p * log2(p) + (1 - p) * log2(1 - p))

def _streak(history):
    last, s = history[-1], 1
    for i in range(len(history) - 2, -1, -1):
        if history[i] != last: break
        s += 1
    return s

def predict_tai_xiu(history):
    """
    Nhận list 16 kết quả ["TAI"/"XIU"] gần nhất (index 0 = mới nhất).
    Trả về dict: prediction, confidence, reason, p_tai, p_xiu.
    """
    if len(history) < _N or any(h not in _FLIP for h in history):
        return {
            "prediction": "TAI", "confidence": 58.0,
            "p_tai": 58.0, "p_xiu": 42.0,
            "reason": "invalid_input"
        }

    h     = history[:_N]
    ent   = _entropy(h)
    ema   = _ema(h, period=5)
    stk   = _streak(h)
    last  = h[0]

    if ent > 0.95:
        pred       = _FLIP[last]
        confidence = 58.0 + (stk * 1.5)
        reason     = f"Chaos(Entropy={ent:.2f}) → Mean_Reversion"
    else:
        if ema > 0.55:
            if stk >= 4:
                pred   = _FLIP[last]
                reason = f"Trend={last} Streak={stk} → Break"
            else:
                pred   = last
                reason = f"Trend={last}(EMA={ema:.2f}) → Follow"
        elif ema < 0.45:
            if stk >= 4:
                pred   = _FLIP[last]
                reason = f"Trend={last} Streak={stk} → Break"
            else:
                pred   = _FLIP[last]
                reason = f"Trend={last}(EMA={ema:.2f}) → Counter"
        else:
            pred   = _FLIP[last] if stk >= 3 else last
            reason = f"Neutral(EMA={ema:.2f}) → {'Break' if stk>=3 else 'Follow'}"

        ts         = abs(ema - 0.5) * 2
        confidence = 58.0 + (ts * 12.0) + ((1.0 - ent) * 5.0) + (1.0 if stk >= 3 else 0.0)

    confidence = round(max(58.0, min(78.0, confidence)), 2)
    p_tai      = round(confidence if pred == "TAI" else 100 - confidence, 1)
    p_xiu      = round(100 - p_tai, 1)

    return {
        "prediction": pred,
        "confidence": confidence,
        "p_tai":      p_tai,
        "p_xiu":      p_xiu,
        "reason":     f"{reason} | H={ent:.2f} | EMA={ema:.2f} | Streak={stk}",
    }

# ── FETCH DATA ────────────────────────────────────────────────────

def fetch_data(url: str, timeout=5, retries=2) -> dict | None:
    """Fetch 1 phiên hiện tại từ API nguồn."""
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == retries - 1:
                print(f"[engine] fetch_data fail: {e}")
    return None

def parse_cau(cau_str: str) -> list[str]:
    """
    Parse chuỗi cầu "TXXXTXTXTXXXTXX" → ["TAI","XIU","XIU",...]
    T = TÀI, X = XỈU, mới nhất ở cuối → reverse để index 0 = mới nhất
    """
    result = []
    for c in cau_str.upper():
        if c == "T":   result.append("TAI")
        elif c == "X": result.append("XIU")
    return list(reversed(result))  # index 0 = mới nhất

def parse_ket_qua(s: str) -> str:
    """'Tài' hoặc 'Xỉu' → 'TAI'/'XIU'"""
    s = s.lower()
    if "t" in s and "x" not in s: return "TAI"
    return "XIU"
