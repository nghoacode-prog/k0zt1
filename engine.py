#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PAWNOVA V8 PRO — independent pattern ensemble; preserves public API contract.
import requests
import math
import unicodedata
from collections import Counter
from statistics import mode
import os
import json as _json
import socket
# FIX: DNS resolution trên Render có thể treo vô hạn (không respect timeout của requests).
# Set socket default timeout để cả DNS + connect đều fail sau 8s.
socket.setdefaulttimeout(4.0)

# All provider feeds use the single Cloudflare API domain supplied by the owner.
# Keep the base URL configurable so it can be changed without editing code.
_TUNNEL_BASE = os.environ.get("PAW_TUNNEL_BASE", "http://180.93.102.202:5000").rstrip("/")
HU_API_URL = _TUNNEL_BASE + "/lc79/api/tx"
API_URL = _TUNNEL_BASE + "/lc79/api/md5"
MAX_HU_API_URL = _TUNNEL_BASE + "/max789/api/tx"
MAX_MD5_API_URL = _TUNNEL_BASE + "/max789/api/md5"

# Older providers remain on the same Cloud API domain.
GAME_SOURCES = {
    "68gb_hu": _TUNNEL_BASE + "/68tx/api/tx",
    "68gb_md5": _TUNNEL_BASE + "/68md5/api/md5",
    "b52_hu": _TUNNEL_BASE + "/b52/api/tx",
    "b52_md5": _TUNNEL_BASE + "/b52/api/md5",
    "hitclub_hu": _TUNNEL_BASE + "/hitclub/api/tx",
    "hitclub_md5": _TUNNEL_BASE + "/hitclub/api/md5",
    "betvip_hu": _TUNNEL_BASE + "/betvip/api/tx",
    "betvip_md5": _TUNNEL_BASE + "/betvip/api/md5",
}

# Every exposed game/table is mapped to its exact Cloud API endpoint.
GAME_API_URLS = {
    **GAME_SOURCES,
    "hu": HU_API_URL,
    "md5": API_URL,
    "max_hu": MAX_HU_API_URL,
    "max_md5": MAX_MD5_API_URL,
    "789club": _TUNNEL_BASE + "/789club/api/789",
    "sunwin": _TUNNEL_BASE + "/sunwin/api/tx",
}

GAME_LABELS = {
    "md5": "LC79 · MD5", "hu": "LC79 · Hũ",
    "max_md5": "MAX789 · MD5", "max_hu": "MAX789 · Hũ",
    "789club": "789CLUB · Hũ", "sunwin": "SUNWIN · Tài Xỉu",
    "68gb_hu": "68GB · Hũ", "68gb_md5": "68GB · MD5",
    "b52_hu": "B52 · Hũ", "b52_md5": "B52 · MD5",
    "hitclub_hu": "HITCLUB · Hũ", "hitclub_md5": "HITCLUB · MD5",
    "betvip_hu": "BETVIP · Hũ", "betvip_md5": "BETVIP · MD5",
}

HEADERS = {"User-Agent": "Mozilla/5.0", "Origin": "https://lc79b.bet"}

_STATE_FILE = os.environ.get("PAWNOVA_ENGINE_STATE_PATH") or ("/data/paw_state.json" if os.path.isdir("/data") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "paw_state.json"))

def _load_state():
    global _BOT_HISTORY, _MODULE_SCORES, _PRED_HISTORY, _BMA_STATE, _PRED_BY_GAME
    try:
        if os.path.exists(_STATE_FILE):
            with open(_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
            history = d.get("bot_history", [])
            scores = d.get("module_scores", {})
            if isinstance(history, list):
                _BOT_HISTORY = [1 if x else 0 for x in history[-200:]]
            if isinstance(scores, dict):
                _MODULE_SCORES = {
                    str(k): {"wins": max(0, int(v.get("wins", 0))), "total": max(0, int(v.get("total", 0)))}
                    for k, v in scores.items() if isinstance(v, dict)
                }
            ph = d.get("pred_history", [])
            if isinstance(ph, list):
                _PRED_HISTORY = [x for x in ph[-100:] if x in ("TAI", "XIU")]
            pg = d.get("pred_by_game", {})
            if isinstance(pg, dict):
                _PRED_BY_GAME = {str(k): [x for x in v[-100:] if x in ("TAI", "XIU")]
                                 for k, v in pg.items() if isinstance(v, list)}
            sb = d.get("single_buf", {})
            if isinstance(sb, dict):
                for u, recs in sb.items():
                    if isinstance(recs, list):
                        _SINGLE_BUF[str(u)] = {int(r["id"]): r for r in recs if isinstance(r, dict) and "id" in r}
            bm = d.get("bma", {})
            if isinstance(bm, dict):
                _BMA_STATE = {str(k): v for k, v in bm.items() if isinstance(v, dict)}
    except Exception:
        pass

def _save_state():
    try:
        os.makedirs(os.path.dirname(_STATE_FILE) or ".", exist_ok=True)
        tmp = _STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump({"bot_history": _BOT_HISTORY[-200:], "module_scores": _MODULE_SCORES, "pred_history": _PRED_HISTORY[-100:], "bma": _BMA_STATE, "pred_by_game": _PRED_BY_GAME, "single_buf": {u: list(b.values()) for u, b in _SINGLE_BUF.items()}}, f)
        os.replace(tmp, _STATE_FILE)
    except Exception:
        pass

def fetch_sessions(api_url=None, timeout=3, retries=1, budget=12.0):
    import json
    import time
    _t0 = time.time()
    errors = []
    from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl, urlencode
    source_url = api_url or API_URL
    parts = urlsplit(source_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["_paw_ts"] = str(int(time.time() * 1000))
    fresh_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    encoded = quote(fresh_url, safe="")
    candidates = [
        ("direct", fresh_url, False),
        ("allorigins_raw", "https://api.allorigins.win/raw?url=" + encoded, False),
        ("allorigins_get", "https://api.allorigins.win/get?url=" + encoded, True),
        ("codetabs", "https://api.codetabs.com/v1/proxy?quest=" + encoded, False),
        ("corsproxy", "https://corsproxy.io/?url=" + encoded, False),
    ]
    last_error = None
    for attempt in range(max(1, int(retries))):
        for proxy_name, request_url, wrapped in candidates:
            if time.time() - _t0 > budget:
                break
            try:
                response = requests.get(request_url, timeout=timeout, headers={"User-Agent": HEADERS.get("User-Agent", "Mozilla/5.0"), "Accept": "application/json,text/plain,*/*"})
                response.raise_for_status()
                data = response.json()
                if wrapped:
                    contents = data.get("contents") if isinstance(data, dict) else None
                    if not isinstance(contents, str) or not contents.strip():
                        raise ValueError("AllOrigins GET thiếu trường contents")
                    data = json.loads(contents)
                raw = data
                # Some game bridges return one current-session object plus a T/X history string.
                # Expand that history into ordered records so the engine has enough samples.
                if isinstance(raw, dict) and not any(isinstance(raw.get(k), (list, dict)) for k in ("list", "htr", "data", "sessions", "history", "results", "result", "records", "items")):
                    history = raw.get("cau") or raw.get("Cau") or raw.get("historyString")
                    current_id = next((raw.get(k) for k in ("phien", "id", "sid", "SessionId", "issue") if raw.get(k) is not None), None)
                    if isinstance(history, str) and current_id is not None and len(history.strip()) >= 2:
                        seq = [ch for ch in history.upper() if ch in ("T", "X")]
                        try:
                            end_id = int(float(str(current_id).strip()))
                            raw = [{"id": end_id - len(seq) + i + 1, "result": ("TAI" if ch == "T" else "XIU")} for i, ch in enumerate(seq)]
                        except (TypeError, ValueError, OverflowError):
                            pass
                _single = False
                if isinstance(raw, dict) and not any(isinstance(raw.get(k), (list, dict)) for k in ("list", "htr", "data", "sessions", "history", "results", "result", "records", "items")):
                    if any(raw.get(k) is not None for k in ("id", "sid", "phien", "SessionId", "issue")):
                        raw = [raw]; _single = True
                if isinstance(raw, dict):
                    for _ in range(4):
                        if isinstance(raw, list): break
                        if not isinstance(raw, dict): break
                        _next = None
                        for _key in ("list", "htr", "data", "sessions", "history", "results", "result", "records", "items"):
                            _candidate = raw.get(_key)
                            if isinstance(_candidate, list):
                                _next = _candidate
                                break
                            if isinstance(_candidate, dict):
                                _next = _candidate
                                break
                        if _next is None: break
                        raw = _next
                if not isinstance(raw, list):
                    raise ValueError("API response has no session list (expected list/htr/data/sessions)")
                out = []
                seen = set()
                for it in raw:
                    if not isinstance(it, dict): continue
                    try:
                        raw_id = next((it.get(k) for k in ("id", "sid", "phien", "SessionId", "session", "roundId", "issue") if it.get(k) is not None), None)
                        if raw_id is None: continue
                        sid = int(float(str(raw_id).strip()))
                        dice = it.get("dices", it.get("xuc_xac", it.get("dice")))
                        if not (isinstance(dice, (list, tuple)) and len(dice) == 3):
                            direct_dice = [it.get("xuc_xac1"), it.get("xuc_xac2"), it.get("xuc_xac3")]
                            if all(v is not None for v in direct_dice): dice = direct_dice
                        if not (isinstance(dice, (list, tuple)) and len(dice) == 3):
                            max_dice = [it.get("d1", it.get("FirstDice")), it.get("d2", it.get("SecondDice")), it.get("d3", it.get("ThirdDice"))]
                            if all(v is not None for v in max_dice): dice = max_dice
                        raw_sum = next((it.get(k) for k in ("point", "DiceSum", "tong", "Tong", "total", "sum") if it.get(k) is not None), None)
                        if raw_sum is None and isinstance(dice, (list, tuple)) and len(dice) == 3:
                            try:
                                _dice_sum = sum(int(v) for v in dice)
                                if all(1 <= int(v) <= 6 for v in dice): raw_sum = _dice_sum
                            except (TypeError, ValueError, OverflowError): pass
                        # MAX789 trả kết quả trong BetSide; ưu tiên các trường kết quả chuẩn,
                        # sau đó mới dùng BetSide làm fallback.
                        side = next((normalized for raw_side in (
                            it.get("resultTruyenThong"), it.get("result"), it.get("ket_qua"),
                            it.get("side"), it.get("resultText"), it.get("outcome"), it.get("BetSide")
                        ) if (normalized := normalize_side(raw_side))), None)
                        if side is None and raw_sum is not None:
                            try:
                                total = int(raw_sum)
                                if 4 <= total <= 10: side = "XIU"
                                elif 11 <= total <= 17: side = "TAI"
                            except (TypeError, ValueError): pass
                        if side not in ("TAI", "XIU") or sid in seen: continue
                        rec = {"id": sid, "result": side}
                        if isinstance(dice, (list, tuple)) and len(dice) == 3:
                            try:
                                vals = [int(v) for v in dice]
                                if all(1 <= v <= 6 for v in vals):
                                    rec["dices"] = vals
                                    try: rec["point"] = int(raw_sum if raw_sum is not None else sum(vals))
                                    except (TypeError, ValueError): rec["point"] = sum(vals)
                            except (TypeError, ValueError, OverflowError): pass
                        out.append(rec)
                        seen.add(sid)
                    except (TypeError, ValueError, OverflowError): continue
                if _single and out:
                    _buf = _SINGLE_BUF.setdefault(source_url, {})
                    for _r in out: _buf[_r["id"]] = _r
                    if len(_buf) > 500:
                        for _k in sorted(_buf)[:len(_buf) - 500]: _buf.pop(_k, None)
                    out = list(_buf.values())
                out.sort(key=lambda x: x["id"], reverse=True)
                if out: return out[:500]
                raise ValueError("API response contains no valid TAI/XIU sessions")
            except Exception as exc:
                last_error = "%s: %s: %s" % (proxy_name, type(exc).__name__, str(exc)[:100])
                errors.append(last_error)
        if attempt + 1 < max(1, int(retries)): time.sleep(0.5)
    global LAST_FETCH_ERROR
    LAST_FETCH_ERROR = (" | ".join(errors[:2]) if errors else None) or last_error or "No upstream candidates succeeded"
    return []

LAST_FETCH_ERROR = None
_SINGLE_BUF = {}  # url -> {id: record}; dùng khi API chỉ trả 1 phiên mỗi lần

def normalize_side(s):
    if s is None:
        return None
    s = unicodedata.normalize("NFD", str(s).upper().strip())
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    s = s.replace("Đ", "D").strip()
    if s in ("T", "TAI"):
        return "TAI"
    if s in ("X", "XIU"):
        return "XIU"
    return None

def get_runs(seq):
    if not seq:
        return []
    runs = []
    cur = seq[0]
    length = 1
    for i in range(1, len(seq)):
        if seq[i] == cur:
            length += 1
        else:
            runs.append((cur, length))
            cur = seq[i]
            length = 1
    runs.append((cur, length))
    return runs

def _opp(side):
    return "XIU" if side == "TAI" else "TAI"

def _runs_to_seq(runs):
    seq = []
    for side, L in runs:
        seq.extend([side] * L)
    return seq

def mod_lifecycle(runs):
    n = len(runs)
    if n < 5:
        return "UNKNOWN", 0, 0
    recent_lens = [r[1] for r in runs[-15:]]
    last_len = runs[-1][1]
    is_bet = last_len >= 3 and n >= 3
    is_khuon = False
    if n >= 6:
        l = [r[1] for r in runs[-6:]]
        if l[0] == l[2] == l[4] and l[1] == l[3] == l[5]:
            is_khuon = True
    try:
        typical = mode(recent_lens[:-1]) if len(recent_lens) > 1 else 1
    except Exception:
        typical = 1
    if last_len >= typical * 2 and last_len >= 4:
        return "MATURE", last_len, typical
    if last_len >= typical * 1.5 and last_len >= 3:
        return "MATURE", last_len, typical
    if last_len >= 2 and is_bet and n >= 4:
        return "CONFIRMED", last_len, typical
    if is_khuon:
        return "CONFIRMED", last_len, typical
    if n >= 5:
        return "FORMING", last_len, typical
    return "UNKNOWN", last_len, typical

def mod_break(runs):
    """FIXED: đếm reached/broke chính xác từ run list + điều chỉnh theo lifecycle."""
    n = len(runs)
    if n < 15:
        return 0.5, 0
    last_side, last_len = runs[-1]
    reached = broke = 0
    for i, (s, L) in enumerate(runs[:-1]):
        if s == last_side and L >= last_len:
            if i + 1 < n:
                reached += 1
                if runs[i + 1][0] != last_side:
                    broke += 1
    if reached < 3:
        return 0.5, reached
    p = (broke + 0.5) / (reached + 1)
    state, _, _ = mod_lifecycle(runs)
    if state == "MATURE":
        p = min(0.85, p + 0.10)
    elif state == "CONFIRMED":
        p = max(0.15, p - 0.05)
    return max(0.05, min(0.95, p)), reached

def mod_bias(runs):
    if len(runs) < 20:
        return 0.5, 0

    def pw(n):
        recent = runs[-n:]
        total = sum(r[1] for r in recent)
        if total < 8:
            return None, 0
        tai = sum(r[1] for r in recent if r[0] == "TAI")
        return tai / total, total

    p20, n20 = pw(min(20, len(runs)))
    p40, n40 = pw(min(40, len(runs)))
    p60, n60 = pw(min(60, len(runs)))
    vals, weights = [], []
    if p20 is not None:
        vals.append(p20); weights.append(0.50)
    if p40 is not None:
        vals.append(p40); weights.append(0.30)
    if p60 is not None:
        vals.append(p60); weights.append(0.20)
    if not vals:
        return 0.5, 0
    tw = sum(weights)
    return sum(v * w for v, w in zip(vals, weights)) / tw, n20 + n40 + n60

def mod_markov(runs):
    seq = _runs_to_seq(runs)
    n = len(seq)
    if n < 30:
        return 0.5, 0
    last = seq[-1]
    ct = cx = 0
    for i in range(n - 1):
        if seq[i] == last:
            if seq[i + 1] == "TAI":
                ct += 1
            else:
                cx += 1
    tot = ct + cx
    if tot < 5:
        return 0.5, tot
    p1 = (ct + 0.5) / (tot + 1)
    ct2 = cx2 = 0
    if n >= 3:
        ctx = tuple(seq[-2:])
        for i in range(n - 2):
            if tuple(seq[i:i + 2]) == ctx:
                if seq[i + 2] == "TAI":
                    ct2 += 1
                else:
                    cx2 += 1
    tot2 = ct2 + cx2
    p2 = (ct2 + 0.5) / (tot2 + 1) if tot2 >= 3 else p1
    return p1 * 0.4 + p2 * 0.6, tot + tot2

def mod_ngram(runs):
    seq = _runs_to_seq(runs)
    n = len(seq)
    if n < 40:
        return 0.5, 0
    results = []
    for L in [3, 4, 5]:
        if n < L + 10:
            continue
        ctx = tuple(seq[-L:])
        ct = cx = 0
        for i in range(n - L):
            if tuple(seq[i:i + L]) == ctx:
                decay = 0.5 + (i / max(1, n - L)) * 0.5
                if seq[i + L] == "TAI":
                    ct += decay
                else:
                    cx += decay
        tot = ct + cx
        if tot >= 3:
            p = (ct + 1) / (tot + 2)
            w = L * math.sqrt(min(tot, 20))
            results.append((p, w, tot))
    if not results:
        return 0.5, 0
    tw = sum(r[1] for r in results)
    return sum(r[0] * r[1] for r in results) / tw, sum(r[2] for r in results)

def mod_run_ngram(runs):
    n = len(runs)
    if n < 15:
        return 0.5, 0
    lens = [r[1] for r in runs]
    sides = [r[0] for r in runs]
    tt = tx = 0
    for L in [2, 3, 4]:
        if n < L + 3:
            continue
        ctx = tuple(lens[-L:])
        for i in range(n - L):
            if tuple(lens[i:i + L]) == ctx:
                if sides[i + L] == "TAI":
                    tt += 1
                else:
                    tx += 1
    tot = tt + tx
    if tot < 3:
        return 0.5, tot
    return (tt + 0.5) / (tot + 1), tot

def mod_cycle(runs):
    n = len(runs)
    if n < 12:
        return None
    lens = [r[1] for r in runs]
    for period in range(2, 9):
        if n < period * 3:
            continue
        recent = lens[-period * 3:]
        c1 = recent[:period]
        c2 = recent[period:period * 2]
        c3 = recent[period * 2:period * 3]
        if c1 == c2 == c3:
            return {"period": period, "cycle": c1, "next_side": _opp(runs[-1][0]), "confidence": 78}
    return None

def mod_symmetry(runs):
    n = len(runs)
    if n < 7:
        return None
    lens = [r[1] for r in runs]
    for span in [9, 7, 5]:
        if n < span:
            continue
        seg = lens[-span:]
        half = span // 2
        if seg[:half] == seg[half + 1:][::-1]:
            return {"span": span, "prediction": _opp(runs[-1][0]), "confidence": 68}
    return None

def mod_morph(runs):
    n = len(runs)
    if n < 5:
        return None
    recent = [r[1] for r in runs[-5:]]
    last_side = runs[-1][0]
    if recent[0] == 1 and recent[1] == 1 and recent[2] == 2:
        return {"prediction": last_side, "confidence": 62, "type": "1-1-2"}
    if recent[0] == 2 and recent[1] == 2 and recent[2] == 1:
        return {"prediction": last_side, "confidence": 62, "type": "2-2-1"}
    if recent[0] == 3 and recent[1] == 3 and recent[2] == 1:
        return {"prediction": last_side, "confidence": 62, "type": "3-3-1"}
    if recent[0] == 1 and recent[1] == 2 and recent[2] == 3:
        return {"prediction": last_side, "confidence": 60, "type": "1-2-3"}
    if recent[0] == 3 and recent[1] == 2 and recent[2] == 1:
        return {"prediction": last_side, "confidence": 60, "type": "3-2-1"}
    return None

def mod_entropy(runs):
    seq = _runs_to_seq(runs)
    if len(seq) < 60:
        return 0.5, 0

    def ent(s):
        if len(s) < 5:
            return 1.0
        p = s.count("TAI") / len(s)
        if p in (0, 1):
            return 0.0
        return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

    e20 = ent(seq[-20:])
    e60 = ent(seq[-60:])
    diff = e20 - e60
    last = seq[-1]
    if diff < -0.08:
        return (0.60 if last == "TAI" else 0.40), 60
    if diff > 0.08:
        return (0.45 if last == "TAI" else 0.55), 60
    return 0.5, 60

def mod_forecast(runs, window=3):
    n = len(runs)
    if n < 8:
        return []
    sig = tuple(r[1] for r in runs[-window:])
    matches = []
    for i in range(n - window - 1):
        cand = tuple(runs[i + j][1] for j in range(window))
        if cand == sig:
            idx = i + window
            if idx < n:
                matches.append(runs[idx][0])
    if len(matches) < 2:
        return []
    c = Counter(matches)
    tot = sum(c.values())
    return [{"side": s, "prob": n2 / tot, "count": n2} for s, n2 in c.most_common()]

def mod_1_1(runs):
    n = len(runs)
    if n < 6:
        return None
    lens = [r[1] for r in runs[-8:]]
    if len(lens) >= 6 and all(l == 1 for l in lens[-6:]):
        return {"prediction": _opp(runs[-1][0]), "confidence": 78, "type": "1-1"}
    ones = sum(1 for l in lens[-8:] if l == 1)
    if ones >= 6:
        return {"prediction": _opp(runs[-1][0]), "confidence": 72, "type": "1-1 weak"}
    return None

def mod_2_2(runs):
    n = len(runs)
    if n < 4:
        return None
    lens = [r[1] for r in runs[-6:]]
    if len(lens) >= 6 and all(l == 2 for l in lens[-6:]):
        return {"prediction": _opp(runs[-1][0]), "confidence": 82, "type": "2-2 strong"}
    if len(lens) >= 4 and all(l == 2 for l in lens[-4:]):
        return {"prediction": _opp(runs[-1][0]), "confidence": 78, "type": "2-2"}
    if len(lens) >= 3 and lens[-3] == 2 and lens[-2] == 2 and lens[-1] == 1:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "2-2 start"}
    return None

def mod_3_3(runs):
    n = len(runs)
    if n < 3:
        return None
    lens = [r[1] for r in runs[-6:]]
    if len(lens) >= 4 and lens[-4] == 3 and lens[-3] == 3 and lens[-2] == 3 and lens[-1] == 1:
        return {"prediction": runs[-1][0], "confidence": 72, "type": "3-3 start"}
    if len(lens) >= 3 and all(l == 3 for l in lens[-3:]):
        return {"prediction": _opp(runs[-1][0]), "confidence": 82, "type": "3-3"}
    if len(lens) >= 3 and lens[-3] == 3 and lens[-2] == 3 and lens[-1] == 2:
        return {"prediction": runs[-1][0], "confidence": 70, "type": "3-3 2/3"}
    return None

def mod_4_4(runs):
    n = len(runs)
    if n < 3:
        return None
    lens = [r[1] for r in runs[-5:]]
    if len(lens) >= 3 and all(l == 4 for l in lens[-3:]):
        return {"prediction": _opp(runs[-1][0]), "confidence": 82, "type": "4-4"}
    return None

def mod_1_2_1(runs):
    n = len(runs)
    if n < 5:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-3:] == [1, 2, 1]:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "1-2-1"}
    if lens[-4:] == [1, 2, 1, 2]:
        return {"prediction": runs[-1][0], "confidence": 72, "type": "1-2-1-2"}
    return None

def mod_211_112(runs):
    n = len(runs)
    if n < 4:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-3:] == [2, 1, 1]:
        return {"prediction": runs[-1][0], "confidence": 65, "type": "2-1-1"}
    if lens[-3:] == [1, 1, 2]:
        return {"prediction": runs[-1][0], "confidence": 65, "type": "1-1-2"}
    if lens[-4:] == [2, 1, 1, 2]:
        return {"prediction": runs[-1][0], "confidence": 72, "type": "2-1-1-2"}
    return None

def mod_322_232(runs):
    n = len(runs)
    if n < 4:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-3:] == [3, 2, 2]:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "3-2-2"}
    if lens[-3:] == [2, 3, 2]:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "2-3-2"}
    if lens[-3:] == [2, 2, 3]:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "2-2-3"}
    if lens[-3:] == [3, 3, 2]:
        return {"prediction": runs[-1][0], "confidence": 68, "type": "3-3-2"}
    return None

def mod_nghieng(runs):
    n = len(runs)
    if n < 4:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-4:] == [1, 2, 3, 4]:
        return {"prediction": _opp(runs[-1][0]), "confidence": 70, "type": "1-2-3-4"}
    if lens[-3:] == [1, 2, 3]:
        return {"prediction": runs[-1][0], "confidence": 62, "type": "1-2-3"}
    if lens[-3:] == [2, 3, 4]:
        return {"prediction": runs[-1][0], "confidence": 65, "type": "2-3-4"}
    return None

def mod_giam(runs):
    n = len(runs)
    if n < 4:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-4:] == [4, 3, 2, 1]:
        return {"prediction": _opp(runs[-1][0]), "confidence": 70, "type": "4-3-2-1"}
    if lens[-3:] == [4, 3, 2]:
        return {"prediction": runs[-1][0], "confidence": 65, "type": "4-3-2"}
    if lens[-3:] == [3, 2, 1]:
        return {"prediction": _opp(runs[-1][0]), "confidence": 65, "type": "3-2-1"}
    return None

def mod_2211(runs):
    n = len(runs)
    if n < 5:
        return None
    lens = [r[1] for r in runs[-6:]]
    if lens[-4:] == [2, 2, 1, 1]:
        return {"prediction": _opp(runs[-1][0]), "confidence": 68, "type": "2-2-1-1"}
    if lens[-4:] == [1, 1, 2, 2]:
        return {"prediction": _opp(runs[-1][0]), "confidence": 68, "type": "1-1-2-2"}
    return None

def mod_bat_thuong(runs):
    n = len(runs)
    if n < 5:
        return None
    lens = [r[1] for r in runs[-5:]]
    if lens[-4:] == [5, 1, 5, 1]:
        return {"prediction": runs[-1][0], "confidence": 62, "type": "5-1-5-1"}
    if lens[-4:] == [4, 1, 4, 1]:
        return {"prediction": runs[-1][0], "confidence": 62, "type": "4-1-4-1"}
    return None

BASE_TAI_RATE = 0.5
def _mod_alpha(seq, max_order=6, alpha=0.5, min_samples=3):
    n = len(seq)
    for order in range(min(max_order, n - 1), 0, -1):
        ctx = tuple(seq[-order:])
        ct = cx = 0
        for i in range(n - order):
            if tuple(seq[i:i + order]) == ctx:
                if seq[i + order] == "T":
                    ct += 1
                else:
                    cx += 1
        tot = ct + cx
        if tot >= min_samples:
            return (ct + alpha) / (tot + 2 * alpha), order, tot
    return 0.5, 0, 0

def _mod_beta(seq, window=40, a0=6.0, b0=6.0, decay=0.95):
    recent = seq[-window:]
    a, b = a0, b0
    L = len(recent)
    for i, r in enumerate(recent):
        w = decay ** (L - 1 - i)
        if r == "T":
            a += w
        else:
            b += w
    return a / (a + b)

def _mod_gamma(seq, max_lag=25):
    x = [1 if r == "T" else 0 for r in seq]
    n = len(x)
    if n < 10:
        return 0, 0.0
    mean = sum(x) / n
    var = sum((v - mean) ** 2 for v in x) / n
    if var == 0:
        return 0, 0.0
    best_lag, best_corr = 0, 0.0
    for lag in range(2, min(max_lag, n // 2)):
        cov = sum((x[i] - mean) * (x[i + lag] - mean) for i in range(n - lag)) / (n - lag)
        corr = cov / var
        if abs(corr) > abs(best_corr):
            best_corr, best_lag = corr, lag
    return best_lag, best_corr

def _mod_delta(seq):
    last = seq[-1]
    s = 1
    for i in range(len(seq) - 2, -1, -1):
        if seq[i] == last:
            s += 1
        else:
            break
    p, w = 0.5, 0.0
    if s >= 4:
        depth = min(0.30, 0.06 * (s - 3))
        p = (0.5 - depth) if last == "T" else (0.5 + depth)
        w = 1.5
    elif s == 1:
        p = 0.55 if last == "T" else 0.45
        w = 0.6
    return p, w, s, last

def _mod_epsilon(seq, window=20):
    recent = seq[-window:]
    return recent.count("T") / len(recent) if recent else 0.5

def _mod_zeta(seq, max_len=6, min_count=4):
    n = len(seq)
    best = (0.5, None, 0, 0)
    for length in range(2, min(max_len, n - 1) + 1):
        ctx = tuple(seq[-length:])
        ct = cx = 0
        for i in range(n - length):
            if tuple(seq[i:i + length]) == ctx:
                if seq[i + length] == "T":
                    ct += 1
                else:
                    cx += 1
        tot = ct + cx
        if tot >= min_count and length > best[3]:
            p = (ct + 0.5) / (tot + 1)
            best = (p, "".join(ctx), tot, length)
    return best[0], best[1], best[2]

def _mod_eta(seq, long_w=400, k=80):
    w = seq[-long_w:]
    n = len(w)
    if n < 50:
        return BASE_TAI_RATE
    return (w.count("T") + BASE_TAI_RATE * k) / (n + k)

def _mod_theta(seq):
    if len(seq) < 100:
        return "stable", 0.5, 0.5, 0.0
    recent = seq[-50:]
    old = seq[-200:-50]
    pr = recent.count("T") / len(recent)
    po = old.count("T") / len(old)
    diff = pr - po
    if diff > 0.10:
        return "tai_shift", pr, po, diff
    if diff < -0.10:
        return "xiu_shift", pr, po, diff
    return "stable", pr, po, diff

def _entropy(seq, window=50):
    recent = seq[-window:]
    if not recent:
        return 1.0
    p = recent.count("T") / len(recent)
    if p in (0.0, 1.0):
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

def _meta_weights(history, names, lookback=50):
    """FIX: kiểm tra isinstance(h, dict) để không crash khi history là list of int."""
    recent = [h for h in history[-lookback:] if isinstance(h, dict) and "signals" in h]
    if len(recent) < 10:
        return {n: 1.0 for n in names}
    correct = {n: 0 for n in names}
    total = {n: 0 for n in names}
    for h in recent:
        actual = h.get("actual")
        for s in h.get("signals", []):
            nm = s.get("name")
            if nm not in correct:
                continue
            pred = "TAI" if s.get("p_tai", 50) >= 50 else "XIU"
            total[nm] += 1
            if pred == actual:
                correct[nm] += 1
    weights = {}
    for n in names:
        t = total.get(n, 0)
        if t < 5:
            weights[n] = 1.0
        else:
            acc = correct[n] / t
            weights[n] = max(0.3, min(2.0, acc / 0.5))
    return weights

_BOT_HISTORY = []
_MODULE_SCORES = {}
_PRED_HISTORY = []
_PRED_BY_GAME = {}
_PRED_RECORDED = set()
_PRED_SKIP_LAST = {}
_PENDING_MODULES = {}
_BMA_STATE = {}
_PENDING_V7 = {}
_V7_PMAP = {}

def _record_prediction(side):
    """Ghi lai du doan de phat hien va tu sua nghieng 1 chieu."""
    if side in ("TAI", "XIU"):
        _PRED_HISTORY.append(side)
        if len(_PRED_HISTORY) > 100:
            del _PRED_HISTORY[:-100]

def _pred_bias_correction(p_tai, hist=None):
    """Neu 20 du doan gan day nghieng >60% ve 1 phia, keo p_tai ve trung lap.
    Cang lech cang keo manh, dam bao khong bi kẹt 1 huong.
    """
    h = _PRED_HISTORY if hist is None else hist
    if len(h) < 10:
        return p_tai
    recent = h[-20:]
    rate_tai = sum(1 for x in recent if x == "TAI") / len(recent)
    if rate_tai > 0.58:
        p_tai -= (rate_tai - 0.5) * 0.45
    elif rate_tai < 0.42:
        p_tai += (0.5 - rate_tai) * 0.45
    return p_tai

def record_module_result(module_name, correct):
    if not module_name:
        return
    score = _MODULE_SCORES.setdefault(str(module_name), {"wins": 0, "total": 0})
    score["total"] += 1
    if correct:
        score["wins"] += 1

def get_module_weight(module_name, default_weight):
    score = _MODULE_SCORES.get(module_name)
    if not score or score.get("total", 0) < 10:
        return default_weight
    rate = score["wins"] / max(1, score["total"])
    factor = max(0.5, min(1.5, 0.5 + rate))
    return default_weight * factor

def record_bot_result(correct):
    _BOT_HISTORY.append(1 if correct else 0)
    if len(_BOT_HISTORY) > 200:
        del _BOT_HISTORY[:-200]
    _save_state()

def mod_anti_flip():
    if len(_BOT_HISTORY) < 15:
        return 0, 0.0
    recent = _BOT_HISTORY[-20:]
    rate = sum(recent) / len(recent)
    if rate <= 0.35:
        return -1, rate
    if rate >= 0.65:
        return 1, rate
    return 0, rate

def mod_stability(votes):
    if len(votes) < 3:
        return 0.7
    probs = [v[0] for v in votes]
    mean = sum(probs) / len(probs)
    var = sum((p - mean) ** 2 for p in probs) / len(probs)
    std = math.sqrt(var)
    if std > 0.20:
        return 0.5
    if std > 0.12:
        return 0.75
    return 1.0

def _mature_signal(last_side, p_break):
    if p_break >= 0.60:
        p_tai = p_break if last_side == "XIU" else (1.0 - p_break)
        return p_tai, 1.8, "MATURE be %.0f%%" % (p_break * 100)
    if p_break <= 0.40:
        p_tai = (1.0 - p_break) if last_side == "TAI" else p_break
        return p_tai, 1.4, "MATURE theo %.0f%%" % (p_break * 100)
    return None

def _collect_all(runs):
    votes = []
    reasons = []
    modules_used = []
    state, last_len, typical = mod_lifecycle(runs)
    p_break, br_n = mod_break(runs)
    p_bias, bias_n = mod_bias(runs)
    if bias_n >= 40:
        effective_n = min(1.0, max(0.0, (bias_n - 30) / 70.0))
        p_bias = 0.5 + (p_bias - 0.5) * effective_n * 0.55
        if abs(p_bias - 0.5) >= 0.025:
            votes.append((p_bias, 0.65))
            modules_used.append("mod_bias")
            reasons.append("bias-adapt %.0f%% n%d" % (p_bias * 100, bias_n))
    p_mk, mk_n = mod_markov(runs)
    if mk_n >= 10:
        votes.append((p_mk, 1.0)); modules_used.append("mod_markov")
        reasons.append("markov n%d" % mk_n)
    p_ng, ng_n = mod_ngram(runs)
    if ng_n >= 5:
        votes.append((p_ng, 1.6)); modules_used.append("mod_ngram")
        reasons.append("ngram n%d" % ng_n)
    p_rn, rn_n = mod_run_ngram(runs)
    if rn_n >= 5:
        votes.append((p_rn, 1.3)); modules_used.append("mod_run_ngram")
        reasons.append("run-ngram n%d" % rn_n)
    p_et, _ = mod_entropy(runs)
    votes.append((p_et, 0.6)); modules_used.append("mod_entropy")
    if state == "MATURE":
        mature_vote = _mature_signal(runs[-1][0], p_break)
        if mature_vote:
            p_tai, weight, label = mature_vote
            votes.append((p_tai, weight)); modules_used.append("mod_mature")
            reasons.append(label)
    elif state == "CONFIRMED" and p_break <= 0.30 and last_len <= max(3, int(typical) + 1):
        last = runs[-1][0]
        votes.append((0.57 if last == "TAI" else 0.43, 0.65))
        modules_used.append("mod_confirmed")
        reasons.append("CONFIRMED theo; weak-weight, low-break evidence")
    cyc = mod_cycle(runs)
    if cyc:
        p = 0.68 if cyc["next_side"] == "TAI" else 0.32
        votes.append((p, 1.8)); modules_used.append("mod_cycle")
        reasons.append("cycle %d" % cyc["period"])
    sym = mod_symmetry(runs)
    if sym:
        p = 0.65 if sym["prediction"] == "TAI" else 0.35
        votes.append((p, 1.2)); modules_used.append("mod_symmetry")
        reasons.append("sym %d" % sym["span"])
    morph = mod_morph(runs)
    if morph:
        p = 0.60 if morph["prediction"] == "TAI" else 0.40
        votes.append((p, 1.6)); modules_used.append("mod_morph")
        reasons.append("morph %s" % morph["type"])
    fc = mod_forecast(runs)
    if fc:
        top = fc[0]
        p = top["prob"] if top["side"] == "TAI" else 1 - top["prob"]
        votes.append((p, 0.9)); modules_used.append("mod_forecast")
        reasons.append("fc %s %.0f%%" % (top["side"], top["prob"] * 100))
    pattern_votes = []
    for mod_fn, weight in [
        (mod_1_1, 2.2), (mod_2_2, 2.0), (mod_3_3, 2.0), (mod_4_4, 2.0),
        (mod_1_2_1, 1.5), (mod_211_112, 1.4), (mod_322_232, 1.4),
        (mod_nghieng, 1.3), (mod_giam, 1.3), (mod_2211, 1.5), (mod_bat_thuong, 1.0),
    ]:
        r = mod_fn(runs)
        if r:
            adaptive_w = get_module_weight(mod_fn.__name__, weight)
            p = 0.60 if r["prediction"] == "TAI" else 0.40
            pattern_votes.append((p, adaptive_w, mod_fn.__name__, r["type"]))
    if pattern_votes:
        total_w = sum(v[1] for v in pattern_votes)
        avg_p = sum(v[0] * v[1] for v in pattern_votes) / total_w
        votes.append((avg_p, total_w * 0.5))
        modules_used.extend(v[2] for v in pattern_votes)
        reasons.append("pattern-%d-mods %.0f%%" % (len(pattern_votes), avg_p * 100))
    return votes, reasons, state, last_len, p_break, modules_used

def ensemble_vote(runs):
    """Fallback ensemble (runs-based). Luôn trả prediction khi có history."""
    if not runs:
        return None
    seq = _runs_to_seq(runs)
    recent = seq[-60:]
    p_tai_fallback = (recent.count("TAI") + 1.0) / (len(recent) + 2.0)
    fallback_side = "TAI" if p_tai_fallback >= 0.5 else "XIU"
    fallback_conf = 50 + min(5, int(abs(p_tai_fallback - 0.5) * 20))
    if len(runs) < 15:
        return {
            "prediction": fallback_side, "confidence": fallback_conf, "p_tai": p_tai_fallback,
            "state": "LIMITED_HISTORY", "p_break": 0.5, "n_votes": 0, "modules_used": [],
            "reasons": ["fallback-frequency; limited run structure"], "flipped": False,
            "stability": 0.5, "last_side": runs[-1][0], "last_len": runs[-1][1],
        }
    votes, reasons, state, last_len, p_break, modules_used = _collect_all(runs)
    if not votes:
        return {
            "prediction": fallback_side, "confidence": fallback_conf, "p_tai": p_tai_fallback,
            "state": state, "p_break": p_break, "n_votes": 0, "modules_used": modules_used,
            "reasons": ["fallback-frequency; no active module votes"], "flipped": False,
            "stability": 0.5, "last_side": runs[-1][0], "last_len": last_len,
        }
    stab = mod_stability(votes)
    total_w = sum(max(0.0, float(v[1])) for v in votes)
    p_tai = sum(v[0] * max(0.0, float(v[1])) for v in votes) / total_w if total_w > 0 else p_tai_fallback
    anti, anti_rate = mod_anti_flip()
    flipped = False
    conf_boost = 2 if anti == 1 else 0
    if anti == -1:
        reasons.append("recent-hit-low %.0f%%" % (anti_rate * 100))
    p_tai = _pred_bias_correction(p_tai)
    p_tai = 0.5 + (p_tai - 0.5) * 0.75
    p_tai = max(0.35, min(0.65, p_tai))
    margin = abs(p_tai - 0.5)
    if margin < 0.005:
        recent8 = seq[-8:]
        p_tai_8 = (recent8.count("TAI") + 1.0) / (len(recent8) + 2.0)
        if abs(p_tai_8 - 0.5) >= 0.001:
            pred = "TAI" if p_tai_8 > 0.5 else "XIU"
            reasons.append("tie-break-smoothed-recent8 %.0f%%" % (p_tai_8 * 100))
        else:
            pred = fallback_side
            reasons.append("tie-break-smoothed-history")
    else:
        pred = "TAI" if p_tai > 0.5 else "XIU"
    conf = 50 + int(margin * 180 * stab) + conf_boost
    probs = [v[0] for v in votes]
    mean_p = sum(probs) / len(probs)
    var_p = sum((p - mean_p) ** 2 for p in probs) / len(probs)
    disagreement = math.sqrt(var_p)
    if disagreement > 0.20:
        conf -= min(8, int((disagreement - 0.20) * 40) + 1)
        reasons.append("module-disagreement %.2f" % disagreement)
    conf = min(68, max(50, conf))
    return {
        "prediction": pred, "confidence": conf, "p_tai": p_tai, "state": state,
        "p_break": p_break, "n_votes": len(votes), "modules_used": modules_used,
        "reasons": reasons, "flipped": flipped, "stability": stab,
        "last_side": runs[-1][0], "last_len": last_len,
    }

# ================== PAWNOVA V8 PRO ==================
def _v8_runs(seq):
    out=[]
    for side in seq:
        if out and out[-1][0] == side: out[-1]=(side,out[-1][1]+1)
        else: out.append((side,1))
    return out

def _v8_experts(rows):
    seq=[r['resultTruyenThong'] for r in rows]
    n=len(seq); runs=_v8_runs(seq); signals=[]
    def add(name, p, support, strength=1.0, note=''):
        if p is None or support < 2: return
        p=max(0.05,min(0.95,float(p)))
        # support is logarithmic so one apparent pattern cannot dominate the vote.
        weight=strength * min(1.0, support/8.0) * (0.55 + 0.45*min(1.0, support/20.0))
        signals.append({'name':name,'p_tai':p*100,'weight':weight,'support':int(support),'note':note})
    # 1) Markov transitions: P(next | last side), Laplace-smoothed.
    last=seq[-1]; nxt=[seq[i+1] for i in range(n-1) if seq[i]==last]
    if len(nxt)>=3: add('transition_1', (nxt.count('TAI')+1)/(len(nxt)+2),len(nxt),1.0,'last-side transition')
    # 2) Context n-grams, lengths 2..6; only historical occurrences are used.
    for order in range(2,7):
        if n <= order: continue
        ctx=tuple(seq[-order:]); outcomes=[]
        for i in range(n-order):
            if tuple(seq[i:i+order])==ctx: outcomes.append(seq[i+order])
        if len(outcomes)>=3:
            add('context_%d'%order,(outcomes.count('TAI')+1)/(len(outcomes)+2),len(outcomes),1.15,'context match')
    # 3) Run-length grammar: prior run-length contexts predict the next run side.
    lens=[x[1] for x in runs]; sides=[x[0] for x in runs]
    for order in (2,3,4):
        if len(runs)<=order: continue
        ctx=tuple(lens[-order:]); outcomes=[]
        for i in range(len(runs)-order):
            if tuple(lens[i:i+order])==ctx: outcomes.append(sides[i+order])
        if len(outcomes)>=3:
            add('run_grammar_%d'%order,(outcomes.count('TAI')+1)/(len(outcomes)+2),len(outcomes),1.15,'run-length grammar')
    # 4) Repeated run-length cycle (2..8); count historical repeats, do not assume it repeats.
    for period in range(2,9):
        if len(lens)<period*3: continue
        pat=tuple(lens[-period:]); hits=0; good=0
        for i in range(len(lens)-period):
            if tuple(lens[i:i+period])==pat:
                j=i+period
                if j < len(sides):
                    hits+=1; good += sides[j]=='TAI'
        if hits>=2:
            add('run_cycle_%d'%period,(good+1)/(hits+2),hits,0.9,'repeated run-length cycle')
    # 5) Alternation/flip rate conditional on the current recent regime.
    for window in (8,16,32,64):
        part=seq[-min(window,n):]
        if len(part)>=8:
            flips=sum(part[i]!=part[i-1] for i in range(1,len(part)))
            rate=(flips+1)/(len(part)+1)
            # If last transitions mostly flip, modestly favor opposite; if not, favor continuation.
            p_flip=max(0.05,min(0.95,rate))
            p_tai=p_flip*(1 if last=='XIU' else 0)+(1-p_flip)*(1 if last=='TAI' else 0)
            add('flip_rate_%d'%window,p_tai,len(part)-1,0.45,'recent flip rate %.2f'%rate)
    # 6) Streak survival: empirically estimate whether runs of this length continue.
    cur_side,cur_len=runs[-1]; continued=total=0
    # Historical decision points: the streak had reached exactly cur_len, and the next
    # observed result tells us whether that streak continued. Exclude the current endpoint.
    for i in range(cur_len-1, n-1):
        if seq[i] != cur_side: continue
        if i-cur_len+1 < 0 or any(x != cur_side for x in seq[i-cur_len+1:i+1]): continue
        if i-cur_len >= 0 and seq[i-cur_len] == cur_side: continue
        total += 1
        if seq[i+1] == cur_side: continued += 1
    if total>=3:
        p_continue=(continued+1)/(total+2)
        # For the next roll, continuation is the same side; this is evidence-based, not forced.
        add('streak_survival',p_continue if cur_side=='TAI' else 1-p_continue,total,0.8,'streak length %d; historical cases %d'%(cur_len,total))
    # 7) Short/medium/long frequency as a weak prior, not a dominant majority rule.
    for window,strength in ((8,0.35),(12,0.30),(16,0.20)):
        part=seq[-min(window,n):]
        if len(part)>=8:
            p=(part.count('TAI')+2)/(len(part)+4)
            add('frequency_%d'%window,p,len(part),strength,'smoothed marginal frequency')
    # 8) Change-point / regime comparison; only a gentle signal.
    if n>=40:
        recent=seq[-20:]; prior=seq[-min(100,n-20):-20]
        if len(prior)>=20:
            pr=(recent.count('TAI')+2)/(len(recent)+4)
            po=(prior.count('TAI')+2)/(len(prior)+4)
            delta=pr-po
            if abs(delta)>=0.08: add('regime_shift',max(.1,min(.9,.5+delta*.45)),len(recent),.45,'recent-vs-prior shift %.2f'%delta)
    return seq,runs,signals

def _v8_analyze(valid, game_key):
    if len(valid)<2: return None
    rows=valid[-16:]
    seq,runs,signals=_v8_experts(rows)
    if not signals:
        # Short-history fallback: descriptive recent balance only, heavily shrunk toward 50%.
        # Valid data still gets TAI/XIU, but 2-10 rows are weak evidence.
        recent = seq[-min(10, len(seq)):]
        p = (recent.count("TAI") + 1.0) / (len(recent) + 2.0)
        signals.append({"name": "short_window_prior", "p_tai": (0.5 + (p - 0.5) * 0.25) * 100,
                        "weight": 0.15, "support": len(recent), "note": "short history; low evidence"})
    # Evidence-weighted ensemble. Experts agreeing because of similar data are capped by
    # group (pattern, frequency, transition) so duplicated signals cannot create fake certainty.
    groups={
        'transition':('transition_1','context_2','context_3','context_4','context_5','context_6'),
        'runs':('run_grammar_2','run_grammar_3','run_grammar_4','run_cycle_2','run_cycle_3','run_cycle_4','run_cycle_5','run_cycle_6','run_cycle_7','run_cycle_8','streak_survival'),
        'regime':('flip_rate_8','flip_rate_16','flip_rate_32','flip_rate_64','regime_shift'),
        'frequency':('frequency_8','frequency_12','frequency_16','short_window_prior')}
    for sig in signals:
        sig['group']=next((g for g,names in groups.items() if sig['name'] in names),'other')
    group_totals={g:sum(x['weight'] for x in signals if x['group']==g) for g in groups}
    # Group-level ceilings prevent run/streak signals from overwhelming everything.
    ceilings={'transition':0.34,'runs':0.32,'regime':0.20,'frequency':0.14,'other':0.10}
    norm=[]
    for group,total in group_totals.items():
        if total>0:
            cap=ceilings[group]
            for sig in signals:
                if sig['group']==group: norm.append((sig,cap*sig['weight']/total))
    other=[x for x in signals if x['group']=='other']
    if other:
        total=sum(x['weight'] for x in other)
        for x in other: norm.append((x,ceilings['other']*x['weight']/total))
    # Re-normalize active groups so missing patterns do not automatically reduce all evidence.
    total_w=sum(w for _,w in norm)
    p_raw=sum(sig['p_tai']/100*w for sig,w in norm)/total_w if total_w else .5
    # Uncertainty shrinkage: fewer independent signal groups -> less extreme output.
    groups_active=len({sig['group'] for sig,w in norm if w>0 and abs(sig['p_tai']-50)>=1})
    shrink=min(.85, .42 + .10*groups_active)
    p_tai=.5+(p_raw-.5)*shrink
    p_tai=max(.30,min(.70,p_tai))
    prediction='TAI' if p_tai>=.5 else 'XIU'
    active=[s for s,w in norm if abs(s['p_tai']-50)>=1]
    agree=sum(1 for s in active if (s['p_tai']>=50)==(prediction=='TAI'))/len(active)*100 if active else 50.0
    last_side,last_len=runs[-1]
    # Label describes the observed structure; it does not claim a deterministic pattern.
    if last_len>=3: state='BET_%s_%d'%(last_side,last_len)
    elif len(runs)>=6 and all(length==1 for _,length in runs[-6:]): state='DAO_1_1'
    elif len(runs)>=4 and [length for _,length in runs[-4:]]==[2,2,2,2]: state='CAU_2_2'
    else: state='HON_HOP'
    confidence=50+abs(p_tai-.5)*100
    return {'prediction':prediction,'p_tai':p_tai*100,'confidence':confidence,'signals':signals,
            'agreement':agree,'n':len(rows),'groups_active':groups_active,'state':state,
            'last_side':last_side,'last_run_len':last_len,'runs':runs,
            'active':[s['name'] for s in sorted(active,key=lambda x:-x['weight'])]}

# ================== PUBLIC API ==================
def analyze_sessions(sessions, record_pred=True, md5_mode=False, game_key=None):
    """Contract giữ nguyên như file 1.
    md5_mode=True: ap dung meo tan suat MD5 cua khach (be/theo nhe/theo manh).
    record_pred=False dùng cho backtest để không làm nhiễu lịch sử tự hiệu chỉnh.
    """
    if not isinstance(sessions, (list, tuple)) or len(sessions) < 2:
        return None
    valid = []
    for s in sessions:
        if not isinstance(s, dict):
            continue
        side = next((normalized for raw_side in (
            s.get("resultTruyenThong"), s.get("result"), s.get("ket_qua"), s.get("side")
        ) if (normalized := normalize_side(raw_side))), None)
        dice_values = s.get("dices") or [s.get("FirstDice"), s.get("SecondDice"), s.get("ThirdDice")]
        raw_point = s.get("point", s.get("DiceSum"))
        if side is None and raw_point is not None:
            try:
                total = int(raw_point)
                side = "XIU" if 4 <= total <= 10 else "TAI" if 11 <= total <= 17 else None
            except (TypeError, ValueError):
                pass
        if side:
            rec = {"id": s.get("id", s.get("phien", s.get("SessionId", 0))), "resultTruyenThong": side}
            if isinstance(dice_values, (list, tuple)) and len(dice_values) == 3 and all(v is not None for v in dice_values):
                rec["dices"] = list(dice_values)
            if raw_point is not None:
                rec["point"] = raw_point
            valid.append(rec)
    if len(valid) < 2:
        return None
    try:
        valid.sort(key=lambda item: int(item.get("id", item.get("phien", 0))))
    except (TypeError, ValueError):
        valid.reverse()
    # Sliding window: analysis uses only the 16 newest valid sessions.
    # The source may return more history, but older rows must not influence this forecast.
    valid = valid[-16:]
    oldest_first = [s["resultTruyenThong"] for s in valid]
    runs = get_runs(oldest_first)
    # V8 Pro is the sole active prediction path for hu/md5/max_hu/max_md5.
    # V7 and legacy ensembles remain in the file only for backward compatibility/debugging;
    # they are not called to generate this forecast.
    game_key_v8 = str(game_key) if game_key in ("md5", "hu", "max_md5", "max_hu") else (
        "md5" if (md5_mode or str(game_key or "").endswith("_md5")) else "hu")
    try:
        v8 = _v8_analyze(valid, game_key_v8)
    except Exception:
        v8 = None
    if v8 is not None:
        if record_pred:
            _record_prediction(v8["prediction"])
        signal_min = [{"name": x["name"], "p_tai": round(x["p_tai"], 1), "w": round(x["weight"], 4), "support": x["support"]} for x in v8["signals"]]
        return {"prediction": v8["prediction"], "confidence": round(v8["confidence"], 1),
                "p_tai": round(v8["p_tai"], 1), "pattern_type": "PAWNOVA-V8-PRO",
                "reason": "V8 Pro: " + ", ".join(v8["active"][:4]),
                "thinking": "V8 independent ensemble; game=%s; history=%d; active_groups=%d; agreement=%.1f%%; state=%s; confidence is signal strength, not guaranteed win rate." % (game_key_v8, v8["n"], v8["groups_active"], v8["agreement"], v8["state"]),
                "last_side": v8["last_side"], "last_run_len": v8["last_run_len"],
                "runs_last_10": [r[1] for r in v8["runs"][-10:]], "total_runs": len(v8["runs"]),
                "state": v8["state"], "p_break": 0.5, "n_votes": len(v8["active"]),
                "stability": round(v8["agreement"] / 100.0, 4), "flipped": False,
                "modules_used": v8["active"], "_v7_signals": signal_min,
                "court_windows": _multi_window_court(valid)}
    state, last_len, typical = mod_lifecycle(runs) if runs else ("UNKNOWN", 0, 0)
    p_break, _ = mod_break(runs) if len(runs) >= 15 else (0.5, 0)
    last_side = runs[-1][0] if runs else "XIU"
    last_run_len = runs[-1][1] if runs else 1
    # --- V7Pro (đường chính cho cả MD5 và HŨ); lỗi/thiếu dữ liệu -> rơi về logic cũ bên dưới ---
    game_key_v7 = str(game_key).lower() if game_key else ("md5" if md5_mode else "hu")
    try:
        v7 = _v7_analyze(valid, game_key_v7, _v7_bma(game_key_v7), _V7_PMAP.setdefault(game_key_v7, {}))
    except Exception:
        v7 = None
    if v7 is not None:
        predict = v7["prediction"]
        hist_bits = _BOT_HISTORY[-100:]
        wl = _v7_wilson(sum(hist_bits), len(hist_bits))[0] * 100 if len(hist_bits) >= 20 else 0.0
        thinking = "V7Pro: dong thuan %.0f%%; entropy %.3f; change-pt %.2f; mau=%d; hit-rate bot %s; Wilson LB %.1f%%" % (
            v7["agreement"], v7["entropy"], v7["cp"], v7["n"],
            ("%.0f%%" % (100.0 * sum(hist_bits) / len(hist_bits))) if hist_bits else "--", wl)
        if record_pred:
            _record_prediction(predict)
        return {"prediction": predict, "confidence": round(v7["confidence"], 1),
                "p_tai": round(v7["p_tai"] * 100, 1), "pattern_type": "PAWNOVA-V7PRO",
                "reason": "V7Pro: " + ", ".join(v7["active"][:3]), "thinking": thinking,
                "last_side": last_side, "last_run_len": last_run_len,
                "runs_last_10": [r[1] for r in runs[-10:]], "total_runs": len(runs),
                "state": state, "p_break": p_break, "n_votes": len(v7["active"]),
                "stability": v7["agreement"] / 100.0, "flipped": False,
                "modules_used": v7["active"], "_v7_signals": v7["signals_min"],
                "court_windows": _multi_window_court(valid)}
    # --- MD5 uses its own adaptive ensemble; frequency remains fallback only ---
    if md5_mode:
        md5_res = _md5_adaptive_ensemble(oldest_first)
        if md5_res is None:
            side, conf, note, rate_tai = _md5_frequency_rule(oldest_first)
            predict, confidence = side, conf
            p_tai = round((rate_tai if side == "TAI" else 1-rate_tai)*100, 1)
            pattern_type, reason = "MD5_FREQ_RULE_FALLBACK", note
            thinking = note + "; w20 TAI=%.1f%%" % (rate_tai*100)
            modules_used, n_votes = ["md5_freq_rule"], 1
            stability = max(0.0, 1.0-abs(rate_tai-0.5)*2)
        else:
            predict, confidence, p_tai = md5_res["prediction"], md5_res["confidence"], md5_res["p_tai"]
            pattern_type, reason, thinking = md5_res["pattern_type"], md5_res["reason"], md5_res["thinking"]
            modules_used, n_votes = md5_res["modules_used"], len(md5_res["modules_used"])
            stability = max(0.0, 1.0-md5_res["entropy"])
        if record_pred: _record_prediction(predict)
        return {"prediction":predict,"confidence":confidence,"p_tai":p_tai,"pattern_type":pattern_type,
                "reason":reason,"thinking":thinking,"last_side":last_side,"last_run_len":last_run_len,
                "runs_last_10":[r[1] for r in runs[-10:]],"total_runs":len(runs),"state":state,
                "p_break":p_break,"n_votes":n_votes,"stability":stability,"flipped":False,
                "modules_used":modules_used}
    new_res = _analyze_new_algorithm(valid, history=[])
    if new_res is not None:
        predict = new_res["predict"]
        confidence = min(75.0, max(50.0, float(new_res["confidence"])))
        p_tai = round(float(new_res["p_tai"]), 1)
        pattern_type = "PAWNOVA-ENSEMBLE-NEW-" + str(new_res.get("regime", "stable")).upper()
        sig_names = [str(x.get("name", "")) for x in new_res.get("signals", []) if x.get("eff_w", 0) > 0]
        reason = "Ensemble moi: " + ", ".join(sig_names[:3])
        thinking = "Entropy %.3f; T10 %.1f%%; T20 %.1f%%; regime %s" % (
            float(new_res.get("entropy", 0.0)), float(new_res.get("f10", 0.0)),
            float(new_res.get("f20", 0.0)), str(new_res.get("regime", "stable")))
        modules_used = sig_names
        n_votes = len(new_res.get("signals", []))
        stability = 1.0 - float(new_res.get("entropy", 1.0))
        flipped = False
    else:
        fb = ensemble_vote(runs)
        if not fb:
            return None
        predict = fb["prediction"]
        confidence = fb["confidence"]
        p_tai = round(fb["p_tai"] * 100, 1)
        pattern_type = "ENS_%s" % fb["state"]
        reason = fb["reasons"][0] if fb["reasons"] else ""
        thinking = " | ".join(fb["reasons"][:3])
        modules_used = fb.get("modules_used", [])
        n_votes = fb["n_votes"]
        stability = fb["stability"]
        flipped = fb["flipped"]
    if record_pred:
        _record_prediction(predict)
    return {
        "prediction": predict,
        "confidence": confidence,
        "p_tai": p_tai,
        "pattern_type": pattern_type,
        "reason": reason,
        "thinking": thinking,
        "last_side": last_side,
        "last_run_len": last_run_len,
        "runs_last_10": [r[1] for r in runs[-10:]],
        "total_runs": len(runs),
        "state": state,
        "p_break": p_break,
        "n_votes": n_votes,
        "stability": stability,
        "flipped": flipped,
        "modules_used": modules_used,
    }

def predict_next(api_url=None):
    """Return a deterministic forecast plus the source rows needed for result grading."""
    try:
        sessions = fetch_sessions(api_url)
        if not sessions:
            return None, "Nguồn API không trả phiên hợp lệ; " + str(LAST_FETCH_ERROR or "không có chi tiết lỗi")
        url_lower = str(api_url or API_URL).lower()
        normalized_url = url_lower.rstrip("/")
        game_key = next((key for key, endpoint in GAME_API_URLS.items() if endpoint.lower().rstrip("/") == normalized_url), None)
        is_md5 = ("md5" in url_lower)
        if game_key is not None:
            is_md5 = game_key == "md5" or game_key.endswith("_md5")
        else:
            # Safe fallback for callers that pass a URL not in the registry.
            if "sunwin" in url_lower: game_key = "sunwin"
            elif "789club" in url_lower: game_key = "789club"
            elif "max789" in url_lower: game_key = "max_md5" if is_md5 else "max_hu"
            else: game_key = "md5" if is_md5 else "hu"
        try:
            _pre_next = str(int(sessions[0].get("id")) + 1)
        except (TypeError, ValueError):
            _pre_next = None
        _PRED_SKIP_LAST[game_key] = 1 if (_pre_next and (game_key, _pre_next) in _PRED_RECORDED) else 0
        res = analyze_sessions(sessions, md5_mode=is_md5, record_pred=False, game_key=game_key)
        if not res:
            return None, "Engine chưa tạo được tín hiệu dự đoán từ dữ liệu phiên hợp lệ (cần ít nhất 15 phiên hợp lệ; tín hiệu có thể hòa)"
        top_id = sessions[0].get("id")
        try:
            next_id = int(top_id) + 1
        except (TypeError, ValueError):
            next_id = None
        _PENDING_MODULES[(game_key, str(next_id))] = list(res.get("modules_used", []))
        _rk = (game_key, str(next_id))
        if _rk not in _PRED_RECORDED and res.get("prediction") in ("TAI", "XIU"):
            _PRED_RECORDED.add(_rk)
            _ph = _PRED_BY_GAME.setdefault(game_key, [])
            _ph.append(res["prediction"])
            del _ph[:-100]
            # Persist immediately: do not wait for a later result/feedback callback.
            # This makes /api/history survive engine-process restarts when the state path is persistent.
            _save_state()
            if len(_PRED_RECORDED) > 600:
                for _old in list(_PRED_RECORDED)[:200]:
                    _PRED_RECORDED.discard(_old)
        if res.get("_v7_signals"):
            _PENDING_V7[(game_key, str(next_id))] = res["_v7_signals"]
            if len(_PENDING_V7) > 400:
                for old_key in list(_PENDING_V7)[:len(_PENDING_V7) - 300]:
                    _PENDING_V7.pop(old_key, None)
        if len(_PENDING_MODULES) > 1000:
            for old_key in list(_PENDING_MODULES)[:len(_PENDING_MODULES)-800]:
                _PENDING_MODULES.pop(old_key, None)
        return {
            "predict": res["prediction"],
            "confidence": res["confidence"],
            "p_tai": res["p_tai"],
            "version": res["pattern_type"],
            "regime": res["pattern_type"],
            "tier": "OK" if res["confidence"] >= 60 else ("WEAK" if res["confidence"] >= 54 else "LOW"),
            "modules_used": res.get("modules_used", []),
            "game": game_key,
            "top_id": top_id,
            "target_id": next_id,
            "reasons": [res["reason"], res.get("thinking", "")],
            "pattern": res["pattern_type"],
            "last_run_len": res["last_run_len"],
            "last_side": res["last_side"],
            "source_rows": sessions,
            "court_windows": res.get("court_windows", _multi_window_court([{"resultTruyenThong": x.get("result", x.get("resultTruyenThong"))} for x in reversed(sessions)])),
        }, None
    except Exception as e:
        return None, "Lỗi phân tích dữ liệu: %s" % type(e).__name__

def save_result(session_id, predict_result, actual, signals=None, game=None):
    try:
        if game is None:
            game_key = next((g for g in list(_PENDING_MODULES.keys()) if str(g[1]) == str(session_id)), ("hu", str(session_id)))[0]
        else:
            supplied_game = str(game).lower()
            game_key = supplied_game or ("md5" if "md5" in supplied_game else "hu")
        correct = (predict_result == actual)
        record_bot_result(correct)
        pending = _PENDING_MODULES.pop((game_key, str(session_id)), [])
        v7_sig = _PENDING_V7.pop((game_key, str(session_id)), None)
        if v7_sig:
            _b = _v7_bma(game_key)
            _b.update(v7_sig, actual)
            _BMA_STATE[game_key] = _b.to_dict()
        modules = list(pending)
        if isinstance(signals, dict):
            supplied = signals.get("modules", [])
            if isinstance(supplied, (list, tuple, set)):
                modules.extend(str(x) for x in supplied)
        prefix = game_key + ":"
        for mod_name in set(modules):
            record_module_result(prefix + str(mod_name), correct)
        _save_state()
    except Exception:
        pass

def get_stats():
    if not _BOT_HISTORY:
        return {}
    total = len(_BOT_HISTORY)
    wins = sum(_BOT_HISTORY)
    return {"total": total, "wins": wins, "rate": wins / total * 100 if total else 0}

def backtest_sessions(sessions, min_train=40, max_tests=500, game_key="hu"):
    """Walk-forward test of the active V8 engine; each forecast sees only earlier rows.

    game_key is one of hu, md5, max_hu, max_md5. This function never trains on the
    target row and does not mutate prediction history while testing.
    """
    key = str(game_key or "hu").lower()
    if key not in ("hu", "md5", "max_hu", "max_md5") and key not in GAME_API_URLS:
        key = "md5" if key.endswith("md5") else "hu"
    valid = []
    for row in sessions or []:
        if not isinstance(row, dict):
            continue
        side = next((v for raw in (row.get("resultTruyenThong"), row.get("result"), row.get("ket_qua"), row.get("side"))
                     if (v := normalize_side(raw))), None)
        if side is None:
            point = row.get("point", row.get("DiceSum"))
            try:
                total = int(point)
                side = "XIU" if 4 <= total <= 10 else "TAI" if 11 <= total <= 17 else None
            except (TypeError, ValueError):
                pass
        if side:
            try:
                sid = int(row.get("id", row.get("phien", row.get("SessionId", len(valid)))))
            except (TypeError, ValueError):
                sid = len(valid)
            rec = {"id": sid, "resultTruyenThong": side}
            if row.get("dices"):
                rec["dices"] = row["dices"]
            if row.get("point", row.get("DiceSum")) is not None:
                rec["point"] = row.get("point", row.get("DiceSum"))
            valid.append(rec)
    if len(valid) < int(min_train) + 1:
        return {"game_key": key, "tests": 0, "wins": 0, "rate": None,
                "error": "insufficient_sessions", "minimum_required": int(min_train) + 1}
    # Preserve source order where session IDs are valid; deduplicate repeated IDs by keeping last.
    by_id = {r["id"]: r for r in valid}
    valid = [by_id[k] for k in sorted(by_id)]
    if len(valid) < int(min_train) + 1:
        return {"game_key": key, "tests": 0, "wins": 0, "rate": None, "error": "insufficient_sessions"}
    start = max(int(min_train), len(valid) - max(1, int(max_tests)))
    wins = tests = skipped = 0
    for target_idx in range(start, len(valid)):
        history = valid[:target_idx]
        actual = valid[target_idx]["resultTruyenThong"]
        # The public analyzer sorts session IDs ascending and uses V8 as the sole active path.
        pred = analyze_sessions(history, record_pred=False, game_key=key)
        if not pred:
            skipped += 1
            continue
        tests += 1
        wins += int(pred["prediction"] == actual)
    out = {"game_key": key, "engine": "PAWNOVA-V8-PRO", "tests": tests, "wins": wins,
           "skipped": skipped, "rate": round(100.0 * wins / tests, 2) if tests else None,
           "note": "Walk-forward historical result only; not a future win-rate guarantee."}
    if tests:
        lo, hi = _v7_wilson(wins, tests)
        z = (wins - tests / 2.0) / math.sqrt(tests / 4.0)
        out["ci95"] = [round(lo * 100, 1), round(hi * 100, 1)]
        out["p_value_vs_50"] = round(math.erfc(abs(z) / math.sqrt(2)), 4)
    return out

def predict_max_md5():
    """Predict from MAX789 MD5 feed."""
    return predict_next(MAX_MD5_API_URL)
def predict_max_hu():
    """Predict from MAX789 HŨ feed."""
    return predict_next(MAX_HU_API_URL)


# --- PAWNOVA V7/V8 algorithm components integrated from updated algorithm ---
def _analyze_new_algorithm(sessions, history=None):
    """Chạy 8 module, gộp có trọng số, trả dict kết quả. sessions: oldest-first list of dict."""
    history = history if isinstance(history, list) else []
    clean = []
    for item in sessions:
        if not isinstance(item, dict):
            continue
        side = normalize_side(item.get("resultTruyenThong", item.get("result", item.get("ket_qua"))))
        if side in ("TAI", "XIU"):
            clean.append({"id": item.get("id", item.get("phien", 0)), "resultTruyenThong": side})
    sessions = clean
    results = [s["resultTruyenThong"] for s in sessions]
    n = len(results)
    if n < 30:
        return None
    seq = ["T" if r == "TAI" else "X" for r in results]
    raw = []
    p_a, ord_a, samp_a = _mod_alpha(seq, max_order=6)
    w_a = 2.8 if samp_a >= 5 else (1.4 if samp_a >= 3 else 0.4)
    raw.append(("alpha", p_a, w_a, "o%d/n%d" % (ord_a, samp_a)))
    p_b = _mod_beta(seq, window=40)
    raw.append(("beta", p_b, 1.6, ""))
    lag, corr = _mod_gamma(seq)
    if lag > 0 and abs(corr) >= 0.10 and n > lag:
        ref = seq[-lag]
        p_g = (1.0 if ref == "T" else 0.0) if corr > 0 else (0.0 if ref == "T" else 1.0)
        w_g = min(2.5, abs(corr) * 6)
    else:
        p_g, w_g = 0.5, 0.0
    raw.append(("gamma", p_g, w_g, "L%d/r%+.2f" % (lag, corr)))
    p_d, w_d, streak, last = _mod_delta(seq)
    raw.append(("delta", p_d, w_d, "%sx%d" % (last, streak)))
    p_e = _mod_epsilon(seq, window=20)
    raw.append(("epsilon", p_e, 0.8, "%.0f%%" % (p_e * 100)))
    p_z, ctx_z, n_z = _mod_zeta(seq, max_len=6, min_count=4)
    w_z = 2.5 if n_z >= 6 else (1.5 if n_z >= 4 else 0.0)
    raw.append(("zeta", p_z, w_z, "%s/n%d" % (ctx_z or "-", n_z)))
    p_h = _mod_eta(seq)
    raw.append(("eta", p_h, 0.9, "%.1f%%" % (p_h * 100)))
    regime, pr, po, rdiff = _mod_theta(seq)
    if regime == "tai_shift":
        raw.append(("theta", 0.62, 1.5, "+%.0f%%" % (rdiff * 100)))
    elif regime == "xiu_shift":
        raw.append(("theta", 0.38, 1.5, "%.0f%%" % (rdiff * 100)))
    names = [r[0] for r in raw]
    meta = _meta_weights(history, names, lookback=50)
    signals = []
    total_w = 0.0
    total_pw = 0.0
    for nm, p, w, note in raw:
        mw = meta.get(nm, 1.0)
        eff_w = w * mw
        total_w += eff_w
        total_pw += p * eff_w
        signals.append({"name": nm, "p_tai": p * 100, "w": w, "meta": mw, "eff_w": eff_w, "note": note})
    p_tai = total_pw / total_w if total_w > 0 else 0.5
    H = _entropy(seq, 50)
    if H >= 0.98:
        p_tai = p_tai * 0.55 + 0.5 * 0.45
    elif H >= 0.92:
        p_tai = p_tai * 0.75 + 0.5 * 0.25
    # Tu hieu chinh thong minh: keo ve trung lap neu lich su du doan nghieng 1 huong
    p_tai = _pred_bias_correction(p_tai)
    # Shrink manh hon de tranh cuc doan 1 chieu
    p_tai = 0.5 + (p_tai - 0.5) * 0.85
    p_tai = max(0.25, min(0.75, p_tai))
    predict = "TAI" if p_tai >= 0.5 else "XIU"
    conf = max(p_tai, 1 - p_tai) * 100
    return {
        "predict": predict, "confidence": conf, "skip": False,
        "p_tai": p_tai * 100, "p_xiu": (1 - p_tai) * 100,
        "streak": streak, "last": last,
        "f10": (seq[-10:].count("T") / 10) * 100,
        "f20": p_e * 100,
        "f50": (seq[-50:].count("T") / min(50, n)) * 100,
        "entropy": H,
        "regime": regime, "regime_diff": rdiff * 100,
        "base_adaptive": p_h * 100,
        "pattern_ctx": ctx_z, "pattern_n": n_z,
        "best_lag": lag, "best_corr": corr,
        "signals": signals,
        "top_id": sessions[-1]["id"],
        "n": n,
    }

def _md5_frequency_rule(oldest_first, window=20):
    """Meo MD5 cua khach: duoi 55% be, tren 55 theo nhe, 60 tro len 99.99% la hup.
    Ap dung doi xung cho phia chiem uu the trong `window` phien gan nhat.
    Tra ve (predicted_side, confidence, note, rate_tai).
    """
    w = min(window, len(oldest_first))
    recent = oldest_first[-w:]
    rate_tai = recent.count("TAI") / len(recent) if recent else 0.5
    if rate_tai >= 0.5:
        dominant, dom_rate = "TAI", rate_tai
    else:
        dominant, dom_rate = "XIU", 1 - rate_tai
    if dom_rate < 0.55:
        side = "XIU" if dominant == "TAI" else "TAI"
        conf = 54 + int((0.55 - dom_rate) * 40)
        note = "MD5 be %s (%.0f%% <55%%)" % (dominant, dom_rate * 100)
    elif dom_rate < 0.60:
        side = dominant
        conf = 58 + int((dom_rate - 0.55) * 80)
        note = "MD5 theo nhe %s (%.0f%%)" % (dominant, dom_rate * 100)
    else:
        side = dominant
        conf = min(72, 65 + int((dom_rate - 0.60) * 100))
        note = "MD5 theo manh %s (%.0f%% >=60%%, hup cao)" % (dominant, dom_rate * 100)
    return side, min(75.0, max(50.0, float(conf))), note, rate_tai

def _md5_adaptive_ensemble(oldest_first):
    """MD5-only ensemble: rolling frequencies, transitions, run-context and regime shift."""
    seq = [normalize_side(x) for x in oldest_first]
    seq = [x for x in seq if x in ("TAI", "XIU")]
    if len(seq) < 15:
        return None
    signals = []
    for window, weight in ((8, 0.9), (15, 1.5), (40, 1.0), (80, 0.55)):
        recent = seq[-min(window, len(seq)):]
        p = (recent.count("TAI") + 1.0) / (len(recent) + 2.0)
        signals.append((f"freq_{window}", p, weight))
    last = seq[-1]
    follows = [seq[i + 1] for i in range(len(seq)-1) if seq[i] == last]
    if len(follows) >= 5:
        p = (follows.count("TAI") + 1.0) / (len(follows) + 2.0)
        signals.append(("transition_1", p, min(1.5, 0.5 + len(follows)/20.0)))
    ctx = tuple(seq[-2:])
    follows2 = [seq[i+2] for i in range(len(seq)-2) if tuple(seq[i:i+2]) == ctx]
    if len(follows2) >= 3:
        p = (follows2.count("TAI") + 1.0) / (len(follows2) + 2.0)
        signals.append(("transition_2", p, min(1.8, 0.6 + len(follows2)/8.0)))
    runs = get_runs(seq)
    lens = [r[1] for r in runs]
    for order in (2, 3):
        if len(runs) <= order: continue
        context = tuple(lens[-order:])
        outcomes = [runs[i+order][0] for i in range(len(runs)-order) if tuple(lens[i:i+order]) == context]
        if len(outcomes) >= 3:
            p = (outcomes.count("TAI") + 1.0)/(len(outcomes)+2.0)
            signals.append((f"run_context_{order}", p, min(1.4, 0.5+len(outcomes)/10.0)))
    if len(seq) >= 60:
        recent, previous = seq[-20:], seq[-60:-20]
        pr = (recent.count("TAI")+2.0)/(len(recent)+4.0)
        po = (previous.count("TAI")+4.0)/(len(previous)+8.0)
        shift = pr-po
        if abs(shift) >= 0.08:
            signals.append(("regime_shift", max(0.15,min(0.85,0.5+shift*0.45)), 0.9))
    if not signals: return None
    weighted=[]
    for name,p,w in signals:
        score=_MODULE_SCORES.get("md5:"+name)
        adaptive=1.0
        if score and score.get("total",0)>=8:
            adaptive=max(0.45,min(1.55,0.5+score["wins"]/max(1,score["total"])))
        weighted.append((p,w*adaptive,name))
    tw=sum(w for _,w,_ in weighted)
    p_tai=sum(p*w for p,w,_ in weighted)/tw if tw else 0.5
    recent=seq[-50:]
    rate=recent.count("TAI")/len(recent)
    entropy=0.0 if rate in (0.0,1.0) else -(rate*math.log2(rate)+(1-rate)*math.log2(1-rate))
    if entropy>=0.98: p_tai=0.5+(p_tai-0.5)*0.55
    elif entropy>=0.92: p_tai=0.5+(p_tai-0.5)*0.75
    p_tai=max(0.30,min(0.70,0.5+(p_tai-0.5)*0.85))
    pred="TAI" if p_tai>=0.5 else "XIU"
    conf=max(50.0,min(70.0,50.0+abs(p_tai-0.5)*100.0))
    names=[name for _,_,name in weighted]
    return {"prediction":pred,"confidence":round(conf,1),"p_tai":round(p_tai*100,1),
            "modules_used":names,"entropy":round(entropy,4),
            "pattern_type":"PAWNOVA-MD5-ADAPTIVE-ENSEMBLE",
            "reason":"MD5 ensemble: "+", ".join(names[:4]),
            "thinking":"MD5 rolling windows + transition + run-context + regime shift; entropy %.3f"%entropy}

# --- Hằng số V7 bị mất ở bản FIXED-2 (gây NameError -> save_result nuốt lỗi, module không học) ---
_V7_WINDOW = 300
_V7_MIN = 15
_V7_SAME_SOFT = 3
_V7_SAME_HARD = 5
_V7_DEFREQ = 0.7
_V7_SHRINK = 0.75
_V7_BASE_TAI = 0.4861
_V7_NAMES = ["v7_ctx", "v7_beta", "v7_gamma", "v7_delta", "v7_eps",
             "v7_zeta", "v7_eta", "v7_dice", "v7_hmm", "v7_band", "v7_runhaz", "v7_streak_regime", "v7_alt", "v7_cau", "v7_step",
             "v7_run_ngram", "v7_cycle", "v7_fliprate", "v7_regime_shift"]
_V7_PAT_LOOKBACK = 60
_V7_PAT_MIN_OPS = 4
_V7_PAT_MIN_RATE = 0.55

def _v7_clamp(p, lo=0.05, hi=0.95):
    return max(lo, min(hi, p))

def _v7_sigmoid(x):
    x = max(-30.0, min(30.0, x))
    return 1.0 / (1.0 + math.exp(-x))

def _v7_wilson(wins, total, z=1.96):
    """Khoang tin cay Wilson 95% (thap, cao) dang 0..1."""
    if total <= 0:
        return 0.0, 1.0
    p = wins / total
    d = 1 + z * z / total
    c = (p + z * z / (2 * total)) / d
    m = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return max(0.0, c - m), min(1.0, c + m)

def _v7_entropy(seq, w=50):
    r = seq[-w:]
    if not r:
        return 1.0
    p = r.count("T") / len(r)
    if p in (0, 1):
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

def _v7_kalman_gain(q=0.02, r=0.15):
    P = 1.0
    K = 0.3
    for _ in range(50):
        Pp = P + q
        K = Pp / (Pp + r)
        P = (1 - K) * Pp
    return K

_V7_K = _v7_kalman_gain()

def _v7_ctx_mix(seq, max_depth=6, decay=0.98):
    """Tron du doan cua cac ngu canh dai 0..max_depth; trong so = softmax(diem du doan thuc te)."""
    y = [1 if s == "T" else 0 for s in seq]
    n = len(y)
    D = min(max_depth, n - 1)
    tables = [dict() for _ in range(D + 1)]
    scores = [0.0] * (D + 1)
    for i in range(n):
        for d in range(D + 1):
            if i < d:
                continue
            ctx = tuple(y[i - d:i]) if d else ()
            a, b = tables[d].get(ctx, (0, 0))
            p1 = (b + 0.5) / (a + b + 1.0)
            scores[d] = scores[d] * decay + math.log(p1 if y[i] else 1.0 - p1)
            tables[d][ctx] = (a + (1 - y[i]), b + y[i])
    mx = max(scores)
    ws = [math.exp(s - mx) for s in scores]
    z = sum(ws) or 1.0
    p, best_d, best_n = 0.0, 0, 0
    for d in range(D + 1):
        ctx = tuple(y[n - d:]) if d else ()
        a, b = tables[d].get(ctx, (0, 0))
        p += (ws[d] / z) * ((b + 0.5) / (a + b + 1.0))
        if ws[d] == 1.0:
            best_d, best_n = d, a + b
    return p, 2.0, "d%d/n%d" % (best_d, best_n)

class _V7HMM:
    """HMM 2 trang thai, Baum-Welch co scaling."""
    def __init__(self):
        self.A = [[0.7, 0.3], [0.3, 0.7]]
        self.B = [[0.6, 0.4], [0.4, 0.6]]
        self.pi = [0.5, 0.5]

    def _forward(self, obs):
        A, B = self.A, self.B
        a0 = [self.pi[i] * B[i][obs[0]] for i in range(2)]
        z = sum(a0) or 1e-300
        alpha, c = [[x / z for x in a0]], [z]
        for t in range(1, len(obs)):
            prev = alpha[-1]
            at = [sum(prev[i] * A[i][j] for i in range(2)) * B[j][obs[t]] for j in range(2)]
            z = sum(at) or 1e-300
            alpha.append([x / z for x in at]); c.append(z)
        return alpha, c

    def _backward(self, obs, c):
        T, A, B = len(obs), self.A, self.B
        beta = [[1.0, 1.0] for _ in range(T)]
        for t in range(T - 2, -1, -1):
            for i in range(2):
                beta[t][i] = sum(A[i][j] * B[j][obs[t + 1]] * beta[t + 1][j] for j in range(2)) / c[t + 1]
        return beta

    def fit(self, obs, iters=5):
        T = len(obs)
        if T < 20:
            return
        for _ in range(iters):
            alpha, c = self._forward(obs)
            beta = self._backward(obs, c)
            gamma = []
            for t in range(T):
                g = [alpha[t][i] * beta[t][i] for i in range(2)]
                z = sum(g) or 1e-300
                gamma.append([x / z for x in g])
            xi = [[0.0, 0.0], [0.0, 0.0]]
            for t in range(T - 1):
                for i in range(2):
                    for j in range(2):
                        xi[i][j] += alpha[t][i] * self.A[i][j] * self.B[j][obs[t + 1]] * beta[t + 1][j] / c[t + 1]
            for i in range(2):
                den = sum(gamma[t][i] for t in range(T - 1)) or 1e-300
                row = [max(0.02, xi[i][j] / den) for j in range(2)]
                s = sum(row)
                self.A[i] = [x / s for x in row]
                den_b = sum(gamma[t][i] for t in range(T)) or 1e-300
                brow = [max(0.02, sum(gamma[t][i] for t in range(T) if obs[t] == v) / den_b) for v in (0, 1)]
                s = sum(brow)
                self.B[i] = [x / s for x in brow]

    def predict_next(self, obs):
        if len(obs) < 20:
            return 0.5
        alpha, _ = self._forward(obs)
        last = alpha[-1]
        nxt = [sum(last[i] * self.A[i][j] for i in range(2)) for j in range(2)]
        return sum(nxt[j] * self.B[j][1] for j in range(2))

def _v7_hmm(seq, window=150):
    obs = [1 if s == "T" else 0 for s in seq[-window:]]
    h = _V7HMM()
    h.fit(obs, iters=5)
    return h.predict_next(obs), 1.5, "HMM"

def _v7_bocpd(seq, window=60, hazard=1 / 40.0):
    """Xac suat chuoi vua doi che do trong ~5 phien gan nhat."""
    s = seq[-window:]
    if len(s) < 15:
        return 0.0
    R = [1.0]; a = [1.0]; b = [1.0]
    for ob in s:
        x = 1.0 if ob == "T" else 0.0
        nR = [0.0] * (len(R) + 1)
        na = [1.0 + x] + [0.0] * len(R)
        nb = [1.0 + (1 - x)] + [0.0] * len(R)
        for r in range(len(R)):
            pr = a[r] / (a[r] + b[r])
            like = pr if x else 1 - pr
            nR[r + 1] += R[r] * (1 - hazard) * like
            nR[0] += R[r] * hazard * 0.5
            na[r + 1] = a[r] + x
            nb[r + 1] = b[r] + (1 - x)
        z = sum(nR) or 1.0
        R = [v / z for v in nR]; a, b = na, nb
    return sum(R[:6])

def _v7_beta(seq, window=40, a0=6.0, b0=6.0, decay=0.95):
    r = seq[-window:]; a, b = a0, b0; L = len(r)
    for i, x in enumerate(r):
        w = decay ** (L - 1 - i)
        if x == "T":
            a += w
        else:
            b += w
    return a / (a + b), 1.2, ""

def _v7_gamma(seq, max_lag=25):
    """Tu tuong quan; chi tin khi |r| vuot nguong y nghia 3/sqrt(n)."""
    x = [1 if r == "T" else 0 for r in seq]
    n = len(x)
    if n < 40:
        return 0.5, 0.0, "L0"
    m = sum(x) / n
    v = sum((q - m) ** 2 for q in x) / n
    if v == 0:
        return 0.5, 0.0, "L0"
    bl, bc = 0, 0.0
    for lag in range(2, min(max_lag, n // 3)):
        cov = sum((x[i] - m) * (x[i + lag] - m) for i in range(n - lag)) / (n - lag)
        c = cov / v
        if abs(c) > abs(bc):
            bc, bl = c, lag
    if bl == 0 or abs(bc) < 3.0 / math.sqrt(n):
        return 0.5, 0.0, "L%d/r%+.2f" % (bl, bc)
    ref_tai = seq[-bl] == "T"
    up = ref_tai if bc > 0 else (not ref_tai)
    return 0.5 + (0.12 if up else -0.12), min(2.0, abs(bc) * 6), "L%d/r%+.2f" % (bl, bc)

def _v7_delta(seq):
    last = seq[-1]; s = 1
    for i in range(len(seq) - 2, -1, -1):
        if seq[i] == last:
            s += 1
        else:
            break
    p, w = 0.5, 0.0
    if s >= 4:
        d = min(0.15, 0.04 * (s - 3))
        p = (0.5 - d) if last == "T" else (0.5 + d)
        w = 1.0
    return p, w, "%s*%d" % (last, s), s

def _v7_eps(seq, window=20):
    r = seq[-window:]
    p = r.count("T") / len(r) if r else 0.5
    return p, 0.6, "%.0f%%" % (p * 100)

def _v7_zeta(seq, max_len=6, min_count=5):
    n = len(seq); best = (0.5, None, 0, 0)
    for L in range(2, min(max_len, n - 1) + 1):
        ctx = tuple(seq[-L:]); ct = cx = 0
        for i in range(n - L):
            if tuple(seq[i:i + L]) == ctx:
                if seq[i + L] == "T":
                    ct += 1
                else:
                    cx += 1
        tot = ct + cx
        if tot >= min_count and L > best[3]:
            best = ((ct + 0.5) / (tot + 1), "".join(ctx), tot, L)
    p, ctx, cnt, _ = best
    w = 1.5 if cnt >= 8 else (0.8 if cnt >= 5 else 0.0)
    return p, w, "%s/n%d" % (ctx or "-", cnt)

def _v7_eta(seq, long_w=400, k=80):
    w = seq[-long_w:]; n = len(w)
    p = _V7_BASE_TAI if n < 50 else (w.count("T") + _V7_BASE_TAI * k) / (n + k)
    return p, 0.4, "%.1f%%" % (p * 100)

def _v7_dice(rows, window=30):
    sums = [0.0, 0.0, 0.0]; cnt = 0
    for s in rows[-window:]:
        d = s.get("dices") or []
        try:
            d = [int(v) for v in d]
        except (TypeError, ValueError):
            continue
        if len(d) == 3 and all(1 <= v <= 6 for v in d):
            for i in range(3):
                sums[i] += d[i]
            cnt += 1
    if cnt < 10:
        return 0.5, 0.0, "no-dice"
    avg = [x / cnt for x in sums]
    dev = sum(abs(a - 3.5) for a in avg)
    return _v7_sigmoid((sum(avg) - 10.5) * 0.5), min(1.5, 0.3 + dev * 0.4), "%.1f/%.1f/%.1f" % tuple(avg)

def _v7_band(rows, window=80):
    def band(t):
        return 0 if t <= 7 else (1 if t <= 10 else (2 if t <= 14 else 3))
    rec = []
    for s in rows[-window:]:
        try:
            pt = int(s.get("point"))
        except (TypeError, ValueError):
            continue
        if pt > 0:
            rec.append((band(pt), s["resultTruyenThong"]))
    if len(rec) < 15:
        return 0.5, 0.0, "no-data"
    cur = rec[-1][0]
    tt = [0] * 4; tot = [0] * 4
    for i in range(len(rec) - 1):
        b = rec[i][0]; tot[b] += 1
        if rec[i + 1][1] == "TAI":
            tt[b] += 1
    if tot[cur] < 5:
        return 0.5, 0.0, "b%d/n%d" % (cur, tot[cur])
    return (tt[cur] + 2.0) / (tot[cur] + 4.0), (1.2 if tot[cur] >= 10 else 0.7), "b%d/n%d" % (cur, tot[cur])

def _v7_runs(seq):
    runs = []
    for x in seq:
        if runs and runs[-1][0] == x:
            runs[-1][1] += 1
        else:
            runs.append([x, 1])
    return runs

def _v7_runhaz(seq, window=180, a=10.0):
    """Hazard cua bet co suy giam theo thoi gian: uoc luong tiep tuc hay gay tai L hien tai.
    Run dai hon L la bang chung tiep tuc; run dung dung L la bang chung gay tai L.
    Dung Laplace prior va trong so gan day, khong tu dong khang dinh cu dai se gay."""
    runs = _v7_runs(seq[-window:])
    if len(runs) < 7:
        return 0.5, 0.0, "run-sample<7"
    cur_side, cur_len = runs[-1]
    completed = runs[:-1]
    # Chi cac run da dat den L moi tham gia uoc luong hazard tai L.
    eligible = [(i, r[1]) for i, r in enumerate(completed) if r[1] >= cur_len]
    if len(eligible) < 3:
        return 0.5, 0.0, "L%d evidence<3" % cur_len
    # Run gan day co trong so cao hon; nho duoc giu de tranh phan ung qua muc.
    cont = brk = total = 0.0
    n_all = len(completed)
    for i, length in eligible:
        age = n_all - 1 - i
        wt = math.exp(-age / 24.0)
        total += wt
        if length == cur_len:
            brk += wt
        else:
            cont += wt
    # Prior break rate 0.5; posterior mean, sau do blend long-term va recent evidence.
    h_recent = (brk + a * 0.5) / (total + a)
    # Chuan hoa evidence de confidence khong phong dai khi chi co vai run tuong tu.
    h = 0.65 * h_recent + 0.35 * ((brk + 5.0 * 0.5) / (total + 5.0))
    p_cont = 1.0 - h
    p_tai = p_cont if cur_side == "T" else 1.0 - p_cont
    weight = min(1.8, 0.45 + 0.12 * len(eligible))
    return p_tai, weight, "L%d continue=%.2f evidence=%d" % (cur_len, p_cont, len(eligible))

def _v7_streak_regime(seq, window=120):
    """Detect regime: persistent streak, alternating pattern, or unstable transition.
    Output is a deliberately modest probability adjustment, not a guaranteed prediction."""
    s = seq[-window:]
    if len(s) < 20:
        return 0.5, 0.0, "regime-sample<20"
    runs = _v7_runs(s)
    if len(runs) < 6:
        return 0.5, 0.0, "regime-runs<6"
    cur_side, cur_len = runs[-1]
    recent = runs[-min(18, len(runs)):]
    lengths = [r[1] for r in recent[:-1]]
    # Run-length continuation: recent empirical probability of a run exceeding current length.
    at_risk = [r[1] for r in recent[:-1] if r[1] >= cur_len]
    if len(at_risk) >= 3:
        cont_n = sum(1 for length in at_risk if length > cur_len)
        p_cont = (cont_n + 2.0) / (len(at_risk) + 4.0)
    else:
        p_cont = 0.5
    # Alternation is a distinct regime: if most recent runs are length 1, expect switch only
    # when the current single-run context is supported by repeated recent alternation.
    single_rate = sum(1 for length in lengths[-8:] if length == 1) / max(1, len(lengths[-8:]))
    flip_rate = sum(1 for i in range(max(1, len(s)-12), len(s)) if s[i] != s[i-1]) / min(12, len(s)-1)
    if cur_len == 1 and single_rate >= 0.65 and flip_rate >= 0.65:
        p_cont = 0.25 * p_cont + 0.75 * 0.28  # favor a switch, but not certainty
        note = "alternating"
    elif cur_len >= 3 and len(at_risk) >= 4:
        note = "streak-L%d" % cur_len
    else:
        note = "mixed"
    # Blend toward 50% for weak evidence; weight grows only with observed comparable runs.
    evidence = min(1.0, len(at_risk) / 8.0)
    p_cont = 0.5 + (p_cont - 0.5) * evidence
    p_tai = p_cont if cur_side == "T" else 1.0 - p_cont
    return p_tai, min(1.4, 0.25 + 1.15 * evidence), "%s continue=%.2f n=%d" % (note, p_cont, len(at_risk))

def _v7_follow(cur_len, target, cur_side):
    """Chua du do dai du kien -> di tiep cung phia; du roi -> doi phia; vuot -> cau hong (None)."""
    if cur_len < target:
        return cur_side
    if cur_len == target:
        return "X" if cur_side == "T" else "T"
    return None

def _v7_pred_runperiod(seq, qs):
    """Chu ky theo DO DAI cac chuoi (q=1: 1-1/2-2/3-3/4-4; q=2: 1-2-1-2, 2-1-2-1; q=3: 1-2-3-1-2-3; q=4: 2-1-1-2-2-1-1-2, 2-2-3-3...)."""
    runs = _v7_runs(seq[-60:])
    if len(runs) < 4:
        return None
    L = [r[1] for r in runs[:-1]]          # cac chuoi da ket thuc
    cur_side, cur_len = runs[-1]
    n = len(L)
    for q in qs:
        need = 3 if q == 1 else 2 * q
        if n < need:
            continue
        if q == 1:
            m = L[-1]
            if m <= 4 and L[-1] == L[-2] == L[-3]:
                return _v7_follow(cur_len, m, cur_side)
        else:
            if L[-q:] == L[-2 * q:-q] and len(set(L[-q:])) > 1 and max(L[-q:]) <= 5:
                return _v7_follow(cur_len, L[-q], cur_side)
    return None

def _v7_pred_step(seq):
    """Cau tang dan (1-2-3, 2-3-4) / giam dan (3-2-1, 4-3-2): 3 chuoi gan nhat lech deu 1."""
    runs = _v7_runs(seq[-60:])
    if len(runs) < 5:
        return None
    L = [r[1] for r in runs[:-1]]
    cur_side, cur_len = runs[-1]
    a, b, c = L[-3], L[-2], L[-1]
    if b - a == 1 and c - b == 1 and c <= 5:
        return _v7_follow(cur_len, c + 1, cur_side)
    if a - b == 1 and b - c == 1 and c >= 2:
        return _v7_follow(cur_len, c - 1, cur_side)
    return None

def _v7_validated(seq, predictor, name):
    """Tra (p_tai, w, note). Danh gia cau tren chinh chuoi gan day (walk-forward) truoc khi cho phep len tieng."""
    nxt = predictor(seq)
    if nxt is None:
        return 0.5, 0.0, "-"
    n = len(seq)
    ops = hit = 0
    for t in range(max(12, n - _V7_PAT_LOOKBACK), n):
        pr = predictor(seq[:t])
        if pr is not None:
            ops += 1
            if pr == seq[t]:
                hit += 1
    rate = (hit + 1.0) / (ops + 2.0)
    if ops < _V7_PAT_MIN_OPS or rate < _V7_PAT_MIN_RATE:
        return 0.5, 0.0, "%s %d/%d chua du tin" % (name, hit, ops)
    edge = min(0.18, (rate - 0.5) * 0.8)
    p_tai = 0.5 + (edge if nxt == "T" else -edge)
    return p_tai, min(2.0, 1.0 + (rate - 0.55) * 8), "%s %d/%d" % (name, hit, ops)

def _v7_alt(seq):
    return _v7_validated(seq, lambda s: _v7_pred_runperiod(s, (1,)), "1-1/2-2")

def _v7_cau(seq):
    return _v7_validated(seq, lambda s: _v7_pred_runperiod(s, (2, 3, 4)), "chu-ky")

def _v7_step(seq):
    return _v7_validated(seq, _v7_pred_step, "tang/giam")

class _V7BMA:
    """Bayesian Model Averaging: trong so module ~ exp(log-likelihood tich luy, suy giam ~50 phien)."""
    def __init__(self, names=None, decay=0.98):
        self.names = list(names or _V7_NAMES)
        self.log_w = {n: 0.0 for n in self.names}
        self.decay = decay
        self.hits = {n: 0 for n in self.names}
        self.totals = {n: 0 for n in self.names}

    def weights(self):
        mx = max(self.log_w.get(n, 0.0) for n in self.names)
        ex = {n: math.exp(max(-30.0, self.log_w.get(n, 0.0) - mx)) for n in self.names}
        z = sum(ex.values()) or 1.0
        return {n: ex[n] / z for n in self.names}

    def update(self, signals, actual):
        actual = normalize_side(actual)
        if actual not in ("TAI", "XIU"):
            return
        y = 1.0 if actual == "TAI" else 0.0
        for s in signals:
            nm = s["name"]
            if nm not in self.log_w:
                self.names.append(nm); self.log_w[nm] = 0.0
            if s.get("w", 1) <= 0:
                continue
            p = _v7_clamp(s["p_tai"] / 100.0)
            ll = y * math.log(p) + (1 - y) * math.log(1 - p)
            self.log_w[nm] = self.decay * self.log_w[nm] + (ll - math.log(0.5))
            self.totals[nm] = self.totals.get(nm, 0) + 1
            if (p >= 0.5) == (actual == "TAI"):
                self.hits[nm] = self.hits.get(nm, 0) + 1

    def to_dict(self):
        return {"names": self.names, "log_w": self.log_w, "decay": self.decay,
                "hits": self.hits, "totals": self.totals}

    @classmethod
    def from_dict(cls, d):
        o = cls(d.get("names") or _V7_NAMES, d.get("decay", 0.98))
        for k, v in (d.get("log_w") or {}).items():
            try:
                o.log_w[str(k)] = float(v)
            except (TypeError, ValueError):
                pass
        o.hits.update({str(k): int(v) for k, v in (d.get("hits") or {}).items() if isinstance(v, (int, float))})
        o.totals.update({str(k): int(v) for k, v in (d.get("totals") or {}).items() if isinstance(v, (int, float))})
        for n in _V7_NAMES:
            if n not in o.names:
                o.names.append(n)
        for n in o.names:
            o.log_w.setdefault(n, 0.0)
        return o

def _v7_bma(game):
    d = _BMA_STATE.get(game)
    try:
        return _V7BMA.from_dict(d) if isinstance(d, dict) else _V7BMA()
    except Exception:
        return _V7BMA()

def _v7_run_ngram(seq, max_order=5):
    """Dự báo theo ngữ cảnh độ dài các bệt đã hoàn tất; Bayesian smoothing chống khớp quá mức."""
    runs = get_runs(["TAI" if x == "T" else "XIU" for x in seq])
    if len(runs) < 8:
        return 0.5, 0.0, "run-context: ít dữ liệu"
    lens = [min(8, r[1]) for r in runs]
    sides = [r[0] for r in runs]
    candidates = []
    for order in range(2, min(max_order, len(lens) - 1) + 1):
        ctx = tuple(lens[-order:])
        outcomes = [sides[i + order] for i in range(len(lens) - order)
                    if tuple(lens[i:i + order]) == ctx]
        if len(outcomes) >= 3:
            p = (outcomes.count("TAI") + 2.0) / (len(outcomes) + 4.0)
            recency = min(1.0, len(outcomes) / 8.0)
            candidates.append((p, 0.35 + 0.9 * recency, order, len(outcomes)))
    if not candidates:
        return 0.5, 0.0, "run-context: chưa lặp đủ"
    p, w, order, count = max(candidates, key=lambda z: (z[1], z[2]))
    return p, w, "run-ngram order=%d matches=%d" % (order, count)

def _v7_cycle(seq, max_period=8):
    """Tìm chu kỳ T/X và chu kỳ độ dài bệt; chỉ có trọng số khi lặp nhiều lần."""
    n = len(seq)
    if n < 18:
        return 0.5, 0.0, "cycle: ít dữ liệu"
    scored = []
    for period in range(2, min(max_period, n // 3) + 1):
        tail = seq[-period:]
        matches = 0
        for back in range(2, min(6, n // period) + 1):
            if seq[-back * period:-(back - 1) * period] == tail:
                matches += 1
        if matches >= 2:
            # Bước kế tiếp theo chu kỳ, shrink về trung tính theo số lần khớp.
            nxt = seq[-period]
            p = 0.5 + (0.5 if nxt == "T" else -0.5) * min(0.18, 0.06 * matches)
            scored.append((matches / period, p, period, matches))
    # Chu kỳ trên chuỗi bệt: mẫu độ dài lặp lại và đổi bên luân phiên theo bản chất run.
    runs = get_runs(["TAI" if x == "T" else "XIU" for x in seq])
    lens = [min(8, r[1]) for r in runs]
    for period in range(2, min(5, len(lens) // 3) + 1):
        a, b, c = lens[-period:], lens[-2*period:-period], lens[-3*period:-2*period]
        if a == b == c:
            scored.append((1.0 / period, 0.5, period, 2))
    if not scored:
        return 0.5, 0.0, "cycle: không có chu kỳ đủ bằng chứng"
    score, p, period, matches = max(scored, key=lambda z: z[0])
    return p, min(0.9, 0.25 + 0.15 * matches), "cycle period=%d repeats=%d" % (period, matches)

def _v7_fliprate(seq, window=24):
    """Phân loại nhịp đảo bên so với tiếp diễn, không mặc định cứ bệt là phải gãy."""
    part = seq[-min(window, len(seq)):]
    if len(part) < 8:
        return 0.5, 0.0, "flip-rate: ít dữ liệu"
    flips = sum(part[i] != part[i-1] for i in range(1, len(part)))
    rate = flips / (len(part) - 1)
    # Xác suất dự báo được co về trung tính; flip-rate chỉ là bối cảnh, không phải dự đoán tự thân.
    runs = get_runs(["TAI" if x == "T" else "XIU" for x in part])
    last_len = runs[-1][1]
    if rate >= 0.72:
        # Chỉ nghiêng đảo nếu nhịp 1-1 thật sự chiếm ưu thế ở cửa sổ gần.
        p = 0.56 if part[-1] == "X" else 0.44
        note = "frequent alternation %.2f" % rate
    elif rate <= 0.28 and last_len >= 3:
        # Bệt tiếp diễn vẫn là giả thuyết chính; không ép đảo vì chuỗi dài.
        p = 0.54 if part[-1] == "T" else 0.46
        note = "low flip-rate %.2f; streak=%d" % (rate, last_len)
    else:
        return 0.5, 0.0, "mixed flip-rate %.2f" % rate
    return p, 0.65, note

def _v7_regime_shift(seq):
    """So sánh cửa sổ gần với nền trước đó để giảm ảnh hưởng mẫu đã lỗi thời."""
    if len(seq) < 50:
        return 0.5, 0.0, "regime-shift: cần >=50"
    recent = seq[-15:]
    prior = seq[-50:-15]
    pr = (recent.count("T") + 1.0) / (len(recent) + 2.0)
    po = (prior.count("T") + 2.0) / (len(prior) + 4.0)
    delta = pr - po
    if abs(delta) < 0.12:
        return 0.5, 0.0, "regime stable delta=%.2f" % delta
    # Nghiêng nhẹ theo cửa sổ gần; mức ảnh hưởng giới hạn để tránh overreaction.
    p = max(0.42, min(0.58, 0.5 + delta * 0.35))
    return p, min(0.75, 0.25 + abs(delta)), "regime delta=%.2f" % delta

def _v7_analyze(valid, game, bma, pmap, pred_hist=None):
    """valid: list phien CU -> MOI [{id, resultTruyenThong, dices?, point?}].
    pmap: {top_id: p_kalman} de loc Kalman nhat quan theo tung phien (cung 1 phien thi ket qua khong doi).
    Tra dict noi bo, hoac None neu chua du du lieu."""
    rows = valid[-_V7_WINDOW:]
    n = len(rows)
    if n < _V7_MIN:
        return None
    seq = ["T" if r["resultTruyenThong"] == "TAI" else "X" for r in rows]
    raw = []
    p, w, note = _v7_ctx_mix(seq);        raw.append(("v7_ctx", p, w, note))
    p, w, note = _v7_beta(seq);           raw.append(("v7_beta", p, w, note))
    p, w, note = _v7_gamma(seq);          raw.append(("v7_gamma", p, w, note))
    p, w, note, streak = _v7_delta(seq);  raw.append(("v7_delta", p, w, note))
    p, w, note = _v7_eps(seq);            raw.append(("v7_eps", p, w, note))
    p, w, note = _v7_zeta(seq);           raw.append(("v7_zeta", p, w, note))
    p, w, note = _v7_eta(seq);            raw.append(("v7_eta", p, w, note))
    p, w, note = _v7_dice(rows);          raw.append(("v7_dice", p, w, note))
    p, w, note = _v7_hmm(seq);            raw.append(("v7_hmm", p, w, note))
    p, w, note = _v7_band(rows);          raw.append(("v7_band", p, w, note))
    p, w, note = _v7_runhaz(seq);         raw.append(("v7_runhaz", p, w, note))
    p, w, note = _v7_streak_regime(seq); raw.append(("v7_streak_regime", p, w, note))
    p, w, note = _v7_alt(seq);            raw.append(("v7_alt", p, w, note))
    p, w, note = _v7_cau(seq);            raw.append(("v7_cau", p, w, note))
    p, w, note = _v7_step(seq);           raw.append(("v7_step", p, w, note))
    p, w, note = _v7_run_ngram(seq);      raw.append(("v7_run_ngram", p, w, note))
    p, w, note = _v7_cycle(seq);           raw.append(("v7_cycle", p, w, note))
    p, w, note = _v7_fliprate(seq);        raw.append(("v7_fliprate", p, w, note))
    p, w, note = _v7_regime_shift(seq);    raw.append(("v7_regime_shift", p, w, note))

    W = bma.weights()
    k = max(1, len(W))
    signals, num, den = [], 0.0, 0.0
    for nm, p, w, note in raw:
        ew = W.get(nm, 1.0 / k) * w
        num += ew * p
        den += ew
        signals.append({"name": nm, "p_tai": p * 100.0, "w": w, "eff_w": ew, "note": note})
    pat_names = ("v7_runhaz", "v7_streak_regime", "v7_alt", "v7_cau", "v7_step", "v7_run_ngram", "v7_cycle", "v7_fliprate")
    pat_ew = sum(sg["eff_w"] for sg in signals if sg["name"] in pat_names)
    if den > 0 and pat_ew > 0.4 * den:      # chong "loan": nhom cau toi da 40% anh huong
        k_scale = (0.4 * (den - pat_ew)) / (0.6 * pat_ew) if den > pat_ew else 0.0
        num = den = 0.0
        for sg in signals:
            if sg["name"] in pat_names:
                sg["eff_w"] *= k_scale
            num += sg["eff_w"] * sg["p_tai"] / 100.0
            den += sg["eff_w"]
    p_ens = num / den if den > 0 else 0.5
    # Cac module beta/eps/eta chi do TAN SUAT gan day (marginal). Neu de nguyen, ca ensemble se
    # di theo phe dang chiem da so -> chuoi du doan bi ket 1 phia (vd full XIU khi cua so dang nghieng XIU).
    fw = fp = 0.0
    for nm, p, w, note in raw:
        if nm in ("v7_beta", "v7_eps", "v7_eta"):
            fw += w; fp += w * p
    if fw > 0:
        p_ens = _v7_clamp(p_ens - _V7_DEFREQ * (fp / fw - 0.5), 0.05, 0.95)

    # Kalman: keo nhe ve uoc luong cua phien truoc (khong phu thuoc so lan goi cho cung 1 phien)
    top_id = None
    try:
        top_id = int(rows[-1]["id"])
    except (TypeError, ValueError, KeyError):
        pass
    prior = None
    if top_id is not None and pmap:
        older = [kk for kk in pmap if kk < top_id]
        if older:
            prior = pmap[max(older)]
    p_k = p_ens if prior is None else prior + _V7_K * (p_ens - prior)
    if top_id is not None:
        pmap[top_id] = p_k
        if len(pmap) > 30:
            for kk in sorted(pmap)[:len(pmap) - 30]:
                pmap.pop(kk, None)

    H = _v7_entropy(seq, 50)
    cp = _v7_bocpd(seq)
    shrink = _V7_SHRINK * (0.85 if H >= 0.98 else 1.0) * (1.0 - 0.3 * min(1.0, cp))
    p_tai = 0.5 + (p_k - 0.5) * shrink
    # Chinh lech chi dua tren chuoi DU DOAN khong phai ket qua that nen khong dung
    # no de ep dao chieu. Chi giam nhe do manh khi output lap mot phia; khong bao gio
    # tu dong lat sang ben kia chi vi da bet nhieu phien.
    if pred_hist is None:
        ph = list(_PRED_BY_GAME.get(game, []))
        if _PRED_SKIP_LAST.get(game) and ph:
            ph = ph[:-1]
    else:
        ph = list(pred_hist)
    same, last_pred = 0, None
    for x in reversed(ph):
        if last_pred is None:
            last_pred, same = x, 1
        elif x == last_pred:
            same += 1
        else:
            break
    if same >= _V7_SAME_SOFT:
        # Soft damp only: neutralize excessive confidence, never force a side flip.
        p_tai = 0.5 + (p_tai - 0.5) * max(0.55, 1.0 - 0.07 * (same - _V7_SAME_SOFT + 1))
    p_tai = _v7_clamp(p_tai, 0.28, 0.72)
    pred = "TAI" if p_tai >= 0.5 else "XIU"
    # Signal strength only; not a guaranteed win probability. Cap display at 72%.
    conf = min(72.0, 50.0 + abs(p_tai - 0.5) * 100.0)

    active = [s for s in signals if s["eff_w"] > 0 and abs(s["p_tai"] - 50.0) > 0.5]
    agreement = (sum(1 for s in active if (s["p_tai"] >= 50.0) == (pred == "TAI")) / len(active) * 100.0
                 if active else 50.0)
    return {"prediction": pred, "p_tai": p_tai, "confidence": conf, "signals": signals,
            "signals_min": [{"name": s["name"], "p_tai": s["p_tai"], "w": s["w"]} for s in signals],
            "agreement": agreement, "entropy": H, "cp": cp, "streak": streak, "n": n,
            "active": [s["name"] for s in sorted(active, key=lambda s: -s["eff_w"])]}

def _multi_window_court(sessions):
    """Diagnostics for 3/6/10/16 last completed outcomes; not a guaranteed next-roll predictor."""
    seq = [x.get("resultTruyenThong") for x in sessions if x.get("resultTruyenThong") in ("TAI", "XIU")]
    out = {}
    for width in (3, 6, 10, 16):
        part = seq[-width:]
        if not part:
            continue
        tai = part.count("TAI")
        xiu = len(part) - tai
        runs = get_runs(part)
        last_side, last_len = runs[-1] if runs else (None, 0)
        out[str(width)] = {
            "n": len(part), "tai": tai, "xiu": xiu,
            "tai_pct": round(100 * tai / len(part), 1),
            "xiu_pct": round(100 * xiu / len(part), 1),
            "last_side": last_side, "last_streak": last_len,
            "pattern": "streak" if last_len >= 3 else ("alternating" if len(runs) >= 2 and all(runs[i][1] == 1 for i in range(max(0, len(runs)-3), len(runs))) else "mixed"),
        }
    # Agreement is descriptive only. It must not be interpreted as calibrated probability.
    lean = ["TAI" if v["tai_pct"] > 50 else "XIU" if v["xiu_pct"] > 50 else "EVEN" for v in out.values()]
    out["agreement"] = {"same_direction_count": max(lean.count("TAI"), lean.count("XIU")), "windows": len(lean), "note": "Descriptive window agreement; not proof of predictive edge."}
    return out

def get_module_stats():
    stats = get_stats()
    stats["modules"] = {
        name: {"wins": score["wins"], "total": score["total"],
               "rate": (score["wins"] / score["total"] * 100) if score["total"] else 0}
        for name, score in _MODULE_SCORES.items()
    }
    return stats


_load_state()
