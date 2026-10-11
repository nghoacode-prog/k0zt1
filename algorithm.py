#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import math
from collections import Counter
from statistics import mode

API_URL = "https://wtxmd52.tele68.com/v1/txmd5/sessions"
HEADERS = {"User-Agent": "Mozilla/5.0", "Origin": "https://lc79b.bet"}


def fetch_sessions():
    for attempt in range(3):
        try:
            r = requests.get(API_URL, timeout=15, headers=HEADERS)
            r.raise_for_status()
            data = r.json()
            raw = data.get("list", []) if isinstance(data, dict) else data
            out = []
            for it in raw:
                try:
                    side = (it.get("resultTruyenThong") or it.get("result") or "").upper()
                    if side not in ("TAI", "XIU"):
                        continue
                    rec = {"id": int(it.get("id")), "result": side}
                    d = it.get("dices")
                    if d and len(d) == 3:
                        rec["dices"] = [int(x) for x in d]
                        rec["point"] = int(it.get("point", sum(rec["dices"])))
                    out.append(rec)
                except Exception:
                    continue
            out.sort(key=lambda x: x["id"], reverse=True)
            if out:
                return out
        except Exception:
            import time
            time.sleep(2)
    return []


def normalize_side(s):
    if not s:
        return None
    s = str(s).upper().strip()
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
    is_bet = last_len >= 3 and len(set(r[0] for r in runs[-3:])) == 1
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
    n = len(runs)
    if n < 15:
        return 0.5, 0
    last_side = runs[-1][0]
    last_len = runs[-1][1]
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
    return p, reached


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
        vals.append(p20)
        weights.append(0.50)
    if p40 is not None:
        vals.append(p40)
        weights.append(0.30)
    if p60 is not None:
        vals.append(p60)
        weights.append(0.20)
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
                if seq[i + L] == "TAI":
                    ct += 1
                else:
                    cx += 1
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
        return {"prediction": last_side, "confidence": 62, "type": "1-1→2"}
    if recent[0] == 2 and recent[1] == 2 and recent[2] == 1:
        return {"prediction": last_side, "confidence": 62, "type": "2-2→1"}
    if recent[0] == 3 and recent[1] == 3 and recent[2] == 1:
        return {"prediction": last_side, "confidence": 62, "type": "3-3→1"}
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


_BOT_HISTORY = []


def record_bot_result(correct):
    _BOT_HISTORY.append(1 if correct else 0)
    if len(_BOT_HISTORY) > 100:
        _BOT_HISTORY.pop(0)


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


def _collect_all(runs):
    votes = []
    reasons = []
    state, last_len, typical = mod_lifecycle(runs)
    p_break, br_n = mod_break(runs)

    p_bias, bias_n = mod_bias(runs)
    if bias_n >= 30:
        votes.append((p_bias, 2.0))
        reasons.append(f"bias {p_bias*100:.0f}% n{bias_n}")

    p_mk, mk_n = mod_markov(runs)
    if mk_n >= 10:
        votes.append((p_mk, 1.0))
        reasons.append(f"markov n{mk_n}")

    p_ng, ng_n = mod_ngram(runs)
    if ng_n >= 5:
        votes.append((p_ng, 1.6))
        reasons.append(f"ngram n{ng_n}")

    p_rn, rn_n = mod_run_ngram(runs)
    if rn_n >= 5:
        votes.append((p_rn, 1.3))
        reasons.append(f"run-ngram n{rn_n}")

    p_et, _ = mod_entropy(runs)
    votes.append((p_et, 0.6))

    if state == "MATURE":
        if p_break >= 0.60:
            votes.append((0.30, 1.8))
            reasons.append(f"MATURE bẻ {p_break*100:.0f}%")
        elif p_break <= 0.40:
            votes.append((0.70, 1.4))
    elif state == "CONFIRMED":
        if p_break <= 0.45:
            last = runs[-1][0]
            votes.append((0.62 if last == "TAI" else 0.38, 1.5))
            reasons.append("CONFIRMED theo")

    cyc = mod_cycle(runs)
    if cyc:
        p = 0.68 if cyc["next_side"] == "TAI" else 0.32
        votes.append((p, 1.8))
        reasons.append(f"cycle {cyc['period']}")

    sym = mod_symmetry(runs)
    if sym:
        p = 0.65 if sym["prediction"] == "TAI" else 0.35
        votes.append((p, 1.2))
        reasons.append(f"sym {sym['span']}")

    morph = mod_morph(runs)
    if morph:
        p = 0.60 if morph["prediction"] == "TAI" else 0.40
        votes.append((p, 1.6))
        reasons.append(f"morph {morph['type']}")

    fc = mod_forecast(runs)
    if fc:
        top = fc[0]
        p = top["prob"] if top["side"] == "TAI" else 1 - top["prob"]
        votes.append((p, 0.9))
        reasons.append(f"fc {top['side']} {top['prob']*100:.0f}%")

    for mod_fn, weight in [
        (mod_1_1, 2.2),
        (mod_2_2, 2.0),
        (mod_3_3, 2.0),
        (mod_4_4, 2.0),
        (mod_1_2_1, 1.5),
        (mod_211_112, 1.4),
        (mod_322_232, 1.4),
        (mod_nghieng, 1.3),
        (mod_giam, 1.3),
        (mod_2211, 1.5),
        (mod_bat_thuong, 1.0),
    ]:
        r = mod_fn(runs)
        if r:
            p = 0.60 if r["prediction"] == "TAI" else 0.40
            votes.append((p, weight))
            reasons.append(f"{r['type']}")

    return votes, reasons, state, last_len, p_break


def ensemble_vote(runs):
    n = len(runs)
    if n < 15:
        return None

    votes, reasons, state, last_len, p_break = _collect_all(runs)
    if not votes:
        return None

    stab = mod_stability(votes)
    total_w = sum(v[1] for v in votes)
    p_tai = sum(v[0] * v[1] for v in votes) / total_w

    anti, anti_rate = mod_anti_flip()
    flipped = False
    conf_boost = 0
    if anti == -1:
        p_tai = 1 - p_tai
        flipped = True
        reasons.append(f"anti-flip {anti_rate*100:.0f}%")
    elif anti == 1:
        conf_boost = 4

    p_tai = max(0.30, min(0.70, p_tai))

    pred = "TAI" if p_tai >= 0.5 else "XIU"
    margin = abs(p_tai - 0.5)
    conf = 55 + int(margin * 120 * stab) + conf_boost
    conf = min(80, max(52, conf))

    return {
        "prediction": pred,
        "confidence": conf,
        "p_tai": p_tai,
        "state": state,
        "p_break": p_break,
        "n_votes": len(votes),
        "reasons": reasons,
        "flipped": flipped,
        "stability": stab,
        "last_side": runs[-1][0],
        "last_len": last_len,
    }


def analyze_sessions(sessions):
    if len(sessions) < 20:
        return None
    valid = []
    for s in sessions:
        raw = s.get("resultTruyenThong") or s.get("result") or s.get("ket_qua")
        side = normalize_side(raw)
        if side:
            rec = {"id": s.get("id", s.get("phien", 0)), "resultTruyenThong": side}
            if s.get("dices"):
                rec["dices"] = s["dices"]
            if s.get("point") is not None:
                rec["point"] = s["point"]
            valid.append(rec)
    if len(valid) < 20:
        return None

    newest_first = [s["resultTruyenThong"] for s in valid[:150]]
    oldest_first = list(reversed(newest_first))
    runs = get_runs(oldest_first)

    result = ensemble_vote(runs)
    if not result:
        return None

    return {
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "pattern_type": f"ENS_{result['state']}",
        "reason": result["reasons"][0] if result["reasons"] else "",
        "thinking": " | ".join(result["reasons"][:3]),
        "last_side": result["last_side"],
        "last_run_len": result["last_len"],
        "runs_last_10": [r[1] for r in runs[-10:]],
        "total_runs": len(runs),
        "state": result["state"],
        "p_break": result["p_break"],
        "n_votes": result["n_votes"],
        "stability": result["stability"],
        "flipped": result["flipped"],
    }


def predict_next():
    try:
        sessions = fetch_sessions()
        if not sessions:
            return None, "API lỗi"
        res = analyze_sessions(sessions)
        if not res:
            return None, "Chưa đủ data"
        return {
            "predict": res["prediction"],
            "confidence": res["confidence"],
            "p_tai": 55 if res["prediction"] == "TAI" else 45,
            "version": res["pattern_type"],
            "regime": res["pattern_type"],
            "tier": "STRONG" if res["confidence"] >= 70 else ("OK" if res["confidence"] >= 60 else "WEAK"),
            "top_id": sessions[0].get("id", 0),
            "reasons": [f"📊 {res['reason']}", f"🧠 {res.get('thinking', '')}"],
            "pattern": res["pattern_type"],
            "last_run_len": res["last_run_len"],
            "last_side": res["last_side"],
        }, None
    except Exception as e:
        return None, f"Lỗi: {e}"


def save_result(session_id, predict_result, actual, signals=None):
    try:
        record_bot_result(predict_result == actual)
    except Exception:
        pass


def get_stats():
    if not _BOT_HISTORY:
        return {}
    total = len(_BOT_HISTORY)
    wins = sum(_BOT_HISTORY)
    return {"total": total, "wins": wins, "rate": wins / total * 100 if total else 0}


def get_module_stats():
    return get_stats()