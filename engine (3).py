# -*- coding: utf-8 -*-
"""LC79 prediction engine v24 — Multi-Layer Meta-Ensemble.

84 thành phần = 21 model lớn + 21 model mini + 42 hàm phụ trợ (aux_*).
Không dùng AI thật: toàn bộ là thống kê / heuristic, có tự hiệu chỉnh theo hiệu suất thực tế.
API, schema DB và các hàm helper giữ nguyên như bản cũ.

Dùng dữ liệu xúc xắc (Model 11 & 22): observe(result, tong=..., dices=[a,b,c]) hoặc
observe_session(session_dict_từ_parse_upstream). Không có xúc xắc thì 2 model này tự im lặng.
"""
from __future__ import annotations
import json, math, os, sqlite3
from collections import deque, defaultdict
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
    conn = sqlite3.connect(DATABASE_PATH, timeout=60.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=60000")
    if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
        conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
CREATE TABLE IF NOT EXISTS tables_ (code TEXT PRIMARY KEY, name TEXT NOT NULL, game_code TEXT NOT NULL, game_name TEXT NOT NULL, upstream_url TEXT NOT NULL, is_active INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS table_states (table_code TEXT PRIMARY KEY REFERENCES tables_(code), history_json TEXT, last_seen_id INTEGER DEFAULT 0, last_poll_at TEXT, last_poll_error TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS predictions (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, session_id INTEGER NOT NULL, prediction TEXT NOT NULL, confidence INTEGER NOT NULL, actual TEXT, result TEXT, resolved_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pred_unique ON predictions(table_code, session_id);
CREATE INDEX IF NOT EXISTS idx_pred_table ON predictions(table_code, session_id DESC);
CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, scope TEXT NOT NULL, note TEXT, is_active INTEGER DEFAULT 1, expires_at TEXT, days INTEGER DEFAULT 7, max_devices INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT, activated INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS api_key_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL REFERENCES api_keys(key), device_id TEXT NOT NULL, ip TEXT, user_agent TEXT, browser TEXT, os TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, released_at TEXT, released_reason TEXT);
CREATE INDEX IF NOT EXISTS idx_devices_key ON api_key_devices(key, released_at);
CREATE TABLE IF NOT EXISTS activation_codes (code TEXT PRIMARY KEY, scope TEXT NOT NULL, days INTEGER NOT NULL, max_uses INTEGER DEFAULT -1, used_count INTEGER DEFAULT 0, expires_at TEXT, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS activation_log (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, code TEXT, success INTEGER, ip TEXT, user_agent TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS admin_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user TEXT, action TEXT, target TEXT, detail_json TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS engine_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, reason TEXT NOT NULL, accuracy_before REAL, sessions_at_reset INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS rate_limits (key TEXT, window TEXT, count INTEGER, PRIMARY KEY (key, window));
""")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(predictions)").fetchall()}
    if "detail_json" not in cols: conn.execute("ALTER TABLE predictions ADD COLUMN detail_json TEXT")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS prediction_resolutions (id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL, session_id INTEGER NOT NULL, prediction TEXT, actual TEXT, result TEXT, regime TEXT, regime_conf REAL, confidence INTEGER, top_module TEXT, top_module_p REAL, module_votes_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_resol_unique ON prediction_resolutions(table_code,session_id);
    CREATE INDEX IF NOT EXISTS idx_resol_date ON prediction_resolutions(created_at);
    CREATE TABLE IF NOT EXISTS table_configs(table_code TEXT PRIMARY KEY,config_json TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS broadcasts(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS worker_control(key TEXT PRIMARY KEY,value TEXT,updated_at TEXT);
    """)
    for i, (code, meta) in enumerate(TABLES.items(), 1):
        conn.execute("INSERT OR IGNORE INTO tables_(code,name,game_code,game_name,upstream_url,is_active,sort_order) VALUES(?,?,?,?,?,1,?)", (code, meta["name"], "lc79", "LC79", meta["url"], i))
        conn.execute("INSERT OR IGNORE INTO table_states(table_code) VALUES(?)", (code,))
    conn.commit(); conn.close()

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
        if not isinstance(point, int) or not (3 <= point <= 18): point = sum(dices) if dices else None
        sessions.append({"session_id": sid, "result": result, "dices": dices, "tong": point})
    sessions.sort(key=lambda s: s["session_id"])
    if not sessions: return None
    return {"sessions": sessions, "latest_id": sessions[-1]["session_id"]}


# =========================================================
# CẤU HÌNH
# =========================================================
DEBUG_STRICT = False   # True: lỗi trong model sẽ raise (dùng khi test). False: model lỗi tự im lặng.
WIN = 200              # cửa sổ tối đa mỗi model nhìn lại
MAX_STORE = 1500       # số phiên lưu tối đa trong history
TAIL_STORE = 400       # số phiên gần nhất lưu kèm tong/xúc xắc
REPLAY = 120           # khi nạp lại engine: chỉ chấm điểm lại N phiên cuối (cho nhanh)

# =========================================================
# TOÁN HỌC CƠ SỞ
# =========================================================
def _clip_prob(p, lo=0.02, hi=0.98):
    return max(lo, min(hi, float(p)))

def _smooth_rate(successes, total, prior=0.5, strength=8.0):
    """Beta smoothing: tránh xác suất cực đoan khi mẫu ít."""
    return (float(successes) + prior * strength) / (float(total) + strength)

def _logit(p):
    p = _clip_prob(p, 1e-4, 1 - 1e-4)
    return math.log(p / (1.0 - p))

def _sigmoid(x):
    x = max(-30.0, min(30.0, x))
    return 1.0 / (1.0 + math.exp(-x))

def _rel(p, n, k=10.0):
    """Độ tin cậy bằng chứng 0..1: cần đủ mẫu (n) VÀ lệch khỏi 0.5 có ý nghĩa."""
    if n <= 0:
        return 0.0
    support = n / (n + k)
    z = abs(float(p) - 0.5) * 2.0 * math.sqrt(n)
    return max(0.0, min(1.0, support * (0.30 + 0.70 * min(1.0, z / 3.0))))

def _side(x):
    return "TÀI" if int(x) == 1 else "XỈU"

def _from_cont(side, p_cont):
    """p_cont = xác suất kết quả kế tiếp == side  ->  xác suất TÀI."""
    return p_cont if int(side) == 1 else 1.0 - p_cont

def _sig(p, conf, why=""):
    return (_clip_prob(p, 0.03, 0.97), max(0.0, min(1.0, float(conf))), why)

def _neutral(why=""):
    return (0.5, 0.0, why)

def _blend(a, b, wb):
    """Gộp tín hiệu chính (a) và mini (b); b có trọng số wb."""
    wa_, wb_ = a[1] * (1.0 - wb), b[1] * wb
    tot = wa_ + wb_
    if tot < 1e-9:
        return (0.5, 0.0, a[2] or b[2])
    p = aux_logit_pool([(a[0], wa_), (b[0], wb_)])
    den = (1.0 - wb) * (1 if a[1] > 0 else 0) + wb * (1 if b[1] > 0 else 0)
    conf = min(1.0, tot / den) if den > 0 else 0.0
    if a[1] > 0:
        why = a[2]
        if b[1] > 0.05 and b[2]:
            why += " | phụ: " + b[2]
    else:
        why = b[2]
    return (_clip_prob(p, 0.03, 0.97), conf, why)

def _pool_bucket(tab, lo, hi):
    lo = max(0, lo); hi = min(len(tab) - 1, hi)
    t = tot = 0
    for b in range(lo, hi + 1):
        t += tab[b][0]; tot += tab[b][1]
    return t, tot

def _clamp(x, lo, hi):
    return max(lo, min(hi, x))

# =========================================================
# 42 HÀM PHỤ TRỢ (aux_*) — thuần hàm, không giữ trạng thái
# =========================================================
def aux_hist_window(h, w):                                   # 1
    return list(h[-w:]) if w > 0 else []

def aux_window_rate(h, w, prior=0.5, strength=2.0):          # 2
    x = h[-w:] if w > 0 else []
    return _smooth_rate(sum(x), len(x), prior, strength)

def aux_runs(h):                                             # 3  RLE: [(side, length), ...]
    out = []
    for x in h:
        if out and out[-1][0] == x:
            out[-1][1] += 1
        else:
            out.append([x, 1])
    return [(s, l) for s, l in out]

def aux_current_run(h):                                      # 4
    if not h:
        return (0, 0)
    s = h[-1]; l = 1; i = len(h) - 2
    while i >= 0 and h[i] == s:
        l += 1; i -= 1
    return (s, l)

def aux_streak_hist_breaks(h, side, length, pool_from=6):    # 5  hazard: (tiếp tục, số lần có rủi ro)
    lens = [l for s, l in aux_runs(h)[:-1] if side is None or s == side]
    if length >= pool_from:
        at_risk = sum(l - pool_from + 1 for l in lens if l >= pool_from)
        breaks = sum(1 for l in lens if l >= pool_from)
        return at_risk - breaks, at_risk
    at_risk = sum(1 for l in lens if l >= length)
    cont = sum(1 for l in lens if l > length)
    return cont, at_risk

def aux_alternation_streak(h):                               # 6  độ dài đuôi đan xen 1-1
    if not h:
        return 0
    k = 1; i = len(h) - 1
    while i > 0 and h[i] != h[i - 1]:
        k += 1; i -= 1
    return k

def aux_pair_streak(h):                                      # 7  số cặp 2-2 liên tiếp ở đuôi
    k = 0
    for s, l in reversed(aux_runs(h)[:-1]):
        if l == 2: k += 1
        else: break
    return k

def aux_ngram_stats(h, k, window=None, half_life=None):      # 8  (TÀI có trọng số, tổng có trọng số)
    seg = h[-window:] if window else list(h)
    m = len(seg)
    if k <= 0 or m <= k:
        return 0.0, 0.0
    pat = seg[-k:]
    lam = 0.5 ** (1.0 / half_life) if half_life else 1.0
    t = tot = 0.0
    for i in range(m - k):
        if seg[i:i + k] == pat:
            w = lam ** (m - k - 1 - i)
            tot += w; t += w * seg[i + k]
    return t, tot

def aux_pattern_signature(h, k=4):                           # 9  vd "1-2-1-3"
    runs = aux_runs(h)
    if not runs:
        return ""
    return "-".join(str(min(9, l)) for _, l in runs[-k:])

def aux_entropy(h, w=60):                                    # 10 entropy khối 2 (chuẩn hoá 0..1)
    x = h[-w:]
    if len(x) < 8:
        return 1.0
    c = [0, 0, 0, 0]
    for a, b in zip(x, x[1:]):
        c[a * 2 + b] += 1
    tot = sum(c)
    H = 0.0
    for v in c:
        if v:
            q = v / tot
            H -= q * math.log2(q)
    return H / 2.0

def aux_runs_test_z(h, w=60):                                # 11 Wald–Wolfowitz (z<0: bệt, z>0: đan xen)
    x = h[-w:]
    n = len(x)
    n1 = sum(x); n2 = n - n1
    if n < 10 or n1 == 0 or n2 == 0:
        return 0.0
    r = 1 + sum(1 for a, b in zip(x, x[1:]) if a != b)
    mu = 2.0 * n1 * n2 / n + 1.0
    var = 2.0 * n1 * n2 * (2.0 * n1 * n2 - n) / (n * n * (n - 1.0))
    return (r - mu) / math.sqrt(var) if var > 1e-12 else 0.0

def aux_autocorr(h, lag=1, w=60):                            # 12
    x = h[-w:]
    n = len(x)
    if n <= lag + 2:
        return 0.0
    m = sum(x) / n
    v = sum((a - m) ** 2 for a in x)
    if v < 1e-12:
        return 0.0
    c = sum((x[i] - m) * (x[i + lag] - m) for i in range(n - lag))
    return c / v

def aux_ema(h, alpha=0.2, init=0.5):                         # 13
    e = init
    for x in h:
        e = alpha * x + (1.0 - alpha) * e
    return e

def aux_imbalance(h, w):                                     # 14 [-1,1], dương = nghiêng TÀI
    x = h[-w:]
    return (2.0 * sum(x) / len(x) - 1.0) if x else 0.0

def aux_slope(h, w):                                         # 15 thay đổi ước lượng trên cả cửa sổ
    x = h[-w:]
    n = len(x)
    if n < 4:
        return 0.0
    mt = (n - 1) / 2.0; mx = sum(x) / n
    num = sum((i - mt) * (x[i] - mx) for i in range(n))
    den = sum((i - mt) ** 2 for i in range(n))
    return (num / den) * (n - 1) if den > 0 else 0.0

def aux_momentum(h, short=5, long=20):                       # 16
    a = h[-short:]; b = h[-long:]
    if not a or not b:
        return 0.0
    return sum(a) / len(a) - sum(b) / len(b)

def aux_flip_rate(h, w):                                     # 17
    x = h[-w:]
    if len(x) < 2:
        return 0.5
    return sum(1 for a, b in zip(x, x[1:]) if a != b) / (len(x) - 1)

def aux_longest_run(h, w):                                   # 18
    x = h[-w:]
    if not x:
        return 0
    best = cur = 1
    for i in range(1, len(x)):
        cur = cur + 1 if x[i] == x[i - 1] else 1
        best = max(best, cur)
    return best

def aux_zscore_rate(h, w):                                   # 19
    x = h[-w:]
    n = len(x)
    return (sum(x) - n / 2.0) / math.sqrt(n / 4.0) if n else 0.0

def aux_cusum_stat(x, ref=None, k=0.0):                      # 20 (S+, S-)
    if not x:
        return 0.0, 0.0
    ref = sum(x) / len(x) if ref is None else ref
    sp = sn = 0.0
    for v in x:
        sp = max(0.0, sp + (v - ref) - k)
        sn = max(0.0, sn - (v - ref) - k)
    return sp, sn

def aux_brier(errs):                                         # 21
    return (sum(errs) / len(errs)) if errs else 0.25

def aux_skill(errs, hits):                                   # 22 điểm kỹ năng 0.2..1.4 từ hiệu suất thực tế
    if not hits:
        return 0.75
    acc = (sum(hits) + 10.0) / (len(hits) + 20.0)
    b_term = 1.0 - aux_brier(errs) / 0.25
    return max(0.20, min(1.40, 0.75 + 0.5 * (acc - 0.5) * 10.0 + 3.0 * b_term))

def aux_shrink(p, n, strength=10.0):                         # 23
    return 0.5 + (p - 0.5) * (n / (n + strength)) if n > 0 else 0.5

def aux_logit_pool(items):                                   # 24 trung bình logit có trọng số [(p, w), ...]
    s = sw = 0.0
    for p, w in items:
        if w > 0:
            s += _logit(p) * w; sw += w
    return _sigmoid(s / sw) if sw > 1e-12 else 0.5

def aux_softmax_weights(scores, temp=1.0):                   # 25
    if not scores:
        return []
    m = max(scores)
    e = [math.exp((s - m) / max(1e-9, temp)) for s in scores]
    t = sum(e)
    return [v / t for v in e]

def aux_gini(ws):                                            # 26 độ tập trung trọng số 0..1
    x = sorted(max(0.0, float(v)) for v in ws)
    n = len(x); s = sum(x)
    if n < 2 or s <= 0:
        return 0.0
    return max(0.0, (2.0 * sum((i + 1) * v for i, v in enumerate(x))) / (n * s) - (n + 1.0) / n)

def aux_cap_and_renorm(ws, cap):                             # 27 chặn tỉ trọng tối đa, trả về tỉ trọng (tổng 1)
    tot = sum(max(0.0, w) for w in ws)
    if tot <= 0:
        return [0.0 for _ in ws]
    sh = [max(0.0, w) / tot for w in ws]
    act = [i for i, s in enumerate(sh) if s > 0]
    if cap * len(act) < 1.0:
        return [(1.0 / len(act)) if s > 0 else 0.0 for s in sh]
    for _ in range(8):
        over = [i for i in act if sh[i] > cap + 1e-12]
        if not over:
            break
        excess = sum(sh[i] - cap for i in over)
        for i in over:
            sh[i] = cap
        free = [i for i in act if sh[i] < cap - 1e-12]
        fs = sum(sh[i] for i in free)
        if not free or fs <= 0:
            break
        for i in free:
            sh[i] += excess * sh[i] / fs
    return sh

def aux_side_share(ps, ws):                                  # 28 tỉ trọng nghiêng TÀI
    tot = sum(max(0.0, w) for w in ws)
    if tot <= 1e-12:
        return 0.5
    return sum(w for p, w in zip(ps, ws) if p >= 0.5 and w > 0) / tot

def aux_binom_pvalue(k, n):                                  # 29
    if n <= 0:
        return 1.0
    z = (k - n / 2.0) / math.sqrt(n / 4.0)
    return math.erfc(abs(z) / math.sqrt(2.0))

def aux_wilson_interval(k, n, z=1.645):                      # 30
    if n <= 0:
        return 0.0, 1.0
    ph = k / n
    d = 1.0 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    r = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - r), min(1.0, c + r)

def aux_dice_sum_stats(tongs, w):                            # 31 (mean, std)
    x = tongs[-w:]
    if not x:
        return 10.5, 2.958
    m = sum(x) / len(x)
    return m, math.sqrt(sum((v - m) ** 2 for v in x) / len(x))

def aux_tong_distance(tongs, w):                             # 32
    x = tongs[-w:]
    return sum(abs(v - 10.5) for v in x) / len(x) if x else 0.0

def aux_tong_markov(tongs, k=3):                             # 33 (TÀI, tổng) sau cùng nhóm TB-k-phiên
    n = len(tongs)
    if n <= k:
        return 0, 0
    key = int(round(sum(tongs[-k:]) / k))
    t = tot = 0
    for i in range(k, n):
        if int(round(sum(tongs[i - k:i]) / k)) == key:
            tot += 1
            t += 1 if tongs[i] >= 11 else 0
    return t, tot

def aux_tong_extremity(t):                                   # 34 [-1,1]
    return _clamp((float(t) - 10.5) / 7.5, -1.0, 1.0)

def aux_dice_face_freq(dices, w):                            # 35
    f = [0] * 6
    for d in dices[-w:]:
        for v in d:
            f[v - 1] += 1
    return f

def aux_dice_triple_count(dices, w):                         # 36
    return sum(1 for d in dices[-w:] if d[0] == d[1] == d[2])

def aux_dice_balance(dices, w):                              # 37 z mặt cao (4-6) so với kỳ vọng
    x = dices[-w:]
    N = 3 * len(x)
    if N == 0:
        return 0.0
    hi = sum(1 for d in x for v in d if v >= 4)
    return (hi - N / 2.0) / math.sqrt(N / 4.0)

def aux_gap_since_extreme(tongs):                            # 38 số phiên từ lần tong<=5 hoặc >=16
    g = 0
    for t in reversed(tongs):
        if t <= 5 or t >= 16:
            return g
        g += 1
    return g

def aux_volatility(tongs, w):                                # 39
    x = tongs[-w:]
    if len(x) < 3:
        return 0.0
    d = [b - a for a, b in zip(x, x[1:])]
    m = sum(d) / len(d)
    return math.sqrt(sum((v - m) ** 2 for v in d) / len(d))

def aux_agreement(ps, ws):                                   # 40 độ đồng thuận 0.5..1
    s = aux_side_share(ps, ws)
    return max(s, 1.0 - s)

def aux_decay_weights(n, half_life):                         # 41 cũ -> mới (mới nhất = 1)
    lam = 0.5 ** (1.0 / half_life)
    return [lam ** (n - 1 - i) for i in range(n)]

def aux_rate_bucket_table(h, w):                             # 42 tab[b] = [TÀI kế tiếp, tổng] khi w phiên trước có b TÀI
    n = len(h)
    tab = [[0, 0] for _ in range(w + 1)]
    if n <= w:
        return tab
    ps = [0]
    for x in h:
        ps.append(ps[-1] + x)
    for i in range(w, n):
        b = ps[i] - ps[i - w]
        tab[b][1] += 1
        tab[b][0] += h[i]
    return tab

# =========================================================
# NGỮ CẢNH & QUÉT MẪU CẦU DÙNG CHUNG
# =========================================================
def _clean_tong(x):
    try:
        v = int(x)
    except (TypeError, ValueError):
        return None
    return v if 3 <= v <= 18 else None

def _clean_dices(x):
    if isinstance(x, (list, tuple)) and len(x) == 3:
        try:
            d = [int(v) for v in x]
        except (TypeError, ValueError):
            return None
        if all(1 <= v <= 6 for v in d):
            return d
    return None

def _tail_known(seq, n):
    """Đoạn cuối liên tục không-None trong n phần tử cuối."""
    if not seq:
        return []
    out = []
    for v in reversed(list(seq[-n:])):
        if v is None:
            break
        out.append(v)
    out.reverse()
    return out

def _tmpl_state(lens, r, L, q):
    """Mẫu tuần hoàn chu kỳ q theo độ dài các cạnh cầu. Trả (độ chắc m, độ dài kỳ vọng E, tiếp tục?) hoặc None."""
    if r < q + 1:
        return None
    m = 0; j = 1
    while r - j - q >= 0 and lens[r - j] == lens[r - j - q]:
        m += 1; j += 1
    if m == 0:
        return None
    E = lens[r - q]
    if L > E:
        return None
    return (min(m, 6), E, L < E)

def _template_scan(h):
    n = len(h)
    lens = []; rid = [0] * n; lsf = [0] * n
    for i, x in enumerate(h):
        if i == 0 or x != h[i - 1]:
            lens.append(1)
        else:
            lens[-1] += 1
        rid[i] = len(lens) - 1; lsf[i] = lens[-1]
    recs = {1: [], 2: [], 3: []}
    for i in range(4, n):
        r = rid[i - 1]; L = lsf[i - 1]
        for q in (1, 2, 3):
            st = _tmpl_state(lens, r, L, q)
            if st:
                recs[q].append((st[0], int((h[i] == h[i - 1]) == st[2])))
    now = {}
    if n > 0:
        r = rid[-1]; L = lsf[-1]
        for q in (1, 2, 3):
            st = _tmpl_state(lens, r, L, q)
            if st:
                now[q] = st
    return {"lens": lens, "rid": rid, "lsf": lsf, "recs": recs, "now": now}

def _tmpl_name(lens, q, E):
    r = len(lens) - 1
    if q == 1:
        return {1: "cầu 1-1 (ping-pong)", 2: "cầu 2-2", 3: "cầu 3-3"}.get(E, "cầu bệt %d-%d" % (E, E))
    return "cầu " + "-".join(str(x) for x in lens[r - q:r])

class Ctx:
    """Ngữ cảnh tính 1 lần / lần dự đoán, dùng chung cho mọi model."""
    def __init__(self, hist, tongs=None, dices=None):
        self.h = [int(x) for x in hist[-WIN:]]
        self.n = len(self.h)
        self.tongs = _tail_known(tongs, self.n) if tongs else []
        self.dices = _tail_known(dices, self.n) if dices else []
        self.side, self.run = aux_current_run(self.h)
        self._cache = {}

    def cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def scan(self):
        return self.cached("scan", lambda: _template_scan(self.h))

def _imbalance_signal(ctx, w, thr, tag):
    h = ctx.h
    if ctx.n < w * 2:
        return _neutral()
    t = sum(h[-w:]); d = 2 * t - w
    if abs(d) < thr:
        return _neutral("%s gần nhất cân bằng (%d TÀI/%d XỈU)" % (tag, t, w - t))
    minority = 0 if d > 0 else 1
    tab = ctx.cached(("tab", w), lambda: aux_rate_bucket_table(h, w))
    lo, hi = (t, w) if d > 0 else (0, t)
    tai, tot = _pool_bucket(tab, lo, hi)
    cnt_min = (tot - tai) if minority == 0 else tai
    prior = 0.5 + min(0.08, 0.012 * (abs(d) - thr + 1))
    p_min = (cnt_min + prior * 10.0) / (tot + 10.0)
    p = p_min if minority == 1 else 1.0 - p_min
    return _sig(p, _rel(p_min, tot, 10),
                "%s: %d TÀI/%d XỈU (lệch %d) → nghiêng %s để cân bằng; lịch sử cùng mức lệch ra %s %d/%d lần"
                % (tag, t, w - t, abs(d), _side(minority), _side(minority), cnt_min, tot))

# =========================================================
# 14 MODEL TẦNG 1 (dự đoán hướng) — mỗi model = main + mini
# =========================================================
class _Stage1:
    mid = ""; label = ""; code = ""; wb = 0.25
    def predict(self, ctx):
        return _blend(self.main(ctx), self.mini(ctx), self.wb)

class M01Pattern(_Stage1):
    """Model 1 (+9): nhận biết cầu cơ bản 1-1, 2-2, 3-3, 1-2-1, 2-1-2, 3-1, 1-3, bệt... theo chu kỳ độ dài cạnh."""
    mid = "m01_pattern"; label = "Cầu cơ bản"; code = "M01"; wb = 0.25
    def main(self, ctx):
        if ctx.n < 14:
            return _neutral("Chưa đủ dữ liệu nhận dạng cầu")
        sc = ctx.scan(); now = sc["now"]
        if not now:
            return _neutral("Chưa thấy mẫu cầu cơ bản (dạng %s)" % aux_pattern_signature(ctx.h))
        q = max(now, key=lambda k: (now[k][0], -k))
        m, E, cont = now[q]
        recs = sc["recs"][q]; trials = len(recs); hits = sum(c for _, c in recs)
        acc = _smooth_rate(hits, trials, 0.5, 6.0)
        p_cont = acc if cont else 1.0 - acc
        p = _from_cont(ctx.side, p_cont)
        return _sig(p, _rel(acc, trials, 8),
                    "%s (khớp %d chu kỳ) → %s; độ đúng lịch sử %.0f%% (%d/%d)"
                    % (_tmpl_name(sc["lens"], q, E), m, "tiếp tục" if cont else "đảo chiều", acc * 100, hits, trials))
    def mini(self, ctx):
        k = aux_alternation_streak(ctx.h)
        if ctx.n < 14 or k < 4:
            return _neutral()
        fr = aux_flip_rate(ctx.h, 24)
        return _sig(_from_cont(ctx.side, 1.0 - fr), _rel(1.0 - fr, 24, 8) * min(1.0, k / 6.0),
                    "ping-pong %d nhịp, tần suất đảo gần đây %.0f%%" % (k, fr * 100))

class M02Trend(_Stage1):
    """Model 2: bắt xu hướng ngắn (6) và dài (24) bằng bảng điều kiện từ lịch sử."""
    mid = "m02_trend"; label = "Xu hướng ngắn/dài"; code = "M02"; wb = 0.25
    def main(self, ctx):
        h = ctx.h
        if ctx.n < 40:
            return _neutral("Chưa đủ dữ liệu xu hướng")
        items = []; info = []
        for w, rad in ((6, 1), (24, 3)):
            tab = ctx.cached(("tab", w), lambda w=w: aux_rate_bucket_table(h, w))
            b = sum(h[-w:])
            t, tot = _pool_bucket(tab, b - rad, b + rad)
            p = _smooth_rate(t, tot, 0.5, 12.0)
            items.append((p, _rel(p, tot, 12)))
            info.append(b)
        p = aux_logit_pool(items)
        conf = max(c for _, c in items)
        same = (info[0] - 3) * (info[1] - 12) > 0
        return _sig(p, conf, "xu hướng ngắn %d/6 TÀI, dài %d/24 TÀI (%s); lịch sử nhóm tương tự → TÀI %.0f%%"
                    % (info[0], info[1], "đồng thuận" if same else "lệch pha", p * 100))
    def mini(self, ctx):
        if ctx.n < 30:
            return _neutral()
        mom = aux_momentum(ctx.h, 5, 20); sl = aux_slope(ctx.h, 12)
        s = 0.6 * mom + 0.2 * sl
        return _sig(0.5 + _clamp(0.12 * s, -0.1, 0.1), min(0.3, abs(s) * 0.6),
                    "động lượng 5/20 = %+.2f, độ dốc 12 = %+.2f" % (mom, sl))

class M03Imbalance(_Stage1):
    """Model 3: 12 phiên gần nhất lệch cao → nghiêng bên còn lại (đã hiệu chỉnh bằng lịch sử)."""
    mid = "m03_imbalance12"; label = "Lệch 12 phiên"; code = "M03"; wb = 0.25
    def main(self, ctx):
        return _imbalance_signal(ctx, 12, 4, "12 phiên")
    def mini(self, ctx):
        return _imbalance_signal(ctx, 6, 4, "6 phiên")

class M04ShortBridge(_Stage1):
    """Model 4: cầu ngắn hạn — n-gram 4/3/2 trên 60 phiên gần nhất, có suy giảm theo thời gian."""
    mid = "m04_short_bridge"; label = "Cầu ngắn hạn"; code = "M04"; wb = 0.25
    def main(self, ctx):
        h = ctx.h
        if ctx.n < 14:
            return _neutral()
        for k in (4, 3, 2):
            t, tot = aux_ngram_stats(h, k, window=60, half_life=30)
            if tot >= 3.0:
                p = _smooth_rate(t, tot, 0.5, 4.0)
                pat = "".join("T" if x else "X" for x in h[-k:])
                return _sig(p, _rel(p, tot, 6), "cầu ngắn %s lặp ~%.0f lần trong 60 phiên → TÀI %.0f%%" % (pat, tot, p * 100))
        return _neutral("Chưa có cầu ngắn lặp đủ số lần")
    def mini(self, ctx):
        h = ctx.h
        if ctx.n < 14:
            return _neutral()
        t, tot = aux_ngram_stats(h, 1, window=40, half_life=20)
        if tot < 5:
            return _neutral()
        p = _smooth_rate(t, tot, 0.5, 6.0)
        return _sig(p, _rel(p, tot, 8) * 0.8, "sau %s thường ra TÀI %.0f%% (40 phiên)" % (_side(h[-1]), p * 100))

class M06FollowBreak(_Stage1):
    """Model 6: biết khi nào nên THEO cầu, khi nào nên BẺ (và khi nào KHÔNG nên bẻ)."""
    mid = "m06_follow_break"; label = "Theo/Bẻ cầu"; code = "M06"; wb = 0.25
    def main(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 24:
            return _neutral()
        side, L = ctx.side, ctx.run
        cont, tot = aux_streak_hist_breaks(h, None, L)
        p_h = _smooth_rate(cont, tot, 0.5, 8.0)
        seg = h[-41:]
        fol = [1 if seg[i] == seg[i - 1] else 0 for i in range(1, len(seg))]
        fr = _smooth_rate(sum(fol), len(fol), 0.5, 10.0)
        fr8 = sum(fol[-8:]) / max(1, len(fol[-8:]))
        p_cont = 0.6 * p_h + 0.4 * fr
        notes = []
        longest = aux_longest_run(h, 60)
        if p_cont < 0.5 and L <= 2 and tot < 12:
            p_cont = 0.5 + (p_cont - 0.5) * 0.5; notes.append("cầu mới hình thành, chưa nên bẻ sớm")
        elif p_cont < 0.5 and L <= 3 and fr8 >= 0.7:
            p_cont = 0.5 + (p_cont - 0.5) * 0.5; notes.append("cầu đang chạy liền mạch, không bẻ vội")
        elif p_cont >= 0.5 and L >= longest and L >= 4:
            p_cont = 0.5 + (p_cont - 0.5) * 0.5; notes.append("cầu chạm độ dài tối đa gần đây (%d), thận trọng" % longest)
        mode = "BẺ" if p_cont < 0.5 else "THEO"
        why = "cầu %s dài %d: lịch sử cầu dài %d tiếp tục %d/%d, 40 phiên gần đây theo cầu %.0f%% → %s" % (_side(side), L, L, cont, tot, fr * 100, mode)
        if notes:
            why += " (" + "; ".join(notes) + ")"
        return _sig(_from_cont(side, p_cont), _rel(p_cont, tot + 20, 12) * (0.6 if notes else 1.0), why)
    def mini(self, ctx):
        h = ctx.h
        if ctx.n < 24:
            return _neutral()
        L = ctx.run; longest = max(1, aux_longest_run(h[:-L] if ctx.n > L else h, 60))
        ratio = L / float(longest)
        if ratio <= 0.7 or L < 3:
            return _neutral()
        p_break = min(0.62, 0.5 + 0.15 * (ratio - 0.7))
        return _sig(_from_cont(ctx.side, 1.0 - p_break), 0.25 * min(1.0, (ratio - 0.7) / 0.3),
                    "cầu %d gần chạm mức dài nhất gần đây (%d) → dễ bẻ" % (L, longest))

class M10BreakProb(_Stage1):
    """Model 10: xác suất bẻ cầu theo hazard độ dài cầu hiện tại."""
    mid = "m10_break_prob"; label = "Xác suất bẻ cầu"; code = "M10"; wb = 0.2
    def main(self, ctx):
        h = ctx.h
        if ctx.n < 20:
            return _neutral()
        L = ctx.run
        cs, ts = aux_streak_hist_breaks(h, ctx.side, L)
        ca, ta = aux_streak_hist_breaks(h, None, L)
        p_cont = (cs + 0.5 * ca + 4.0) / (ts + 0.5 * ta + 8.0)
        n_eff = ts + 0.5 * ta
        return _sig(_from_cont(ctx.side, p_cont), _rel(p_cont, n_eff, 10),
                    "xác suất bẻ cầu %s dài %d = %.0f%% (mẫu %d)" % (_side(ctx.side), L, (1 - p_cont) * 100, ta))
    def mini(self, ctx):
        h = ctx.h
        runs = [l for _, l in aux_runs(h)[:-1]]
        if len(runs) < 8:
            return _neutral()
        mean = sum(runs) / len(runs)
        p_break = _clamp(1.0 / mean, 0.2, 0.8)
        return _sig(_from_cont(ctx.side, 1.0 - p_break), _rel(p_break, len(runs), 12) * 0.7,
                    "độ dài cầu trung bình %.2f → bẻ %.0f%%" % (mean, p_break * 100))

class M11Dice(_Stage1):
    """Model 11: biến động xúc xắc & nguyên lý xúc xắc (tổng ~10.5, hồi quy về trung bình)."""
    mid = "m11_dice"; label = "Biến động xúc xắc"; code = "M11"; wb = 0.25
    def main(self, ctx):
        tg = ctx.tongs
        if len(tg) < 24:
            return _neutral("Chưa có đủ dữ liệu xúc xắc")
        w = min(8, len(tg))
        mean, _ = aux_dice_sum_stats(tg, w)
        z = (mean - 10.5) / (2.958 / math.sqrt(w))
        vol = aux_volatility(tg, 12)
        tai, tot = aux_tong_markov(tg, 3)
        prior = 0.5 + _clamp(-0.02 * z, -0.06, 0.06)
        p = (tai + prior * 10.0) / (tot + 10.0)
        tri = aux_dice_triple_count(ctx.dices, 20) if ctx.dices else 0
        return _sig(p, _rel(p, tot, 10) * 0.9,
                    "tổng điểm %d phiên TB %.1f (lệch %+.1fσ so với 10.5), biến động %.1f, bão/20 phiên: %d → TÀI %.0f%%"
                    % (w, mean, z, vol, tri, p * 100))
    def mini(self, ctx):
        dc = ctx.dices
        if len(dc) >= 20:
            z = aux_dice_balance(dc, 20)
            return _sig(0.5 - 0.015 * _clamp(z, -3, 3), min(0.3, abs(z) / 8.0),
                        "mặt cao/thấp 20 phiên lệch %+.1fσ → hồi quy" % z)
        tg = ctx.tongs
        if len(tg) < 10:
            return _neutral()
        e = aux_tong_extremity(tg[-1])
        return _sig(0.5 - 0.03 * e, 0.15 * abs(e), "tổng điểm gần nhất %d (cực trị %+.2f) → hồi quy" % (tg[-1], e))

class M12Patterns(_Stage1):
    """Model 12: nhận diện rất nhiều mẫu cầu — PPM bậc 1..6 (trộn các bậc từ thấp lên cao)."""
    mid = "m12_ppm"; label = "Đa mẫu cầu (PPM)"; code = "M12"; wb = 0.2
    @staticmethod
    def _cycle_pred(h, i):
        for d in range(2, 7):
            if i >= 2 * d and h[i - d:i] == h[i - 2 * d:i - d]:
                return h[i - d]
        return None
    def main(self, ctx):
        if ctx.n < 30:
            return _neutral()
        seg = ctx.h[-200:]; m = len(seg); K = 6
        tabs = [defaultdict(lambda: [0, 0]) for _ in range(K + 1)]
        for k in range(1, K + 1):
            d = tabs[k]
            for i in range(k, m):
                d[tuple(seg[i - k:i])][seg[i]] += 1
        p = 0.5; top = 0; topn = 0; lam = 2.5
        for k in range(1, K + 1):
            c = tabs[k].get(tuple(seg[-k:]))
            if not c:
                break
            tot = c[0] + c[1]
            p = (c[1] + lam * p) / (tot + lam); top = k; topn = tot
        if top == 0:
            return _neutral()
        pat = "".join("T" if x else "X" for x in seg[-top:])
        return _sig(p, _rel(p, topn, 10) * (0.5 + 0.5 * min(1.0, top / 4.0)),
                    "PPM bậc %d: mẫu %s đã gặp %d lần → TÀI %.0f%%" % (top, pat, topn, p * 100))
    def mini(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 30:
            return _neutral()
        pred = self._cycle_pred(h, n)
        if pred is None:
            return _neutral()
        hits = trials = 0
        for i in range(max(12, n - 100), n):
            pr = self._cycle_pred(h, i)
            if pr is not None:
                trials += 1; hits += int(pr == h[i])
        acc = _smooth_rate(hits, trials, 0.5, 8.0)
        return _sig(acc if pred == 1 else 1.0 - acc, _rel(acc, trials, 8) * 0.8,
                    "chu kỳ lặp đang chạy, độ đúng %.0f%% (%d/%d)" % (acc * 100, hits, trials))

class M14TrendBreak(_Stage1):
    """Model 14: xác suất bẻ xu hướng theo "tuổi" xu hướng (10 phiên)."""
    mid = "m14_trend_break"; label = "Bẻ xu hướng"; code = "M14"; wb = 0.2
    def main(self, ctx):
        h = ctx.h; n = ctx.n; W = 10
        if n < 40:
            return _neutral()
        ps = [0]
        for x in h:
            ps.append(ps[-1] + x)
        buckets = defaultdict(lambda: [0, 0])
        def bk(a):
            return 1 if a <= 1 else 2 if a <= 2 else 3 if a <= 4 else 4 if a <= 7 else 5
        age = 0; prev = 0; s = 0; cnt = 0
        for i in range(W, n + 1):
            cnt = ps[i] - ps[i - W]
            s = 1 if cnt > 5 else (-1 if cnt < 5 else 0)
            if s != 0 and s == prev: age += 1
            elif s != 0: age = 1
            else: age = 0
            prev = s
            if i < n and s != 0:
                b = buckets[bk(age)]; b[1] += 1; b[0] += int(h[i] != (1 if s > 0 else 0))
        if s == 0:
            return _neutral("xu hướng 10 phiên cân bằng")
        ag, tot = buckets.get(bk(age), (0, 0))
        p_ag = _smooth_rate(ag, tot, 0.5, 10.0)
        trend = 1 if s > 0 else 0
        against = 1 - trend
        p = p_ag if against == 1 else 1.0 - p_ag
        return _sig(p, _rel(p_ag, tot, 10),
                    "xu hướng %s (10 phiên %d/10) tuổi %d; lịch sử bẻ xu hướng ở tuổi này %.0f%% (%d/%d)"
                    % (_side(trend), cnt, age, p_ag * 100, ag, tot))
    def mini(self, ctx):
        h = ctx.h
        if ctx.n < 40:
            return _neutral()
        a = aux_imbalance(h, 10); b = aux_imbalance(h, 30)
        if a * b >= 0 or abs(a) < 0.2 or abs(b) < 0.1:
            return _neutral()
        return _sig(0.5 + 0.05 * (1 if b > 0 else -1), 0.25, "xu hướng ngắn ngược xu hướng dài → hướng về xu hướng dài")

class M15FollowTrend(_Stage1):
    """Model 15: "suy nghĩ" có nên bắt theo xu hướng không — 3 bằng chứng: chiến lược, tự tương quan, runs-test."""
    mid = "m15_follow_trend"; label = "Có nên theo xu hướng"; code = "M15"; wb = 0.25
    def main(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 50:
            return _neutral()
        ps = [0]
        for x in h:
            ps.append(ps[-1] + x)
        hits = tr = 0
        for i in range(max(10, n - 40), n):
            c = ps[i] - ps[i - 10]
            if c == 5:
                continue
            tr += 1; hits += int((1 if c > 5 else 0) == h[i])
        wr = _smooth_rate(hits, tr, 0.5, 10.0)
        ac = aux_autocorr(h, 1, 60); z = aux_runs_test_z(h, 60)
        score = (wr - 0.5) * 4.0 + _clamp(ac * 3.0, -1, 1) + _clamp(-z / 3.0, -1, 1)
        c10 = sum(h[-10:])
        trend = ctx.side if c10 == 5 else (1 if c10 > 5 else 0)
        target = trend if score > 0 else 1 - trend
        edge = min(0.08, abs(score) * 0.025)
        p = 0.5 + edge if target == 1 else 0.5 - edge
        verdict = "NÊN bắt theo xu hướng" if score > 0 else "KHÔNG nên bắt theo xu hướng"
        return _sig(p, _rel(0.5 + edge, 60, 15) * min(1.0, abs(score) / 1.5),
                    "chiến lược theo-xu-hướng thắng %.0f%% (40 phiên), tự tương quan %+.2f, runs-test z=%+.1f → %s"
                    % (wr * 100, ac, z, verdict))
    def mini(self, ctx):
        if ctx.n < 50:
            return _neutral()
        ac = aux_autocorr(ctx.h, 1, 60)
        if abs(ac) < 0.2:
            return _neutral()
        c10 = sum(ctx.h[-10:])
        trend = ctx.side if c10 == 5 else (1 if c10 > 5 else 0)
        target = trend if ac > 0 else 1 - trend
        return _sig(0.5 + 0.04 if target == 1 else 0.5 - 0.04, 0.25, "tự tương quan mạnh %+.2f" % ac)

class M16BridgeBreak(_Stage1):
    """Model 16: xác suất bẻ cầu của mẫu cầu đang chạy, tính theo độ chắc của mẫu."""
    mid = "m16_bridge_break"; label = "Bẻ cầu theo mẫu"; code = "M16"; wb = 0.25
    def main(self, ctx):
        if ctx.n < 20:
            return _neutral()
        sc = ctx.scan(); now = sc["now"]
        if not now:
            return _neutral("chưa có cầu chu kỳ để tính xác suất bẻ")
        q = max(now, key=lambda k: (now[k][0], -k))
        m, E, cont = now[q]
        recs = sc["recs"][q]; tr = len(recs); hits = sum(c for _, c in recs)
        prior = _smooth_rate(hits, tr, 0.5, 6.0)
        mb = min(m, 4)
        sub = [c for mm, c in recs if min(mm, 4) == mb]
        pc = (sum(sub) + prior * 8.0) / (len(sub) + 8.0)
        p_cont = pc if cont else 1.0 - pc
        p_break = 1.0 - p_cont
        breaking = p_break > 0.5
        return _sig(_from_cont(ctx.side, p_cont), _rel(pc, len(sub) + tr * 0.3, 10) * (1.0 if breaking else 0.6),
                    "xác suất bẻ %s = %.0f%% (độ chắc %d, mẫu %d) → %s"
                    % (_tmpl_name(sc["lens"], q, E), p_break * 100, m, len(sub), "BẺ" if breaking else "GIỮ"))
    def mini(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 30:
            return _neutral()
        k = aux_alternation_streak(h)
        if k < 3:
            return _neutral()
        tab = defaultdict(lambda: [0, 0]); a = 1
        for i in range(1, n):
            alt = int(h[i] != h[i - 1])
            if a >= 3:
                t = tab[min(a, 8)]; t[1] += 1; t[0] += alt
            a = a + 1 if alt else 1
        c, t = tab.get(min(k, 8), (0, 0))
        p_alt = _smooth_rate(c, t, 0.5, 8.0)
        return _sig(_from_cont(ctx.side, 1.0 - p_alt), _rel(p_alt, t, 10) * 0.8,
                    "đan xen %d nhịp, lịch sử đan xen tiếp %.0f%% (%d/%d)" % (k, p_alt * 100, c, t))

class M18RunTrend(_Stage1):
    """Model 18: xu hướng của độ dài cầu (tăng/giảm dần) + hướng ngắn hạn 5 phiên."""
    mid = "m18_run_trend"; label = "Xu hướng độ dài cầu"; code = "M18"; wb = 0.25
    def main(self, ctx):
        n = ctx.n; h = ctx.h
        if n < 40:
            return _neutral()
        sc = ctx.scan(); lens, rid, lsf = sc["lens"], sc["rid"], sc["lsf"]
        def key(r, L):
            if r < 3:
                return None
            prev = lens[r - 1]
            c = (L > prev) - (L < prev)
            a, b, c3 = lens[r - 3], lens[r - 2], lens[r - 1]
            return (c, 1 if a < b < c3 else (-1 if a > b > c3 else 0))
        tab = defaultdict(lambda: [0, 0])
        for i in range(4, n):
            k = key(rid[i - 1], lsf[i - 1])
            if k is None:
                continue
            t = tab[k]; t[1] += 1; t[0] += int(h[i] == h[i - 1])
        k = key(rid[-1], lsf[-1])
        if k is None:
            return _neutral()
        cont, tot = tab.get(k, (0, 0))
        p_cont = _smooth_rate(cont, tot, 0.5, 8.0)
        cmpn = {1: "dài hơn", 0: "bằng", -1: "ngắn hơn"}[k[0]]
        trn = {1: "tăng dần", -1: "giảm dần", 0: "đều/không rõ"}[k[1]]
        return _sig(_from_cont(ctx.side, p_cont), _rel(p_cont, tot, 10),
                    "độ dài cầu gần đây %s (%s), cầu hiện tại %d %s cầu trước → tiếp tục %.0f%% (%d/%d)"
                    % (lens[-4:-1], trn, ctx.run, cmpn, p_cont * 100, cont, tot))
    def mini(self, ctx):
        if ctx.n < 20:
            return _neutral()
        cnt = sum(ctx.h[-5:]); st = abs(2 * cnt - 5) / 5.0
        maj = 1 if cnt >= 3 else 0
        return _sig(0.5 + (0.05 * st if maj else -0.05 * st), 0.25 * st, "5 phiên gần nhất nghiêng %s (%d/5)" % (_side(maj), cnt if maj else 5 - cnt))

def _d_bet3(h, i):
    if i >= 3 and h[i - 1] == h[i - 2] == h[i - 3]: return h[i - 1]
def _d_bet5(h, i):
    if i >= 5 and h[i - 1] == h[i - 2] == h[i - 3] == h[i - 4] == h[i - 5]: return 1 - h[i - 1]
def _d_ping4(h, i):
    if i >= 4 and h[i - 1] != h[i - 2] and h[i - 2] != h[i - 3] and h[i - 3] != h[i - 4]: return 1 - h[i - 1]
def _d_pair22(h, i):
    if i >= 4 and h[i - 4] == h[i - 3] != h[i - 2] == h[i - 1]: return 1 - h[i - 1]
def _d_pairmid(h, i):
    if i >= 4 and h[i - 3] == h[i - 2] != h[i - 1] and h[i - 4] != h[i - 3]: return h[i - 1]
def _d_triple33(h, i):
    if i >= 6 and h[i - 6] == h[i - 5] == h[i - 4] != h[i - 3] == h[i - 2] == h[i - 1]: return 1 - h[i - 1]
def _d_121(h, i):
    if i >= 4 and h[i - 4] != h[i - 3] == h[i - 2] != h[i - 1] and h[i - 4] == h[i - 1]: return h[i - 1]
def _d_212(h, i):
    if i >= 5 and h[i - 5] == h[i - 4] != h[i - 3] != h[i - 2] == h[i - 1] and h[i - 5] == h[i - 1]: return 1 - h[i - 1]
def _d_31(h, i):
    if i >= 4 and h[i - 4] == h[i - 3] == h[i - 2] != h[i - 1]: return 1 - h[i - 1]
def _d_13(h, i):
    if i >= 4 and h[i - 4] != h[i - 3] == h[i - 2] == h[i - 1]: return 1 - h[i - 1]

DETECTORS = [("bệt 3+", _d_bet3), ("bệt 5 bẻ", _d_bet5), ("1-1 (4 nhịp)", _d_ping4), ("2-2", _d_pair22),
             ("hoàn tất cặp 2", _d_pairmid), ("3-3", _d_triple33), ("1-2-1", _d_121), ("2-1-2", _d_212),
             ("3-1", _d_31), ("1-3", _d_13)]

class M19Popular(_Stage1):
    """Model 19: các cầu/xu hướng phổ biến (bệt, 1-1, 2-2, 3-3, 1-2-1, 2-1-2, 3-1, 1-3...) — chấm độ đúng thực tế."""
    mid = "m19_popular"; label = "Cầu phổ biến"; code = "M19"; wb = 0.25
    def main(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 30:
            return _neutral()
        start = max(8, n - 150)
        items = []; act = []
        for name, fn in DETECTORS:
            pred = fn(h, n)
            if pred is None:
                continue
            hits = tr = 0
            for i in range(start, n):
                pr = fn(h, i)
                if pr is not None:
                    tr += 1; hits += int(pr == h[i])
            acc = _smooth_rate(hits, tr, 0.5, 8.0)
            items.append((acc if pred == 1 else 1.0 - acc, _rel(acc, tr, 8)))
            act.append("%s→%s (đúng %.0f%%, %d/%d)" % (name, _side(pred), acc * 100, hits, tr))
        if not act:
            return _neutral("không có cầu phổ biến nào đang hiện")
        return _sig(aux_logit_pool(items), max(c for _, c in items), "cầu đang hiện: " + "; ".join(act[:3]))
    def mini(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 30:
            return _neutral()
        start = max(8, n - 50)
        for name, fn in DETECTORS[:3]:
            pred = fn(h, n)
            if pred is None:
                continue
            hits = tr = 0
            for i in range(start, n):
                pr = fn(h, i)
                if pr is not None:
                    tr += 1; hits += int(pr == h[i])
            acc = _smooth_rate(hits, tr, 0.5, 6.0)
            return _sig(acc if pred == 1 else 1.0 - acc, _rel(acc, tr, 6) * 0.7, "%s gần đây đúng %.0f%% (%d/%d)" % (name, acc * 100, hits, tr))
        return _neutral()

class M22HouseBreak(_Stage1):
    """Model 22: nhận biết cầu có gãy không (đổi chế độ đảo chiều) + dấu hiệu từ xúc xắc."""
    mid = "m22_house_break"; label = "Cầu gãy / ý đồ nhà cái"; code = "M22"; wb = 0.3
    def main(self, ctx):
        h = ctx.h; n = ctx.n
        if n < 40:
            return _neutral()
        f = [int(h[i] != h[i - 1]) for i in range(1, n)]
        recent = f[-10:]; base = f[:-10][-50:]
        fb = _clamp(sum(base) / len(base), 0.1, 0.9)
        fr = sum(recent) / len(recent)
        z = (fr - fb) / math.sqrt(fb * (1 - fb) / len(recent))
        sp, sn = aux_cusum_stat(f[-30:], ref=fb, k=0.25)
        if not (abs(z) >= 1.8 or max(sp, sn) >= 2.5):
            return _neutral("cầu ổn định (tần suất đảo chiều %.0f%% vs nền %.0f%%), chưa thấy dấu hiệu gãy" % (fr * 100, fb * 100))
        f6 = sum(f[-6:]) / 6.0
        if f6 >= 0.67:
            target = 1 - ctx.side; mode = "chế độ đảo (1-1)"
        elif f6 <= 0.33:
            target = ctx.side; mode = "chế độ bệt"
        else:
            return _neutral("cầu có dấu hiệu gãy (z=%+.1f) nhưng chưa định hình chế độ mới" % z)
        edge = min(0.07, 0.03 + 0.01 * abs(z))
        p = 0.5 + edge if target == 1 else 0.5 - edge
        return _sig(p, _rel(0.5 + edge, 12, 8) * 0.8, "cầu GÃY (z=%+.1f, CUSUM %.1f): chuyển sang %s → %s" % (z, max(sp, sn), mode, _side(target)))
    def mini(self, ctx):
        tg = ctx.tongs
        if len(tg) < 12 or ctx.run < 3 or ctx.n < 30:
            return _neutral()
        L = ctx.run; side = ctx.side
        run_t = tg[-min(L, 6):]
        if len(run_t) < 3:
            return _neutral()
        ext = [aux_tong_extremity(t) * (1 if side == 1 else -1) for t in run_t]
        weak = ext[0] - ext[-1]
        p_break = _clamp(0.5 + 0.06 * _clamp(weak * 2, -1, 1) + 0.02 * min(3, L - 2), 0.4, 0.62)
        return _sig(_from_cont(side, 1.0 - p_break), 0.2,
                    "xúc xắc trong cầu %d: lực %s %s, cách cực trị %d phiên" % (L, _side(side), "yếu dần" if weak > 0 else "ổn định", aux_gap_since_extreme(tg)))

STAGE1 = [M01Pattern(), M02Trend(), M03Imbalance(), M04ShortBridge(), M06FollowBreak(), M10BreakProb(),
          M11Dice(), M12Patterns(), M14TrendBreak(), M15FollowTrend(), M16BridgeBreak(), M18RunTrend(),
          M19Popular(), M22HouseBreak()]
STAGE1_IDS = [m.mid for m in STAGE1]
PATTERN_MODELS = {"m01_pattern", "m04_short_bridge", "m06_follow_break", "m10_break_prob", "m12_ppm",
                  "m16_bridge_break", "m18_run_trend", "m19_popular"}

# =========================================================
# 7 MODEL TẦNG 2 (điều tiết / cân bằng / chọn tối ưu) — mỗi model = main + mini
# =========================================================
class M08Chaos:
    """Model 8: nhận biết cầu xấu (không theo xu hướng nào) → tự giảm trọng số các model theo cầu."""
    mid = "m08_chaos_guard"; label = "Cầu xấu / loạn"; code = "M08"
    def mini(self, ctx):
        return 1.0 - min(1.0, abs(aux_flip_rate(ctx.h, 30) - 0.5) * 8.0)
    def assess(self, ctx):
        h = ctx.h
        if ctx.n < 30:
            return 0.5, 1.0, 1.0, _neutral("chưa đủ dữ liệu đánh giá cầu")
        z = aux_runs_test_z(h, 60); ent = aux_entropy(h, 60)
        ac = aux_autocorr(h, 1, 60); ac2 = aux_autocorr(h, 2, 60); fr = aux_flip_rate(h, 60)
        structure = max(abs(z) / 2.5, abs(ac) * 4.0, abs(ac2) * 4.0, abs(fr - 0.5) * 8.0, (1.0 - ent) * 6.0)
        chaos = 0.7 * (1.0 - min(1.0, structure)) + 0.3 * self.mini(ctx)
        gp = 1.0 - 0.6 * chaos; go = 1.0 - 0.15 * chaos
        imb = aux_imbalance(h, 30)
        sig = _sig(0.5 - 0.05 * imb, 0.3 * chaos * min(1.0, abs(imb) * 2.0),
                   "độ loạn của cầu %.2f (runs z=%+.1f, entropy %.2f, tự tương quan %+.2f) → trọng số model theo cầu ×%.2f"
                   % (chaos, z, ent, ac, gp))
        return chaos, gp, go, sig

class M13Performance:
    """Model 13: đánh giá hiệu suất THỰC TẾ từng model → quyết định trọng số."""
    mid = "m13_performance"; label = "Đánh giá hiệu suất"; code = "M13"
    @staticmethod
    def mini(mem):
        hs = [h for _, h in list(mem)[-20:] if h is not None]
        return (sum(hs) / len(hs)) if len(hs) >= 10 else None
    def evaluate(self, memory, names):
        skills = {}; skills30 = {}; stats = {}
        for nm in names:
            mem = list(memory[nm])
            hits = [h for _, h in mem if h is not None]
            errs = [e for e, _ in mem]
            if len(hits) >= 12:
                sk = aux_skill(errs, hits); acc = (sum(hits) + 10.0) / (len(hits) + 20.0)
                a20 = self.mini(mem)
                if a20 is not None:
                    sk = 0.85 * sk + 0.15 * (0.75 + (a20 - 0.5) * 3.0)
                sk = _clamp(sk, 0.2, 1.4)
            else:
                sk = 0.75; acc = None
            m30 = mem[-30:]; h30 = [h for _, h in m30 if h is not None]
            skills[nm] = sk
            skills30[nm] = aux_skill([e for e, _ in m30], h30) if len(h30) >= 10 else sk
            stats[nm] = (acc, len(hits))
        return skills, skills30, stats
    def vote(self, names, sigs, skills, stats):
        ranked = sorted(names, key=lambda n: -skills[n])
        top = [n for n in ranked if sigs[n][1] > 0.02][:3]
        p = aux_logit_pool([(sigs[n][0], sigs[n][1] * skills[n]) for n in top])
        known = [n for n in names if stats[n][0] is not None]
        why = None
        if known:
            best = max(known, key=lambda n: stats[n][0]); worst = min(known, key=lambda n: stats[n][0])
            why = "hiệu suất thực tế: tốt nhất %s (%.0f%%, n=%d), kém nhất %s (%.0f%%) → trọng số theo hiệu suất" % (
                best.split("_")[0].upper(), stats[best][0] * 100, stats[best][1], worst.split("_")[0].upper(), stats[worst][0] * 100)
        return p, why

class M05SideBalance:
    """Model 5: nếu tỉ lệ trọng số TÀI/XỈU chênh quá cao → cân bằng lại."""
    mid = "m05_side_balance"; label = "Cân bằng TÀI/XỈU"; code = "M05"
    def mini(self, ps, W):
        act = [p for p, w in zip(ps, W) if w > 1e-9]
        return (sum(1 for p in act if p >= 0.5) / len(act)) if act else 0.5
    def apply(self, ps, W, pred_log):
        if sum(W) < 1e-9:
            return list(W), 0.5, None
        S = aux_side_share(ps, W); S_eff = 0.7 * S + 0.3 * self.mini(ps, W)
        W2 = list(W); note = None
        if S_eff > 0.70 or S_eff < 0.30:
            dom_tai = S_eff > 0.5
            share = _clamp(S if dom_tai else 1.0 - S, 1e-6, 1 - 1e-6)
            f = min(1.0, 0.60 * (1.0 - share) / (share * 0.40))
            for i in range(len(W2)):
                if (ps[i] >= 0.5) == dom_tai:
                    W2[i] *= f
            S2 = aux_side_share(ps, W2)
            note = "trọng số %s %.0f%% quá lệch → cân bằng còn %.0f%%" % (_side(1 if dom_tai else 0), share * 100, (S2 if dom_tai else 1 - S2) * 100)
        if len(pred_log) >= 16:
            q = sum(pred_log) / len(pred_log)
            if q > 0.75 or q < 0.25:
                heavy = q > 0.5
                for i in range(len(W2)):
                    if (ps[i] >= 0.5) == heavy:
                        W2[i] *= 0.85
                note = (note + "; " if note else "") + "20 phiên gần đây engine dự đoán %s %.0f%% → giảm thiên lệch" % (_side(1 if heavy else 0), (q if heavy else 1 - q) * 100)
        return W2, aux_logit_pool(list(zip(ps, W2))), note

class M07WeightCap:
    """Model 7: cân bằng trọng số từng model khi chênh lệch quá cao (chặn tỉ trọng tối đa)."""
    mid = "m07_weight_cap"; label = "Chặn trọng số"; code = "M07"
    def mini(self, W):
        act = [w for w in W if w > 1e-9]
        if len(act) < 3:
            return 0.0
        return max(act) / (sum(act) / len(act))
    def apply(self, ps, W):
        act = [w for w in W if w > 1e-9]
        if len(act) < 3:
            return list(W), aux_logit_pool(list(zip(ps, W))), None
        tot = sum(W); mx = max(W) / tot; g = aux_gini(act)
        if mx > 0.26 or g > 0.45 or self.mini(W) > 3.2:
            sh = aux_cap_and_renorm(W, 0.22)
            W2 = [s * tot for s in sh]
            return W2, aux_logit_pool(list(zip(ps, W2))), "một model chiếm %.0f%% trọng số (gini %.2f) → chặn tối đa 22%%" % (mx * 100, g)
        return list(W), aux_logit_pool(list(zip(ps, W))), None

class M17WeightSmooth:
    """Model 17: cân bằng trọng số bằng co về trung bình (mức co tuỳ độ chênh lệch)."""
    mid = "m17_weight_smooth"; label = "Làm mượt trọng số"; code = "M17"
    def mini(self, act):
        m = sum(act) / len(act)
        return (math.sqrt(sum((a - m) ** 2 for a in act) / len(act)) / m) if m > 0 else 0.0
    def apply(self, ps, W):
        act = [w for w in W if w > 1e-9]
        if len(act) < 2:
            return list(W), aux_logit_pool(list(zip(ps, W))), None
        g = aux_gini(act); mean = sum(act) / len(act)
        lam = _clamp(0.12 + 0.45 * g + 0.05 * self.mini(act), 0.1, 0.5)
        W2 = [((1 - lam) * w + lam * mean) if w > 1e-9 else 0.0 for w in W]
        return W2, aux_logit_pool(list(zip(ps, W2))), None

class M20MaxPerf:
    """Model 20: Max Performance — chọn bộ tổng hợp (A..E) có hiệu suất thực tế tốt nhất."""
    mid = "m20_max_perf"; label = "Chọn tối ưu"; code = "M20"
    AGG = ("A", "B", "C", "D", "E")
    @staticmethod
    def perf(mem):
        hs = [h for h in mem if h is not None]
        return ((sum(hs) + 10.0) / (len(hs) + 20.0), len(hs)) if len(hs) >= 20 else (None, len(hs))
    def mini(self, names, sigs, skills):
        c = [n for n in names if sigs[n][1] > 0.05]
        if not c:
            return 0.5
        return sigs[max(c, key=lambda n: skills[n] * sigs[n][1])][0]
    def choose(self, aggs, agg_memory):
        pb, nb = self.perf(agg_memory["B"])
        best = "B"; bp = pb if pb is not None else 0.5
        for a in self.AGG:
            pa, na = self.perf(agg_memory[a])
            if pa is not None and pa > bp + 0.02:
                best, bp = a, pa
        return best, aggs[best], bp

class M21GlobalBalance:
    """Model 21: cân bằng tất cả khi thấy chênh lệch cao (trọng số, hai phía, lệch trung vị, phân tán)."""
    mid = "m21_global_balance"; label = "Cân bằng tổng"; code = "M21"
    def mini(self, ps, W):
        a = [p for p, w in zip(ps, W) if w > 1e-9]
        if len(a) < 3:
            return 0.0
        m = sum(a) / len(a)
        return math.sqrt(sum((x - m) ** 2 for x in a) / len(a))
    def finalize(self, p, ps, W):
        act = [w for w in W if w > 1e-9]; trig = []
        if len(act) >= 3 and aux_gini(act) > 0.5:
            trig.append("trọng số lệch")
        S = aux_side_share(ps, W)
        if act and (S > 0.8 or S < 0.2):
            trig.append("phe %s áp đảo %.0f%%" % (_side(1 if S > 0.5 else 0), max(S, 1 - S) * 100))
        a = sorted(pp for pp, w in zip(ps, W) if w > 1e-9)
        if a:
            med = a[len(a) // 2] if len(a) % 2 else (a[len(a) // 2 - 1] + a[len(a) // 2]) / 2.0
            if abs(p - med) > 0.08:
                trig.append("tổng hợp lệch xa trung vị")
        if self.mini(ps, W) > 0.12:
            trig.append("các model bất đồng mạnh")
        f = 1.0 if not trig else (0.8 if len(trig) == 1 else 0.55)
        return 0.5 + (p - 0.5) * f, trig

M08 = M08Chaos(); M13 = M13Performance(); M05 = M05SideBalance(); M07 = M07WeightCap()
M17 = M17WeightSmooth(); M20 = M20MaxPerf(); M21 = M21GlobalBalance()
STAGE2 = [M05, M07, M08, M13, M17, M20, M21]
ALL_MODELS = sorted(STAGE1 + STAGE2, key=lambda m: m.code)
ALL_IDS = [m.mid for m in ALL_MODELS]

def component_count():
    aux = [k for k in globals() if k.startswith("aux_") and callable(globals()[k])]
    major = len(ALL_MODELS)
    mini = sum(1 for m in ALL_MODELS if hasattr(m, "mini"))
    return {"major": major, "mini": mini, "aux": len(aux), "total": major + mini + len(aux)}

# =========================================================
# ENGINE TỔNG HỢP — giữ nguyên API V22/V23
# =========================================================
class PredictionEngine:
    EXPERTS = tuple(ALL_IDS)

    def __init__(self, history=None, table_code="", tongs=None, dices=None):
        self.table_code = table_code
        self.history = []; self.tongs = []; self.dices = []
        self.memory = {n: deque(maxlen=100) for n in self.EXPERTS}       # (brier, hit|None) mỗi model
        self.agg_memory = {a: deque(maxlen=100) for a in M20MaxPerf.AGG}  # hit 0/1 mỗi bộ tổng hợp
        self.pred_log = deque(maxlen=20)                                  # hướng engine đã dự đoán (cho M5)
        self._last = None
        hs = []
        for v in list(history or []):
            try:
                y = int(v)
            except (TypeError, ValueError):
                continue
            if y in (0, 1):
                hs.append(y)
        hs = hs[-MAX_STORE:]
        tg = list(tongs or []); dc = list(dices or [])
        tg = [None] * (len(hs) - len(tg)) + tg[-len(hs):] if hs else []
        dc = [None] * (len(hs) - len(dc)) + dc[-len(hs):] if hs else []
        k = max(0, len(hs) - REPLAY)
        for i, y in enumerate(hs):
            self._update(y, tg[i] if i < len(tg) else None, dc[i] if i < len(dc) else None, score=(i >= k))

    # ---------- lõi ----------
    def _pipeline(self):
        ctx = Ctx(self.history, self.tongs, self.dices)
        n = ctx.n
        names = STAGE1_IDS; K = len(names)
        sigs = {}
        for m in STAGE1:
            try:
                sigs[m.mid] = m.predict(ctx)
            except Exception as e:
                if DEBUG_STRICT:
                    raise
                sigs[m.mid] = (0.5, 0.0, "lỗi nội bộ %s" % type(e).__name__)
        try:
            chaos, gp, go, s08 = M08.assess(ctx)
        except Exception:
            if DEBUG_STRICT:
                raise
            chaos, gp, go, s08 = 0.5, 1.0, 1.0, _neutral()
        skills, skills30, stats = M13.evaluate(self.memory, names)
        ps = [sigs[nm][0] for nm in names]
        gate = [(gp if nm in PATTERN_MODELS else go) for nm in names]
        conf_g = [sigs[nm][1] * gate[i] for i, nm in enumerate(names)]
        W0 = [conf_g[i] * skills[nm] for i, nm in enumerate(names)]
        W5, p5, n5 = M05.apply(ps, W0, self.pred_log)
        W7, p7, n7 = M07.apply(ps, W5)
        W17, p17, n17 = M17.apply(ps, W7)
        tot17 = sum(W17)

        # các bộ tổng hợp cho M20
        A = aux_logit_pool(list(zip(ps, conf_g)))
        B = aux_logit_pool(list(zip(ps, W17)))
        idx = sorted(range(K), key=lambda i: -W17[i])[:4]
        C = aux_logit_pool([(ps[i], W17[i]) for i in idx])
        D = aux_logit_pool([(ps[i], conf_g[i] * skills30[nm]) for i, nm in enumerate(names)])
        E = (0.5 + (aux_side_share(ps, W17) - 0.5) * 0.3) if tot17 > 1e-9 else 0.5
        aggs = {"A": A, "B": B, "C": C, "D": D, "E": E}
        choice, p20, perf = M20.choose(aggs, self.agg_memory)
        p_final, trig = M21.finalize(p20, ps, W17)
        p_final = _clip_prob(p_final, 0.02, 0.98)
        p13, n13 = M13.vote(names, sigs, skills, stats)

        modules = {}
        for i, nm in enumerate(names):
            share = (W17[i] / tot17) if tot17 > 1e-9 else 0.0
            modules[nm] = {"p": round(ps[i], 4), "w": round(share, 4), "c": round(sigs[nm][1], 4), "r": sigs[nm][2]}
        def meta(mid, p, r=""):
            modules[mid] = {"p": round(p, 4), "w": 0.0, "c": 0.5 if abs(p - 0.5) > 1e-9 else 0.0, "r": r or ""}
        meta("m05_side_balance", p5, n5); meta("m07_weight_cap", p7, n7); meta("m17_weight_smooth", p17, n17)
        meta("m08_chaos_guard", s08[0], s08[2]); meta("m13_performance", p13, n13)
        meta("m20_max_perf", p20, "bộ tổng hợp %s (hiệu suất %.0f%%)" % (choice, perf * 100) if perf else "bộ tổng hợp mặc định B")
        meta("m21_global_balance", p_final, ("; ".join(trig)) if trig else "")

        # lý do dự đoán
        side_int = 1 if p_final >= 0.5 else 0
        order = sorted(range(K), key=lambda i: -W17[i])
        lines = []
        for i in order:
            nm = names[i]
            if sigs[nm][1] >= 0.05 and sigs[nm][2] and len(lines) < 4:
                m = STAGE1[i]
                lines.append("%s %s: %s" % (m.code, m.label, sigs[nm][2]))
        notes = []
        if chaos >= 0.6:
            notes.append("M08 " + s08[2])
        for code, nt in (("M05", n5), ("M07", n7)):
            if nt:
                notes.append(code + " " + nt)
        if n13:
            notes.append("M13 " + n13)
        if choice != "B":
            notes.append("M20 chọn bộ tổng hợp %s (hiệu suất %.0f%%)" % (choice, perf * 100))
        if trig:
            notes.append("M21 cân bằng tổng vì: " + ", ".join(trig))
        fr = aux_flip_rate(ctx.h, 30) if n >= 10 else 0.5
        regime = "WARMUP" if n < 12 else ("CHAOS" if chaos >= 0.75 else ("PINGPONG" if fr >= 0.62 else ("STREAK" if fr <= 0.38 else "MIXED")))
        return {"p": p_final, "side_int": side_int, "modules": modules, "aggs": aggs, "chaos": chaos,
                "regime": regime, "regime_conf": 1.0 - chaos, "total_w": tot17, "lines": lines, "notes": notes,
                "agg_choice": choice, "n": n}

    def _get_out(self):
        n = len(self.history)
        if self._last is None or self._last[0] != n:
            self._last = (n, self._pipeline())
        return self._last[1]

    def _update(self, y, tong=None, dices=None, score=True):
        y = int(y)
        if score and len(self.history) >= 12:
            out = self._get_out()
            for name, rec in out["modules"].items():
                p = rec["p"]
                hit = None if (abs(p - 0.5) < 0.005 or rec["c"] < 0.02) else int((p >= 0.5) == (y == 1))
                self.memory[name].append(((p - y) ** 2, hit))
            for an, ap in out["aggs"].items():
                self.agg_memory[an].append(None if abs(ap - 0.5) < 0.002 else int((ap >= 0.5) == (y == 1)))
            self.pred_log.append(out["side_int"])
        self.history.append(y)
        self.tongs.append(_clean_tong(tong) if tong is not None else None)
        self.dices.append(_clean_dices(dices) if dices is not None else None)
        self._last = None
        if len(self.history) > MAX_STORE + 200:
            self.history = self.history[-MAX_STORE:]
            self.tongs = self.tongs[-MAX_STORE:]
            self.dices = self.dices[-MAX_STORE:]

    # ---------- API công khai (giữ nguyên) ----------
    def predict(self, accuracy_100=.5, accuracy_500=.5):
        n = len(self.history)
        out = self._get_out()
        p = out["p"]
        edge = abs(p - 0.5) * 2.0
        side = "TAI" if p >= 0.5 else "XIU"

        # Confidence = xác suất ước lượng, co về 50% theo hiệu suất thực tế gần đây.
        try:
            acc = 0.6 * float(accuracy_100) + 0.4 * float(accuracy_500)
        except (TypeError, ValueError):
            acc = 0.5
        k = _clamp(0.35 + (acc - 0.5) * 8.0, 0.25, 1.0)
        confidence = int(round(50.0 + edge * 50.0 * k))
        confidence = max(50, min(80, confidence))

        supported = out["total_w"] >= 0.02
        skip = (n < 20) or (not supported)
        reason = "WARMUP" if n < 20 else ("NO_RELIABLE_SIGNAL" if not supported else None)
        mv = {nm: {"p": r["p"], "w": r["w"]} for nm, r in out["modules"].items()}

        parts = list(out["lines"]) + list(out["notes"])
        if not parts:
            parts = ["chưa có tín hiệu đủ mạnh — giữ trung tính"]
        reasons = ["Dự đoán %s %d%%" % (_side(1 if side == "TAI" else 0), confidence)] + parts
        reason_text = " • ".join(reasons)
        return {
            "side": side,
            "confidence": confidence,
            "p_internal": round(p, 6),
            "regime": out["regime"],
            "regime_conf": round(out["regime_conf"], 4),
            "skip": skip,
            "reason": reason,
            "reasons": reasons,
            "reason_text": reason_text,
            "modules": mv,
            "full": {
                "modules": mv,
                "p_internal": round(p, 6),
                "regime": out["regime"],
                "regime_conf": round(out["regime_conf"], 4),
                "aggregator": out["agg_choice"],
                "reasons": reasons,
                "explanation": "V24 multi-layer ensemble: 21 model lớn / 21 mini / 42 aux"
            }
        }

    def observe(self, result, tong=None, dices=None):
        if isinstance(result, str):
            result = result.strip().upper()
        if result in ("TAI", "XIU"):
            self._update(1 if result == "TAI" else 0, tong, dices)
        elif isinstance(result, int) and not isinstance(result, bool) and result in (0, 1):
            self._update(result, tong, dices)

    def observe_session(self, s):
        """Nhận 1 phần tử trong parse_upstream(...)['sessions']."""
        if isinstance(s, dict):
            self.observe(s.get("result"), s.get("tong"), s.get("dices"))

    def to_dict(self):
        tail = min(len(self.history), TAIL_STORE)
        d = {"history": list(self.history[-MAX_STORE:]), "table_code": self.table_code}
        tg = self.tongs[-tail:] if tail else []
        dc = self.dices[-tail:] if tail else []
        if any(v is not None for v in tg):
            d["tongs"] = tg
        if any(v is not None for v in dc):
            d["dices"] = dc
        return d

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            return cls()
        return cls(history=data.get("history", []), table_code=data.get("table_code", ""),
                   tongs=data.get("tongs"), dices=data.get("dices"))


# ============ CÁC HÀM HELPER (Giữ nguyên) ============
class Backtest:
    @staticmethod
    def run(history, warmup=10, tongs=None, dices=None):
        eng = PredictionEngine()
        rows, correct = [], 0
        for idx, y in enumerate(history):
            pred = eng.predict()
            if len(eng.history) >= warmup:
                ok = pred["side"] == ("TAI" if y else "XIU")
                correct += int(ok)
                rows.append({"actual": y, "prediction": pred["side"], "correct": ok})
            eng.observe(y, tong=(tongs[idx] if tongs else None), dices=(dices[idx] if dices else None))
        return {"total": len(rows), "correct": correct, "accuracy": correct/len(rows) if rows else 0}

def resolve_actual(table_code, sessions):
    c = db(); count = 0
    for x in sessions:
        sid = int(x.get("session_id", 0)); actual = "TAI" if int(x.get("result", 0)) == 1 else "XIU"
        r = c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=? AND actual IS NULL", (table_code, sid)).fetchone()
        if not r: continue
        result = "win" if r["prediction"] == actual else "lose"
        detail = json.loads(r["detail_json"] or "{}")
        modules = detail.get("modules", {}); top = max(modules.items(), key=lambda z: z[1].get("w", 0)) if modules else (None, {})
        c.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?", (actual, result, now_iso(), r["id"]))
        c.execute("INSERT OR IGNORE INTO prediction_resolutions(table_code,session_id,prediction,actual,result,regime,regime_conf,confidence,top_module,top_module_p,module_votes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (table_code, sid, r["prediction"], actual, result, detail.get("regime"), detail.get("regime_conf"), r["confidence"], top[0], top[1].get("p"), json.dumps(modules)))
        count += 1
    c.commit(); c.close(); return count

def get_table_config(table_code): return {}
def save_table_config(table_code, config): pass
def accuracy_detail(table_code, days=7): return {"total":0,"wins":0,"losses":0,"accuracy":0.0}
def get_broadcast(): return ""
def set_worker_control(key, value): pass
def get_worker_control(key, default=None): return default

def load_engine(table_code):
    conn = db(); row = conn.execute("SELECT history_json FROM table_states WHERE table_code=?", (table_code,)).fetchone(); conn.close()
    try: state = json.loads(row["history_json"] or '{"history":[]}') if row else {"history": []}
    except: state = {"history": []}
    obj = PredictionEngine.from_dict(state); obj.table_code = table_code
    return obj

def save_engine(table_code, engine):
    conn = db(); conn.execute("UPDATE table_states SET history_json=?,updated_at=? WHERE table_code=?", (json.dumps(engine.to_dict(), separators=(",", ":")), now_iso(), table_code)); conn.commit(); conn.close()

def load_last_seen(table_code):
    conn = db(); row = conn.execute("SELECT last_seen_id FROM table_states WHERE table_code=?", (table_code,)).fetchone(); conn.close()
    return int(row[0]) if row else 0

def save_last_seen(table_code, session_id):
    conn = db(); conn.execute("UPDATE table_states SET last_seen_id=?,updated_at=? WHERE table_code=?", (int(session_id), now_iso(), table_code)); conn.commit(); conn.close()

def save_worker_state(table_code, engine, session_id):
    conn = db(); conn.execute("UPDATE table_states SET history_json=?,last_seen_id=?,updated_at=? WHERE table_code=?", (json.dumps(engine.to_dict(), separators=(",", ":")), int(session_id), now_iso(), table_code)); conn.commit(); conn.close()

def mark_poll_ok(table_code):
    conn = db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=NULL,updated_at=? WHERE table_code=?", (now_iso(), now_iso(), table_code)); conn.commit(); conn.close()

def mark_poll_error(table_code, error):
    conn = db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?", (now_iso(), str(error)[:500], now_iso(), table_code)); conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    conn = db(); rows = conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IN ('win','lose') ORDER BY session_id DESC LIMIT ?", (table_code, int(limit))).fetchall(); conn.close()
    return (sum(r[0] == "win" for r in rows) / len(rows)) if rows else 0.5
