# -*- coding: utf-8 -*-
"""LC79 API JSON và bảng điều khiển quản trị. Giao diện quản trị inline duy nhất tại đây."""
from __future__ import annotations
import hashlib
import csv
import io
import importlib.util
import threading
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for, make_response
from engine import TABLES, PredictionEngine, Backtest, accuracy, accuracy_detail, db, init_db, load_engine, now_iso, get_table_config, save_table_config, get_broadcast, set_worker_control

app = Flask(__name__)
init_db()
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
APP_STARTED=time.time(); APP_VERSION="2.0.0"; BUILD_DATE="2026-11-11"; ENGINE_VERSION="2.0-adaptive"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

# -----------------------------------------------------------------------------
# JSON API helpers. /makey and every /makey/* route return jsonify only.
# -----------------------------------------------------------------------------
def api_error(code, message, status, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    response = jsonify(body)
    response.status_code = status
    return response

def api_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Device-Id"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Vary"] = "Origin"
    return response

@app.after_request
def add_api_cors(response):
    if request.path == "/makey" or request.path.startswith("/makey/") or request.path in {"/history","/stats","/regime","/modules","/backtest","/detail","/resolutions"}:
        return api_cors(response)
    return response

@app.errorhandler(Exception)
def api_exception_json(error):
    if request.path == "/makey" or request.path.startswith("/makey/"):
        response = jsonify({"error": "internal_error", "message": "Lỗi máy chủ, vui lòng thử lại"})
        response.status_code = 500
        return response
    raise error

@app.route("/makey", methods=["GET", "OPTIONS"])
@app.route("/makey/<path:subpath>", methods=["GET", "OPTIONS"])
def makey_json_only(subpath=None):
    """JSON ONLY: không render_template_string, không Accept header, không content negotiation."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    if subpath == "activate":
        return activate_key_json()
    if subpath == "check":
        return check_key_json()
    if subpath is not None:
        return jsonify({"error": "not_found", "message": "Đường dẫn không tồn tại"}), 404
    return predict_or_history_json()

def _client_device():
    supplied = (request.headers.get("X-Device-Id") or "").strip()
    if supplied:
        return supplied[:128]
    raw = (request.remote_addr or "") + "|" + (request.headers.get("User-Agent") or "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

def _duration_seconds(days):
    try:
        value = float(days)
    except (TypeError, ValueError):
        value = 7.0
    return max(60, min(3650 * 86400, int(value * 86400)))


def duration_label(days):
    seconds = _duration_seconds(days)
    if seconds < 3600:
        return f"{max(1, seconds // 60)} phút"
    if seconds < 86400:
        return f"{seconds // 3600} giờ"
    if seconds % 86400 == 0:
        return f"{seconds // 86400} ngày"
    return f"{seconds / 86400:.2f} ngày"


def _key_access(key, table_code=None, touch=True):
    if not key:
        return None, api_error("invalid_key", "Key không tồn tại", 401)
    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    if not row or not row["is_active"]:
        conn.close(); return None, api_error("invalid_key", "Key không tồn tại", 401)
    if row["expires_at"]:
        try:
            expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                conn.close(); return None, api_error("expired", "Key hết hạn", 403)
        except ValueError:
            conn.close(); return None, api_error("expired", "Key hết hạn", 403)
    if table_code and not _scope_allows(row["scope"], table_code):
        conn.close(); return None, api_error("no_access", "Key không có quyền cho bàn này", 403)
    # Giới hạn 60 yêu cầu/key/phút.
    minute = str(int(time.time() // 60))
    rate = conn.execute("SELECT count FROM rate_limits WHERE key=? AND window=?", (key, minute)).fetchone()
    if rate and rate["count"] >= 60:
        conn.close(); return None, api_error("rate_limited", "Vượt quá giới hạn yêu cầu", 429, retry_after_seconds=60-int(time.time())%60)
    conn.execute("INSERT INTO rate_limits(key,window,count) VALUES(?,?,1) ON CONFLICT(key,window) DO UPDATE SET count=count+1", (key, minute))
    device = _client_device(); now = now_iso()
    # Thiết bị không hoạt động 10 phút được tự động nhả khóa.
    conn.execute("UPDATE api_key_devices SET released_at=?,released_reason='Tự động nhả sau 10 phút không hoạt động' WHERE key=? AND released_at IS NULL AND last_seen<?",
                 (now, key, (datetime.now(timezone.utc)-timedelta(minutes=10)).replace(microsecond=0).isoformat()))
    active = conn.execute("SELECT * FROM api_key_devices WHERE key=? AND released_at IS NULL", (key,)).fetchall()
    current = next((d for d in active if d["device_id"] == device), None)
    if not current and len(active) >= int(row["max_devices"] or 1):
        conn.close(); return None, api_error("device_locked", "Key đang dùng thiết bị khác", 423, retry_after_minutes=7)
    ua = request.headers.get("User-Agent", "")[:300]
    if current:
        conn.execute("UPDATE api_key_devices SET last_seen=?,ip=?,user_agent=? WHERE id=?", (now, request.remote_addr, ua, current["id"]))
    else:
        conn.execute("INSERT INTO api_key_devices(key,device_id,ip,user_agent,browser,os,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                     (key, device, request.remote_addr, ua, _browser_name(ua), _os_name(ua), now, now))
    key_data = dict(row)
    if touch:
        # Bắt đầu thời hạn ở lần khách thực sự dùng key đầu tiên.
        expiry_value = row["expires_at"]
        if not expiry_value and not int(row["activated"] or 0):
            expiry_value = (datetime.now(timezone.utc) +
                            timedelta(seconds=_duration_seconds(row["days"]))).replace(microsecond=0).isoformat()
        conn.execute("UPDATE api_keys SET last_used_at=?,activated=1,expires_at=? WHERE key=?",
                     (now, expiry_value, key))
        key_data["activated"] = 1
        key_data["expires_at"] = expiry_value
    conn.commit(); conn.close()
    return key_data, None

def _scope_allows(scope, table_code):
    parts = {x.strip() for x in str(scope or "").split(",") if x.strip()}
    return bool(parts.intersection({"*", "all", table_code}))

def _log_api_request(key, table_code, request_type):
    conn=db()
    conn.execute("INSERT INTO activation_log(key,code,success,ip,user_agent,reason) VALUES(?,NULL,1,?,?,?)",
                 (key,request.remote_addr,request.headers.get("User-Agent",""),f"API {request_type} {table_code}"))
    conn.commit(); conn.close()

def _browser_name(ua):
    u=ua.lower()
    for token,name in (("edg/","Edge"),("chrome/","Chrome"),("firefox/","Firefox"),("safari/","Safari")):
        if token in u: return name
    return "Không rõ"

def _os_name(ua):
    u=ua.lower()
    for token,name in (("android","Android"),("iphone","iOS"),("ipad","iPadOS"),("windows","Windows"),("mac os","macOS"),("linux","Linux")):
        if token in u: return name
    return "Không rõ"

def predict_or_history_json():
    key=request.args.get("key", "").strip(); table=request.args.get("table", "").strip()
    if table not in TABLES:
        return jsonify({"error":"invalid_table","message":"Mã bàn không hợp lệ"}),400
    keyrow, error = _key_access(key, table)
    if error: return error
    kind=request.args.get("type", "predict").lower()
    _log_api_request(key,table,kind)
    meta=TABLES[table]
    conn=db(); state=conn.execute("SELECT last_seen_id,last_poll_error FROM table_states WHERE table_code=?",(table,)).fetchone()
    if not state or int(state["last_seen_id"] or 0)==0:
        conn.close(); return api_error("bootstrapping","Worker đang khởi động, thử lại sau 60 giây",503)
    if kind=="history":
        try: limit=max(1,min(105,int(request.args.get("limit",105))))
        except ValueError: limit=50
        rows=conn.execute("SELECT session_id,prediction,confidence,actual,result FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT ?",(table,limit)).fetchall()
        conn.close()
        items=[]
        for r in rows:
            status="" if not r["actual"] else ("win✅" if r["result"]=="win" else "lose❌")
            items.append({"phien":r["session_id"],"dudoan":r["prediction"],"confidence":r["confidence"],"ketqua":r["actual"] or "chuacoketqua","trangthai":status})
        return jsonify({"ok":True,"table":table,"table_name":meta["name"],"count":len(items),"items":items})
    row=conn.execute("SELECT session_id,prediction,confidence,actual,result,detail_json FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT 1",(table,)).fetchone()
    conn.close()
    if not row: return api_error("bootstrapping","Worker đang khởi động, thử lại sau 60 giây",503)
    status="" if not row["actual"] else ("win" if row["result"]=="win" else "lose")
    try: detail=json.loads(row["detail_json"] or "{}")
    except Exception: detail={}
    return jsonify({"ok":True,"admin":"P A W","telegram":"@K0ZT1","table":table,"table_name":meta["name"],
                    "phien":row["session_id"],"dudoan":row["prediction"],"confidence":row["confidence"],"ketqua":row["actual"] or "chuacoketqua","trangthai":status,"broadcast":get_broadcast(),"full":detail,"regime":detail.get("regime"),"regime_conf":detail.get("regime_conf"),"modules":detail.get("modules"),"p_internal":detail.get("p_internal")})

def activate_key_json():
    code=request.args.get("code", "").strip().upper(); extend=request.args.get("extend", "").strip()
    if not code: return api_error("invalid_code","Mã kích hoạt không hợp lệ",400)
    conn=db(); c=conn.execute("SELECT * FROM activation_codes WHERE code=? AND revoked=0",(code,)).fetchone()
    if not c:
        conn.execute("INSERT INTO activation_log(code,success,ip,user_agent,reason) VALUES(?,0,?,?,?)",(code,request.remote_addr,request.headers.get("User-Agent",""),"Mã không tồn tại")); conn.commit(); conn.close()
        return api_error("invalid_code","Mã kích hoạt không tồn tại",404)
    if c["expires_at"] and c["expires_at"] < now_iso(): conn.close(); return api_error("code_expired","Mã kích hoạt đã hết hạn",403)
    if c["max_uses"]!=-1 and c["used_count"]>=c["max_uses"]: conn.close(); return api_error("code_used","Mã kích hoạt đã hết lượt",409)
    if extend:
        old=conn.execute("SELECT * FROM api_keys WHERE key=? AND is_active=1",(extend,)).fetchone()
        if not old: conn.close(); return api_error("invalid_key","Key gia hạn không tồn tại",404)
        added_days=float(c["days"])
        if old["expires_at"]:
            try:
                base=max(datetime.now(timezone.utc),datetime.fromisoformat(old["expires_at"].replace("Z","+00:00")))
            except ValueError:
                base=datetime.now(timezone.utc)
            expiry=(base+timedelta(seconds=_duration_seconds(added_days))).replace(microsecond=0).isoformat()
            conn.execute("UPDATE api_keys SET expires_at=?,days=days+? WHERE key=?",(expiry,added_days,extend))
        else:
            expiry=None
            conn.execute("UPDATE api_keys SET days=days+? WHERE key=?",(added_days,extend))
        newkey=extend
    else:
        newkey="LC79-"+secrets.token_hex(12).upper()
        expiry=None
        _cn=c["customer_name"] if "customer_name" in c.keys() and c["customer_name"] else ""
        _nt=("Kích hoạt từ mã "+code)+((" · "+c["note"]) if "note" in c.keys() and c["note"] else "")
        conn.execute("INSERT INTO api_keys(key,scope,note,expires_at,days,max_devices,activated,customer_name) VALUES(?,?,?,?,?,?,0,?)",
                     (newkey,c["scope"],_nt,expiry,float(c["days"]),1,_cn))
    conn.execute("UPDATE activation_codes SET used_count=used_count+1 WHERE code=?",(code,))
    conn.execute("INSERT INTO activation_log(key,code,success,ip,user_agent,reason) VALUES(?,?,1,?,?,?)",
                 (newkey,code,request.remote_addr,request.headers.get("User-Agent",""),"Kích hoạt thành công"))
    conn.commit(); conn.close()
    return jsonify({"ok":True,"key":newkey,"scope":c["scope"],"expires_at":expiry,"message":"Kích hoạt thành công"})

def check_key_json():
    key=request.args.get("key", "").strip()
    if not key: return api_error("invalid_key","Key không tồn tại",401)
    row,error=_key_access(key,None,touch=True)
    if error: return error
    _log_api_request(key,"all","check")
    return jsonify({"ok":True,"valid":True,"scope":row["scope"],"expires_at":row["expires_at"],"max_devices":row["max_devices"],"activated":bool(row["activated"])})

# -----------------------------------------------------------------------------
# Admin authentication and helpers
# -----------------------------------------------------------------------------
def admin_required(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        if not session.get("admin_user") or session.get("admin_until",0)<time.time():
            session.clear(); return redirect(url_for("admin_login"))
        session.permanent=True
        return fn(*args,**kwargs)
    return wrapped

def admin_log(action,target="",detail=None):
    conn=db(); conn.execute("INSERT INTO admin_actions(admin_user,action,target,detail_json,ip) VALUES(?,?,?,?,?)",
        (session.get("admin_user","system"),action,str(target),json.dumps(detail or {},ensure_ascii=False),request.remote_addr)); conn.commit(); conn.close()

def fmt_date(value):
    if not value:return "Chưa có"
    try:return datetime.fromisoformat(str(value).replace("Z","+00:00")).strftime("%d/%m/%Y %H:%M")
    except:return str(value)

def rel_date(value):
    if not value:return "Không thời hạn"
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00")); delta=dt-datetime.now(timezone.utc)
        if delta.total_seconds()<0:return "Đã hết hạn"
        days=delta.days
        if days:return f"Còn {days} ngày"
        hours=int(delta.total_seconds()//3600)
        return f"Còn {hours} giờ" if hours else "Sắp hết hạn"
    except:return value

def svg_icon(name,size=20):
    paths={
      "grid":"<rect x='3' y='3' width='7' height='7' rx='1'/><rect x='14' y='3' width='7' height='7' rx='1'/><rect x='3' y='14' width='7' height='7' rx='1'/><rect x='14' y='14' width='7' height='7' rx='1'/>",
      "key":"<circle cx='8' cy='15' r='5'/><path d='m11.5 11.5 8-8 2 2-2 2 2 2-3 3-2-2-3 3'/>",
      "ticket":"<path d='M3 8V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a3 3 0 0 0 0 8v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a3 3 0 0 0 0-8Z'/><path d='M13 5v2m0 4v2m0 4v2'/>",
      "activity":"<path d='M3 12h4l3-8 4 16 3-8h4'/>",
      "monitor":"<rect x='3' y='3' width='18' height='14' rx='2'/><path d='M8 21h8m-4-4v4'/>",
      "logs":"<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>",
      "copy":"<rect x='8' y='8' width='13' height='13' rx='2'/><path d='M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3'/>",
      "plus":"<path d='M12 5v14M5 12h14'/>",
      "search":"<circle cx='11' cy='11' r='7'/><path d='m20 20-4-4'/>",
      "refresh":"<path d='M20 7v5h-5M4 17v-5h5'/><path d='M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3'/>",
      "lock":"<rect x='4' y='10' width='16' height='11' rx='2'/><path d='M8 10V7a4 4 0 1 1 8 0v3'/>",
      "unlock":"<rect x='4' y='10' width='16' height='11' rx='2'/><path d='M8 10V7a4 4 0 0 1 8 0'/>",
      "trash":"<path d='M3 6h18M8 6V4h8v2m3 0-1 15H6L5 6m4 4v7m6-7v7'/>",
      "arrow":"<path d='M5 12h14m-6-6 6 6-6 6'/>",
      "close":"<path d='m6 6 12 12M18 6 6 18'/>",
      "check":"<path d='m5 12 4 4L19 6'/>",
      "clock":"<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
      "server":"<rect x='3' y='3' width='18' height='7' rx='2'/><rect x='3' y='14' width='18' height='7' rx='2'/><path d='M7 6h.01M7 17h.01'/>",
      "eye":"<path d='M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z'/><circle cx='12' cy='12' r='3'/>",
    }
    return f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{paths.get(name,paths['grid'])}</svg>"

def badge(text,kind="neutral"):
    return f'<span class="badge {kind}">{text}</span>'

def chart_svg(values,height=220):
    vals=[float(v or 0) for v in values]
    if not vals: vals=[0]
    w=900; pad=34; plot_h=height-45; plot_w=w-2*pad
    pts=[]
    for i,v in enumerate(vals):
        x=pad+(plot_w*i/max(1,len(vals)-1)); y=height-22-(max(0,min(1,v))*plot_h); pts.append((x,y))
    line=" ".join(("M" if i==0 else "L")+f"{x:.1f},{y:.1f}" for i,(x,y) in enumerate(pts))
    area=line+f" L{pts[-1][0]:.1f},{height-22} L{pts[0][0]:.1f},{height-22} Z"
    grid="".join(f"<line x1='{pad}' y1='{height-22-i*plot_h/4:.1f}' x2='{w-pad}' y2='{height-22-i*plot_h/4:.1f}' stroke='#e5eaf2' stroke-dasharray='4 5'/><text x='4' y='{height-18-i*plot_h/4:.1f}' fill='#94a3b8' font-size='11'>{i*25}%</text>" for i in range(5))
    return f"<svg class='chart' viewBox='0 0 {w} {height}' role='img' aria-label='Biểu đồ độ chính xác'><defs><linearGradient id='chartFill' x1='0' x2='0' y1='0' y2='1'><stop offset='0%' stop-color='#3b82f6' stop-opacity='.10'/><stop offset='100%' stop-color='#3b82f6' stop-opacity='0'/></linearGradient></defs>{grid}<path d='{area}' fill='url(#chartFill)'/><path d='{line}' fill='none' stroke='#2563eb' stroke-width='2' vector-effect='non-scaling-stroke'/>{''.join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="#2563eb"><title>{v*100:.1f}%</title></circle>' for (x,y),v in zip(pts,vals))}</svg>"

# -----------------------------------------------------------------------------
# ADMIN V3 — giao diện quản trị chuyên sâu (inline, một nơi duy nhất)
# -----------------------------------------------------------------------------
from markupsafe import escape as esc

VN_TZ = timezone(timedelta(hours=7))
SCOPE_NAMES = {"lc79_tx": "Bàn Hũ", "lc79_md5": "Bàn MD5", "*": "Tất cả bàn", "all": "Tất cả bàn"}
_LOGIN_FAILS = {}


def ensure_schema():
    """Thêm cột thông tin khách hàng nếu DB cũ chưa có (an toàn, chạy nhiều lần)."""
    try:
        c = db()
        def cols(t):
            return {r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()}
        k = cols("api_keys")
        for name in ("customer_name", "contact"):
            if name not in k:
                c.execute(f"ALTER TABLE api_keys ADD COLUMN {name} TEXT DEFAULT ''")
        a = cols("activation_codes")
        for name in ("customer_name", "note"):
            if name not in a:
                c.execute(f"ALTER TABLE activation_codes ADD COLUMN {name} TEXT DEFAULT ''")
        c.commit(); c.close()
    except Exception:
        pass

ensure_schema()


def _col(r, name, default=""):
    try:
        v = r[name]
        return default if v is None else v
    except (KeyError, IndexError):
        return default


def parse_dt(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fmt_date(value):
    d = parse_dt(value)
    if not d:
        return "Chưa có" if not value else str(value)
    return d.astimezone(VN_TZ).strftime("%d/%m/%Y %H:%M")


def ago(value):
    d = parse_dt(value)
    if not d:
        return "Chưa từng"
    s = max(0, int((datetime.now(timezone.utc) - d).total_seconds()))
    if s < 60: return "Vừa xong"
    if s < 3600: return f"{s // 60} phút trước"
    if s < 86400: return f"{s // 3600} giờ trước"
    return f"{s // 86400} ngày trước"


def rel_date(value):
    if not value:
        return "Không thời hạn"
    d = parse_dt(value)
    if not d:
        return str(value)
    s = int((d - datetime.now(timezone.utc)).total_seconds())
    if s <= 0: return "Đã hết hạn"
    days, rem = divmod(s, 86400); hours = rem // 3600; mins = (rem % 3600) // 60
    if days: return f"Còn {days} ngày {hours} giờ" if hours else f"Còn {days} ngày"
    if hours: return f"Còn {hours} giờ {mins} phút"
    return f"Còn {max(1, mins)} phút"


def key_status(r):
    if not r["is_active"]:
        return "Đã thu hồi", "danger", "revoked"
    if not int(r["activated"] or 0):
        return "Chưa kích hoạt", "warning", "pending"
    e = parse_dt(r["expires_at"])
    if e and e <= datetime.now(timezone.utc):
        return "Hết hạn", "danger", "expired"
    return "Đang hoạt động", "success", "active"


def remaining_pct(r):
    if not int(r["activated"] or 0) or not r["expires_at"]:
        return 100.0
    e = parse_dt(r["expires_at"])
    if not e:
        return 0.0
    left = (e - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(100.0, left / max(1, _duration_seconds(r["days"])) * 100))


def scope_chips(scope):
    parts = [x.strip() for x in str(scope or "").split(",") if x.strip()]
    return "".join(f'<span class="chip-s">{esc(SCOPE_NAMES.get(p, p))}</span>' for p in parts) or '<span class="muted">—</span>'


def is_online(last_seen, seconds=120):
    d = parse_dt(last_seen)
    return bool(d and (datetime.now(timezone.utc) - d).total_seconds() <= seconds)


def dev_icon(os_name):
    return "📱" if os_name in ("Android", "iOS", "iPadOS") else "💻"


def epoch(v):
    d = parse_dt(v)
    return int(d.timestamp()) if d else ""


def parse_req_reason(reason):
    p = str(reason or "").split()
    if len(p) >= 3 and p[0] == "API":
        return p[1], p[2]
    return None, None


def stat_card(label, value, note="", tone=""):
    return f'<div class="card stat {tone}"><div class="stat-label">{label}</div><div class="stat-value">{value}</div><div class="stat-note">{note}</div></div>'


# ------------------------------- CSS + SHELL (UI v4: Vercel/Linear style) ----------
CSS = r'''<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
/* Biến màu: light mặc định, dark qua data-theme */
:root{--bg:#ffffff;--s1:#fafafa;--s2:#ffffff;--s3:#f3f4f6;--bd:#e5e7eb;--bd2:#d1d5db;--tx:#111827;--tx2:#6b7280;--tx3:#8b93a1;--cy:#2563eb;--bl:#2563eb;--vi:#7c3aed;--gr:#10b981;--rd:#ef4444;--am:#f59e0b;--gr-t:#059669;--rd-t:#dc2626;--am-t:#b45309;--acc-bg:rgba(37,99,235,.08);--r:12px;--r2:8px;--r3:6px;--sh:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);--sh2:0 12px 32px rgba(16,24,40,.14);--sbw:240px}
html[data-theme=dark]{--bg:#0a0a0a;--s1:#171717;--s2:#111111;--s3:#1f1f1f;--bd:#262626;--bd2:#333333;--tx:#fafafa;--tx2:#a3a3a3;--tx3:#737373;--cy:#3b82f6;--bl:#3b82f6;--vi:#a78bfa;--gr-t:#34d399;--rd-t:#f87171;--am-t:#fbbf24;--acc-bg:rgba(59,130,246,.14);--sh:0 1px 2px rgba(0,0,0,.4);--sh2:0 12px 32px rgba(0,0,0,.6);color-scheme:dark}
*{box-sizing:border-box}html{background:var(--s1)}
body{margin:0;background:var(--s1);color:var(--tx);font:13px/1.55 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;transition:background .25s,color .25s;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}button,input,select,textarea{font:inherit;color:inherit}button{cursor:pointer}svg{vertical-align:middle;flex:none}
/* Sidebar 240px, thu nhỏ còn 64px */
.sidebar{position:fixed;inset:0 auto 0 0;width:var(--sbw);background:var(--bg);border-right:1px solid var(--bd);padding:14px 10px;z-index:40;display:flex;flex-direction:column;transition:width .2s,transform .25s;overflow-y:auto;overflow-x:hidden}
.brand{display:flex;gap:10px;align-items:center;padding:4px 8px 18px;white-space:nowrap}.brand-mark{width:32px;height:32px;border-radius:var(--r2);display:grid;place-items:center;font-weight:800;font-size:13px;letter-spacing:.02em;color:#fff;background:var(--tx);flex:none}html[data-theme=dark] .brand-mark{color:#0a0a0a}
.brand-name{font-weight:800;letter-spacing:.08em;font-size:13px}.brand-sub{font-size:9.5px;letter-spacing:.14em;color:var(--tx3)}
.nav-label{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--tx3);padding:14px 10px 6px;font-weight:600;white-space:nowrap}
.nav-item{display:flex;align-items:center;gap:11px;height:36px;padding:0 10px;border-radius:var(--r3);color:var(--tx2);margin:1px 0;position:relative;transition:background .15s,color .15s;white-space:nowrap;font-weight:500}
.nav-item i{font-style:normal;display:grid;place-items:center;width:18px;height:18px}.nav-item:hover{background:var(--s3);color:var(--tx)}
.nav-item.active{background:var(--s1);color:var(--tx);font-weight:600}.nav-item.active:before{content:"";position:absolute;left:-10px;top:6px;bottom:6px;width:3px;border-radius:0 3px 3px 0;background:var(--cy)}.nav-item.active i{color:var(--cy)}
.sidebar-foot{margin-top:auto;border-top:1px solid var(--bd);padding:12px 8px 0;color:var(--tx3);font-size:11px;white-space:nowrap}
.collapse-btn{display:flex;align-items:center;gap:10px;height:34px;padding:0 10px;margin-top:10px;border:0;background:transparent;border-radius:var(--r3);color:var(--tx2);width:100%}.collapse-btn:hover{background:var(--s3)}
body.collapsed{--sbw:64px}body.collapsed .nav-text,body.collapsed .brand>div:last-child,body.collapsed .nav-label,body.collapsed .sidebar-foot span,body.collapsed .collapse-btn span{display:none}body.collapsed .nav-label{display:block;height:1px;padding:0;margin:10px 8px;background:var(--bd);font-size:0}body.collapsed .nav-item,body.collapsed .collapse-btn{justify-content:center;padding:0}body.collapsed .collapse-btn svg{transform:rotate(180deg)}
.main{margin-left:var(--sbw);min-height:100vh;transition:margin-left .2s}
.topbar{height:56px;position:sticky;top:0;z-index:30;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 24px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--bd)}
.crumb{color:var(--tx3);font-size:13px;display:flex;align-items:center;gap:8px}.crumb b{color:var(--tx);font-weight:600}
.top-user{display:flex;gap:6px;align-items:center}
.icon-btn{position:relative;width:34px;height:34px;display:inline-grid;place-items:center;border-radius:var(--r2);border:1px solid transparent;background:transparent;color:var(--tx2);transition:.15s}.icon-btn:hover{background:var(--s3);color:var(--tx)}.icon-btn .pip{position:absolute;top:6px;right:7px;min-width:8px;height:8px;border-radius:8px;background:var(--rd);border:2px solid var(--bg)}
.menu-btn{display:none}
.search-trigger{display:flex;align-items:center;gap:8px;height:34px;padding:0 10px;min-width:200px;border:1px solid var(--bd);border-radius:var(--r2);background:var(--s1);color:var(--tx3)}.search-trigger:hover{border-color:var(--bd2)}.search-trigger kbd{margin-left:auto}
kbd{font:500 10.5px 'JetBrains Mono',monospace;border:1px solid var(--bd2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;color:var(--tx2);background:var(--bg)}
.me-avatar{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:12px;color:#fff;background:linear-gradient(135deg,var(--cy),var(--vi));border:0}
/* Dropdown */
.dd{position:relative;display:inline-block}.dd-menu{position:absolute;right:0;top:calc(100% + 6px);min-width:200px;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);box-shadow:var(--sh2);padding:6px;display:none;z-index:60;animation:pop .15s ease}.dd.open>.dd-menu{display:block}
.dd-item{display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:0;background:transparent;border-radius:var(--r3);text-align:left;color:var(--tx);font-size:12.5px}.dd-item:hover{background:var(--s3)}.dd-sep{height:1px;background:var(--bd);margin:6px 0}.dd-head{padding:8px 10px;font-size:11px;color:var(--tx3);text-transform:uppercase;letter-spacing:.08em;font-weight:600}
.notif{display:flex;gap:10px;padding:9px 10px;border-radius:var(--r3)}.notif:hover{background:var(--s3)}.notif .nd{width:8px;height:8px;border-radius:50%;margin-top:5px;flex:none}.notif b{display:block;font-size:12.5px;font-weight:600}.notif span{font-size:11.5px;color:var(--tx3)}
.content{max-width:1280px;margin:0 auto;padding:24px 24px 64px}
.page-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:20px;flex-wrap:wrap}.page-title{font-size:24px;font-weight:700;letter-spacing:-.025em;line-height:1.25}.page-sub{color:var(--tx2);margin-top:4px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.actions form{margin:0}
.grid{display:grid;gap:16px}.two{grid-template-columns:repeat(2,minmax(0,1fr))}.three{grid-template-columns:repeat(3,minmax(0,1fr))}.stats{grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin-bottom:16px}
.card{background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);padding:18px;min-width:0;box-shadow:var(--sh);transition:border-color .15s}
.card:hover{border-color:var(--bd2)}.card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.card-title{font-weight:600;font-size:14px}.card-sub{color:var(--tx3);font-size:12px;margin-top:2px}
.stat-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--tx2);font-weight:600}.stat-value{font-size:28px;font-weight:700;letter-spacing:-.03em;margin-top:6px;font-family:'JetBrains Mono',ui-monospace,monospace;font-variant-numeric:tabular-nums}.stat-note{color:var(--tx3);font-size:12px;margin-top:4px}
.stat.good .stat-value{color:var(--gr-t)}.stat.warn .stat-value{color:var(--am-t)}.stat.bad .stat-value{color:var(--rd-t)}.stat.info .stat-value{color:var(--cy)}
/* Button */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:34px;padding:0 14px;border-radius:var(--r2);font-weight:500;font-size:12.5px;border:1px solid var(--bd2);background:var(--bg);color:var(--tx);transition:.15s;white-space:nowrap;box-shadow:var(--sh)}
.btn:hover{background:var(--s3)}.btn:active{transform:scale(.98)}.btn[disabled],.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{background:var(--cy);border-color:var(--cy);color:#fff}.btn-primary:hover{background:var(--cy);filter:brightness(1.1)}
.btn-danger{background:transparent;border-color:color-mix(in srgb,var(--rd) 40%,transparent);color:var(--rd-t)}.btn-danger:hover{background:color-mix(in srgb,var(--rd) 10%,transparent)}
.btn-ok{background:transparent;border-color:color-mix(in srgb,var(--gr) 40%,transparent);color:var(--gr-t)}.btn-ok:hover{background:color-mix(in srgb,var(--gr) 10%,transparent)}
.btn-quiet,.btn-ghost{background:transparent;border-color:transparent;box-shadow:none;color:var(--tx2)}.btn-quiet:hover,.btn-ghost:hover{background:var(--s3);color:var(--tx)}
.btn-sm{height:28px;padding:0 10px;font-size:12px;border-radius:var(--r3)}.btn-lg{height:42px;padding:0 20px;font-size:14px}
.btn.loading{pointer-events:none;opacity:.8}.btn.loading:before{content:"";width:13px;height:13px;border-radius:50%;border:2px solid currentColor;border-right-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* Form */
.field{display:flex;flex-direction:column;gap:6px}.field label{font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--tx2);font-weight:600}
.input,.select,.textarea,input[type=text],input[type=number],input[type=password],input[type=date],select,textarea{width:100%;background:var(--bg);color:var(--tx);border:1px solid var(--bd2);border-radius:var(--r2);padding:7px 11px;min-height:34px;outline:none;transition:.15s}
.input:focus,.select:focus,.textarea:focus,input:focus,select:focus,textarea:focus{border-color:var(--cy);box-shadow:0 0 0 3px var(--acc-bg)}.input::placeholder{color:var(--tx3)}.textarea{min-height:120px;resize:vertical;font-family:'JetBrains Mono',monospace;font-size:12px}
input[type=checkbox]{width:15px;height:15px;accent-color:var(--cy)}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.searchbox{position:relative;flex:1;min-width:220px;max-width:400px}.searchbox svg{position:absolute;left:11px;top:9px;color:var(--tx3)}.searchbox .input{padding-left:34px}
/* Table */
.table-wrap{overflow:auto;border:1px solid var(--bd);border-radius:var(--r);background:var(--bg);max-height:70vh}.data-table{width:100%;border-collapse:separate;border-spacing:0;white-space:nowrap}
.data-table th{position:sticky;top:0;z-index:2;background:var(--s1);color:var(--tx2);font-size:11px;letter-spacing:.05em;text-transform:uppercase;padding:10px 14px;text-align:left;border-bottom:1px solid var(--bd);font-weight:600;user-select:none}
.data-table th.sortable{cursor:pointer}.data-table th.sortable:hover{color:var(--tx)}.data-table th.asc:after{content:" ↑";color:var(--cy)}.data-table th.desc:after{content:" ↓";color:var(--cy)}
.data-table td{padding:10px 14px;border-bottom:1px solid var(--bd);color:var(--tx);font-size:12.5px;vertical-align:middle}.data-table tr:last-child td{border-bottom:0}.data-table tbody tr{transition:background .12s}.data-table tbody tr:hover td{background:var(--s1)}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace}
/* Badge */
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid transparent}
.badge.success{background:color-mix(in srgb,var(--gr) 12%,transparent);color:var(--gr-t);border-color:color-mix(in srgb,var(--gr) 28%,transparent)}.badge.danger{background:color-mix(in srgb,var(--rd) 11%,transparent);color:var(--rd-t);border-color:color-mix(in srgb,var(--rd) 28%,transparent)}.badge.warning{background:color-mix(in srgb,var(--am) 13%,transparent);color:var(--am-t);border-color:color-mix(in srgb,var(--am) 30%,transparent)}.badge.neutral{background:var(--s3);color:var(--tx2);border-color:var(--bd)}.badge.info{background:var(--acc-bg);color:var(--cy);border-color:color-mix(in srgb,var(--cy) 28%,transparent)}
.badge.dot:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.health,.dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--tx3)}.health.green,.dot.on{background:var(--gr);box-shadow:0 0 0 3px color-mix(in srgb,var(--gr) 22%,transparent)}.health.red{background:var(--rd);box-shadow:0 0 0 3px color-mix(in srgb,var(--rd) 22%,transparent)}.health.yellow{background:var(--am);box-shadow:0 0 0 3px color-mix(in srgb,var(--am) 22%,transparent)}
.progress{height:6px;border-radius:10px;background:var(--s3);overflow:hidden}.progress>span{display:block;height:100%;border-radius:10px;background:var(--cy);transition:width .4s}.progress.warn>span{background:var(--am)}.progress.bad>span{background:var(--rd)}.progress.compact{display:inline-block;width:70px;height:5px;vertical-align:middle;margin-right:6px}
.muted{color:var(--tx2)}.small{font-size:12px}.empty{padding:40px 20px;text-align:center;color:var(--tx3)}.split{display:flex;justify-content:space-between;align-items:center;gap:14px}
.kv{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.kv.c3{grid-template-columns:repeat(3,minmax(0,1fr))}.kv.c2{grid-template-columns:repeat(2,minmax(0,1fr))}.kv-item{padding:11px 13px;background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2);min-width:0}.kv-label{font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--tx2);font-weight:600}.kv-value{font-size:14px;font-weight:600;margin-top:4px;overflow-wrap:anywhere}
.detail-line{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--bd)}.detail-line:last-child{border-bottom:0}.detail-line span{color:var(--tx2)}
.timeline{position:relative;padding-left:22px}.timeline:before{content:"";position:absolute;left:6px;top:6px;bottom:6px;width:1px;background:var(--bd2)}.timeline-item{position:relative;padding:0 0 16px 10px}.timeline-item:before{content:"";position:absolute;left:-20px;top:5px;width:9px;height:9px;border-radius:50%;background:var(--cy);box-shadow:0 0 0 3px var(--acc-bg)}.timeline-title{font-size:13px}.timeline-meta{font-size:12px;color:var(--tx3);margin-top:2px}
.chart-box{position:relative;height:240px}
.alert{padding:11px 14px;border-radius:var(--r2);margin-bottom:16px;background:color-mix(in srgb,var(--am) 10%,transparent);border:1px solid color-mix(in srgb,var(--am) 32%,transparent);color:var(--am-t)}.alert.error{background:color-mix(in srgb,var(--rd) 9%,transparent);border-color:color-mix(in srgb,var(--rd) 32%,transparent);color:var(--rd-t)}
/* Modal: blur 4px, scale-in 200ms */
.modal-backdrop{position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.45);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;padding:18px}.modal-backdrop.open{display:flex}
.modal{width:100%;max-width:560px;max-height:92vh;overflow:auto;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);padding:22px;box-shadow:var(--sh2);animation:pop .2s ease}.modal-wide{max-width:780px}.modal-title{font-size:17px;font-weight:700}.modal-body{color:var(--tx2);margin:10px 0 16px}.modal-footer{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:18px}
@keyframes pop{from{opacity:0;transform:scale(.96) translateY(6px)}to{opacity:1;transform:none}}
/* Toast: góc phải dưới, có thanh đếm ngược */
.toast-stack{position:fixed;bottom:18px;right:18px;z-index:9999;display:grid;gap:8px;max-width:calc(100vw - 36px)}
.toast{position:relative;overflow:hidden;display:flex;gap:10px;align-items:center;background:var(--bg);border:1px solid var(--bd);padding:11px 16px;border-radius:var(--r2);min-width:240px;box-shadow:var(--sh2);animation:pop .2s}.toast .ti{display:grid;place-items:center;width:20px;height:20px;border-radius:50%;font-size:11px;font-weight:800;color:#fff;background:var(--gr);flex:none}.toast.error .ti{background:var(--rd)}.toast.warn .ti{background:var(--am)}.toast.info .ti{background:var(--cy)}
.toast:after{content:"";position:absolute;left:0;bottom:0;height:3px;width:100%;background:var(--gr);transform-origin:left;animation:countdown 4s linear forwards}.toast.error:after{background:var(--rd)}.toast.warn:after{background:var(--am)}.toast.info:after{background:var(--cy)}
@keyframes countdown{to{transform:scaleX(0)}}
/* Skeleton + tooltip */
.skeleton{border-radius:var(--r3);background:linear-gradient(90deg,var(--s3) 25%,var(--s1) 50%,var(--s3) 75%);background-size:200% 100%;animation:shimmer 1.3s infinite;min-height:14px}@keyframes shimmer{to{background-position:-200% 0}}
[data-tooltip]{position:relative}[data-tooltip]:hover:after{content:attr(data-tooltip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--tx);color:var(--bg);font-size:11px;font-weight:500;padding:4px 8px;border-radius:var(--r3);white-space:nowrap;z-index:70;pointer-events:none}
/* Key cards */
.kgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(460px,1fr));gap:16px}
.kcard{display:flex;flex-direction:column;gap:14px;padding:18px;border-radius:var(--r);border:1px solid var(--bd);background:var(--bg);box-shadow:var(--sh);position:relative;overflow:hidden;transition:.15s}
.kcard:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--tx3)}.kcard[data-status=active]:before{background:var(--gr)}.kcard[data-status=pending]:before{background:var(--am)}.kcard[data-status=expired]:before,.kcard[data-status=revoked]:before{background:var(--rd)}
.kcard:hover{border-color:var(--bd2);box-shadow:var(--sh2)}
.khead{display:flex;gap:12px;align-items:center}.avatar{width:40px;height:40px;border-radius:var(--r2);display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff;background:linear-gradient(135deg,var(--cy),var(--vi));flex:none}.kname{font-weight:600;font-size:14.5px;line-height:1.25}.kcontact{color:var(--tx3);font-size:12px}
.keyline{display:flex;align-items:center;gap:8px;background:var(--s1);border:1px dashed var(--bd2);border-radius:var(--r2);padding:7px 10px}.keyline .mono{flex:1;font-size:12px;color:var(--cy);overflow-wrap:anywhere}
.krow{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.kcell{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2);padding:8px 11px;min-width:0}.kcell b{display:block;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}.kcell small{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--tx2);font-weight:600}
.chip-s{display:inline-block;padding:2px 8px;border-radius:var(--r3);background:var(--acc-bg);border:1px solid color-mix(in srgb,var(--cy) 25%,transparent);color:var(--cy);font-size:11px;font-weight:600;margin:0 4px 3px 0}
.dev{display:flex;gap:10px;align-items:center;padding:8px 10px;background:var(--s1);border:1px solid var(--bd);border-radius:var(--r2)}.dev+.dev{margin-top:6px}.dev-ic{font-size:18px}.dev b{font-size:12.5px}.dev small{display:block;color:var(--tx3);font-size:11px}
.sec-label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--tx2);font-weight:600;margin-bottom:7px;display:flex;justify-content:space-between}
.kfoot{display:flex;gap:6px;flex-wrap:wrap;margin-top:auto}.kfoot form{margin:0}
.chip{border:1px solid var(--bd2);background:var(--bg);color:var(--tx2);padding:5px 12px;border-radius:999px;font-size:12px;font-weight:500}.chip:hover{background:var(--s3)}.chip.on{background:var(--acc-bg);border-color:var(--cy);color:var(--cy)}.chip em{font-style:normal;opacity:.7;margin-left:4px}
/* Tabs gạch chân */
.tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--bd)}.tab{padding:9px 14px;color:var(--tx2);font-weight:500;border-bottom:2px solid transparent;margin-bottom:-1px}.tab:hover{color:var(--tx)}.tab.on{border-bottom-color:var(--cy);color:var(--tx);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:var(--r2);border:1px solid var(--bd2);background:var(--bg);margin:0 6px 8px 0;cursor:pointer}.pill input{width:auto}.pill:has(input:checked){border-color:var(--cy);background:var(--acc-bg)}
.pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;padding-top:14px}.pagination button:disabled{opacity:.35;cursor:not-allowed}
.module-list{display:grid;gap:10px}.module-label{display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px}.module-label span{color:var(--tx2);font:11px 'JetBrains Mono',monospace}
.broadcast-form{display:flex;gap:10px;flex-wrap:wrap}.broadcast-form .input{flex:1;min-width:220px}
.side-tai{color:var(--rd-t)!important;font-weight:700}.side-xiu{color:var(--cy)!important;font-weight:700}.result-win{color:var(--gr-t)!important;font-weight:700}.result-lose{color:var(--rd-t)!important;font-weight:700}
/* Đăng nhập */
.login-page{min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--s1)}.login-card{width:100%;max-width:400px;border:1px solid var(--bd);border-radius:var(--r);padding:32px;background:var(--bg);box-shadow:var(--sh2)}.login-brand{display:flex;gap:12px;align-items:center;margin-bottom:24px}.login-card h1{margin:0 0 6px;font-size:21px;letter-spacing:-.02em}.login-card p{color:var(--tx2);margin:0 0 20px}.login-card .field{margin:14px 0}.login-card .btn{width:100%;margin-top:8px;height:40px}
/* Palette Ctrl+K */
.pal{max-width:560px;padding:0;overflow:hidden}.pal input{border:0;border-bottom:1px solid var(--bd);border-radius:0;padding:14px 18px;font-size:14px;box-shadow:none!important}.pal-list{max-height:340px;overflow:auto;padding:6px}.pal-item{display:flex;gap:10px;align-items:center;padding:9px 12px;border-radius:var(--r3);color:var(--tx);cursor:pointer}.pal-item.sel,.pal-item:hover{background:var(--s3)}.pal-item small{margin-left:auto;color:var(--tx3)}
.sc-row{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--bd)}
.drawer-mask{display:none}
@media(max-width:1100px){.kv{grid-template-columns:repeat(2,minmax(0,1fr))}.three{grid-template-columns:repeat(2,1fr)}.search-trigger{min-width:0}.search-trigger span,.search-trigger kbd{display:none}}
@media(max-width:820px){.sidebar{transform:translateX(-100%);width:240px;box-shadow:var(--sh2)}body.drawer-open .sidebar{transform:none}body.drawer-open .drawer-mask{display:block;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:35}.main{margin-left:0!important}.menu-btn{display:inline-grid}.topbar{padding:0 12px}.content{padding:16px 12px 40px}.two,.three{grid-template-columns:1fr}.kgrid{grid-template-columns:1fr}.krow{grid-template-columns:1fr 1fr}.page-title{font-size:21px}.chart-box{height:210px}body.collapsed{--sbw:240px}body.collapsed .nav-text,body.collapsed .brand>div:last-child,body.collapsed .collapse-btn span,body.collapsed .sidebar-foot span{display:revert}.collapse-btn{display:none}}
@media(max-width:440px){.kv,.kv.c3{grid-template-columns:1fr 1fr}.krow{grid-template-columns:1fr}.stat-value{font-size:23px}}
/* ===== V4: nền trắng, thẻ phẳng, nút chính đen ===== */
html{background:var(--bg)}body{background:var(--bg)}
.sidebar{background:var(--s1)}.card{box-shadow:none}.kcard{box-shadow:none}
.btn-primary{background:var(--tx);border-color:var(--tx);color:var(--bg)}.btn-primary:hover{background:var(--tx);filter:opacity(.85)}
.btn{box-shadow:none}.topbar{background:color-mix(in srgb,var(--bg) 90%,transparent)}
.badge.tai{background:color-mix(in srgb,var(--vi) 12%,transparent);color:var(--vi);border-color:color-mix(in srgb,var(--vi) 30%,transparent);font-weight:700}
.badge.xiu{background:color-mix(in srgb,var(--cy) 12%,transparent);color:var(--cy);border-color:color-mix(in srgb,var(--cy) 30%,transparent);font-weight:700}
.progress.good>span{background:var(--gr)}
.stat2-top{display:flex;align-items:center;gap:8px}.stat2-ic{display:grid;place-items:center;width:26px;height:26px;border-radius:var(--r3);background:var(--s3);color:var(--tx2)}
.dl{font-weight:600;font-size:12px}.dl.up{color:var(--gr-t)}.dl.down{color:var(--rd-t)}
.bigpred{display:flex;align-items:center;gap:14px}.bigpred .badge{font-size:16px;padding:6px 16px}
.clickrow{cursor:pointer}.xdetail{display:none}.xdetail.open{display:table-row}.xdetail td{background:var(--s1)!important}
.sticky-filter{position:sticky;top:56px;z-index:5;background:var(--bg);padding:10px 0;margin-top:-4px}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(480px,100vw);background:var(--bg);border-left:1px solid var(--bd);box-shadow:var(--sh2);z-index:1100;transform:translateX(100%);transition:transform .25s;display:flex;flex-direction:column}.drawer.open{transform:none}
.drawer-head{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--bd)}.drawer-body{padding:20px;overflow:auto;flex:1}
.kcheck{position:absolute;right:14px;top:14px;z-index:3}.kcard.sel{border-color:var(--cy);box-shadow:0 0 0 2px var(--acc-bg)}
.bulkbar{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);z-index:900;display:none;align-items:center;gap:10px;padding:10px 14px;background:var(--tx);color:var(--bg);border-radius:var(--r);box-shadow:var(--sh2);flex-wrap:wrap}.bulkbar.show{display:flex}.bulkbar .btn{height:30px}
</style>'''

# Script chạy sớm để không bị nháy theme
THEME_BOOT = r'''<script>try{document.documentElement.dataset.theme=localStorage.getItem('paw-theme')||'light'}catch(e){document.documentElement.dataset.theme='light'}</script>'''

ICONS = {
    "grid": "<rect x='3' y='3' width='7' height='7' rx='1'/><rect x='14' y='3' width='7' height='7' rx='1'/><rect x='3' y='14' width='7' height='7' rx='1'/><rect x='14' y='14' width='7' height='7' rx='1'/>",
    "dice": "<rect x='3' y='3' width='18' height='18' rx='3'/><circle cx='8' cy='8' r='1'/><circle cx='16' cy='8' r='1'/><circle cx='12' cy='12' r='1'/><circle cx='8' cy='16' r='1'/><circle cx='16' cy='16' r='1'/>",
    "hash": "<path d='M4 9h16M4 15h16M10 3 8 21M16 3l-2 18'/>",
    "key": "<circle cx='8' cy='15' r='5'/><path d='m11.5 11.5 8-8 2 2-2 2 2 2-3 3-2-2-3 3'/>",
    "ticket": "<path d='M3 8V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a3 3 0 0 0 0 8v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a3 3 0 0 0 0-8Z'/><path d='M13 5v2m0 4v2m0 4v2'/>",
    "logs": "<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>",
    "gear": "<circle cx='12' cy='12' r='3'/><path d='M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z'/>",
    "sun": "<circle cx='12' cy='12' r='4'/><path d='M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'/>",
    "moon": "<path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z'/>",
    "bell": "<path d='M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0'/>",
    "menu": "<path d='M4 6h16M4 12h16M4 18h16'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='m20 20-4-4'/>",
    "chev": "<path d='m15 6-6 6 6 6'/>",
    "out": "<path d='M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9'/>",
    "help": "<circle cx='12' cy='12' r='9'/><path d='M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3m.1 4h.01'/>",
    "refresh": "<path d='M20 7v5h-5M4 17v-5h5'/><path d='M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3'/>",
}


def ui_icon(name, size=18):
    return f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{ICONS.get(name, ICONS['grid'])}</svg>"


BASE = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · LC79</title>''' + THEME_BOOT + r'''<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>''' + CSS + r'''</head><body>
<aside class="sidebar" id="sidebar"><a class="brand" href="/admin"><div class="brand-mark">PAW</div><div><div class="brand-name">P A W</div><div class="brand-sub">LC79 CONTROL</div></div></a>{{ nav|safe }}<button class="collapse-btn" onclick="toggleSidebar()" data-tooltip="Thu gọn / mở rộng">{{ ico_chev|safe }}<span>Thu gọn</span></button><div class="sidebar-foot"><span>v{{ version }} · engine {{ engine }}</span></div></aside>
<div class="drawer-mask" onclick="document.body.classList.remove('drawer-open')"></div>
<main class="main"><header class="topbar"><div class="crumb"><button class="icon-btn menu-btn" onclick="document.body.classList.add('drawer-open')" aria-label="Menu">{{ ico_menu|safe }}</button>Quản trị <span>/</span> <b>{{ title }}</b></div>
<div class="top-user"><button class="search-trigger" onclick="openPalette()">{{ ico_search|safe }}<span>Tìm nhanh…</span><kbd>Ctrl K</kbd></button>
<label class="small muted" id="arWrap" style="display:none;align-items:center;gap:6px;margin:0 8px"><input type="checkbox" id="autoRefresh"> Tự làm mới 15s</label>
<button class="icon-btn" onclick="openModal('helpModal')" data-tooltip="Phím tắt (?)">{{ ico_help|safe }}</button>
<button class="icon-btn" id="themeBtn" onclick="toggleTheme()" data-tooltip="Sáng / tối"></button>
<div class="dd" id="bellDd"><button class="icon-btn" onclick="toggleDd('bellDd',event)" aria-label="Thông báo">{{ ico_bell|safe }}{% if notif_count %}<span class="pip"></span>{% endif %}</button><div class="dd-menu" style="min-width:300px"><div class="dd-head">Thông báo ({{ notif_count }})</div>{{ notifs|safe }}</div></div>
<div class="dd" id="meDd"><button class="icon-btn" onclick="toggleDd('meDd',event)" aria-label="Tài khoản"><span class="me-avatar">{{ admin_user[:1]|upper }}</span></button><div class="dd-menu"><div class="dd-head">{{ admin_user }}</div><a class="dd-item" href="/admin/settings">{{ ico_gear|safe }} Cài đặt</a><div class="dd-sep"></div><a class="dd-item" href="/admin/logout">{{ ico_out|safe }} Đăng xuất</a></div></div></div></header>
<section class="content">{{ body|safe }}</section></main>
<div class="toast-stack" id="toasts"></div>
<div class="drawer" id="drawer"><div class="drawer-head"><b id="drawerTitle"></b><button class="btn btn-quiet btn-sm" onclick="closeDrawer()">✕</button></div><div class="drawer-body" id="drawerBody"></div></div>
<div class="bulkbar" id="bulkBar"><b id="bulkCount">0</b><span>đã chọn</span><button class="btn btn-sm" onclick="bulkExtend()">Gia hạn +30 ngày</button><button class="btn btn-sm" onclick="bulkCopy()">Sao chép key</button><button class="btn btn-sm btn-danger" onclick="bulkDo('revoke')">Thu hồi</button><button class="btn btn-sm btn-danger" onclick="bulkDo('delete')">Xóa</button><button class="btn btn-sm btn-quiet" style="color:var(--bg)" onclick="bulkClear()">Bỏ chọn</button></div>
<div class="modal-backdrop" id="palModal" onclick="if(event.target===this)closeModal('palModal')"><div class="modal pal"><input id="palInput" placeholder="Gõ để tìm trang hoặc hành động…" autocomplete="off"><div class="pal-list" id="palList"></div></div></div>
<div class="modal-backdrop" id="helpModal" onclick="if(event.target===this)closeModal('helpModal')"><div class="modal"><div class="split"><div class="modal-title">Phím tắt</div><button class="btn btn-quiet btn-sm" onclick="closeModal('helpModal')">✕</button></div><div class="modal-body"><div class="sc-row"><span>Tìm nhanh</span><span><kbd>Ctrl</kbd> <kbd>K</kbd></span></div><div class="sc-row"><span>Dashboard</span><span><kbd>G</kbd> <kbd>D</kbd></span></div><div class="sc-row"><span>Bàn Hũ</span><span><kbd>G</kbd> <kbd>H</kbd></span></div><div class="sc-row"><span>Bàn MD5</span><span><kbd>G</kbd> <kbd>M</kbd></span></div><div class="sc-row"><span>Modules / Backtest</span><span><kbd>G</kbd> <kbd>O</kbd> · <kbd>G</kbd> <kbd>B</kbd></span></div><div class="sc-row"><span>Predictions / Resolutions</span><span><kbd>G</kbd> <kbd>P</kbd> · <kbd>G</kbd> <kbd>R</kbd></span></div><div class="sc-row"><span>Sức khỏe hệ thống</span><span><kbd>G</kbd> <kbd>T</kbd></span></div><div class="sc-row"><span>Keys</span><span><kbd>G</kbd> <kbd>K</kbd></span></div><div class="sc-row"><span>Mã kích hoạt</span><span><kbd>G</kbd> <kbd>C</kbd></span></div><div class="sc-row"><span>Nhật ký</span><span><kbd>G</kbd> <kbd>L</kbd></span></div><div class="sc-row"><span>Cài đặt</span><span><kbd>G</kbd> <kbd>S</kbd></span></div><div class="sc-row"><span>Đóng hộp thoại</span><kbd>Esc</kbd></div><div class="sc-row"><span>Mở bảng này</span><kbd>?</kbd></div></div></div></div>
<script>
const ICO_SUN={{ ico_sun_js|tojson }},ICO_MOON={{ ico_moon_js|tojson }};
/* Toast: success | error | warn | info, tự tắt sau 4s */
function toast(m,t){const k=t||'success',e=document.createElement('div');e.className='toast '+k;const ic={success:'✓',error:'!',warn:'!',info:'i'}[k]||'✓';e.innerHTML='<span class="ti">'+ic+'</span><span></span>';e.lastChild.textContent=m;document.getElementById('toasts').appendChild(e);setTimeout(()=>e.remove(),4000)}
function copyText(v){if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(v).then(()=>toast('Đã sao chép')).catch(()=>toast('Không thể sao chép','error'))}else{const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();try{document.execCommand('copy');toast('Đã sao chép')}catch(e){toast('Không thể sao chép','error')}t.remove()}}
function openModal(id){const m=document.getElementById(id);if(m)m.classList.add('open')}
function closeModal(id){const m=document.getElementById(id);if(m)m.classList.remove('open')}
function confirmAction(m){return window.confirm(m)}
function filterRows(i,t){const q=document.getElementById(i).value.toLowerCase();document.querySelectorAll('#'+t+' tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}
/* Theme */
function paintTheme(){const d=document.documentElement.dataset.theme==='dark';document.getElementById('themeBtn').innerHTML=d?ICO_SUN:ICO_MOON}
function toggleTheme(){const n=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=n;try{localStorage.setItem('paw-theme',n)}catch(e){}paintTheme()}
paintTheme();
/* Sidebar */
function toggleSidebar(){document.body.classList.toggle('collapsed');try{localStorage.setItem('paw-collapsed',document.body.classList.contains('collapsed')?'1':'0')}catch(e){}}
try{if(localStorage.getItem('paw-collapsed')==='1')document.body.classList.add('collapsed')}catch(e){}
/* Dropdown */
function toggleDd(id,ev){ev.stopPropagation();document.querySelectorAll('.dd.open').forEach(d=>{if(d.id!==id)d.classList.remove('open')});document.getElementById(id).classList.toggle('open')}
document.addEventListener('click',()=>document.querySelectorAll('.dd.open').forEach(d=>d.classList.remove('open')));
/* Palette Ctrl+K */
const PAL=[['Dashboard','/admin','G D'],['Bàn Hũ','/admin/hu','G H'],['Bàn MD5','/admin/md5','G M'],['Modules','/admin/modules','G O'],['Backtest','/admin/backtest','G B'],['Predictions','/admin/predictions','G P'],['Resolutions','/admin/resolutions','G R'],['Sức khỏe hệ thống','/admin/health','G T'],['Keys & Khách hàng','/admin/keys','G K'],['Mã kích hoạt','/admin/codes','G C'],['Nhật ký','/admin/logs','G L'],['Cài đặt','/admin/settings','G S'],['Xuất CSV keys','/admin/keys/export.csv',''],['Xuất CSV Bàn Hũ','/admin/lc79_tx/export.csv',''],['Xuất CSV Bàn MD5','/admin/lc79_md5/export.csv',''],['Đăng xuất','/admin/logout','']];
let palSel=0;
function paintPal(){const q=document.getElementById('palInput').value.toLowerCase(),items=PAL.filter(p=>p[0].toLowerCase().includes(q));palSel=Math.min(palSel,Math.max(0,items.length-1));const l=document.getElementById('palList');l.innerHTML='';if(!items.length){l.innerHTML='<div class="empty">Không có kết quả</div>';return}items.forEach((p,i)=>{const a=document.createElement('a');a.className='pal-item'+(i===palSel?' sel':'');a.href=p[1];a.innerHTML='<span></span><small></small>';a.firstChild.textContent=p[0];a.lastChild.textContent=p[2];l.appendChild(a)})}
function openPalette(){openModal('palModal');const i=document.getElementById('palInput');i.value='';palSel=0;paintPal();setTimeout(()=>i.focus(),30)}
document.getElementById('palInput').addEventListener('input',()=>{palSel=0;paintPal()});
document.getElementById('palInput').addEventListener('keydown',e=>{const n=document.querySelectorAll('#palList .pal-item').length;if(e.key==='ArrowDown'){e.preventDefault();palSel=Math.min(n-1,palSel+1);paintPal()}else if(e.key==='ArrowUp'){e.preventDefault();palSel=Math.max(0,palSel-1);paintPal()}else if(e.key==='Enter'){const s=document.querySelector('#palList .pal-item.sel');if(s)location.href=s.getAttribute('href')}});
/* Phím tắt: G+D/H/M/K/C/L/S, Esc, ? */
const GO={d:'/admin',h:'/admin/hu',m:'/admin/md5',o:'/admin/modules',b:'/admin/backtest',p:'/admin/predictions',r:'/admin/resolutions',t:'/admin/health',k:'/admin/keys',c:'/admin/codes',l:'/admin/logs',s:'/admin/settings'};let gWait=0;
document.addEventListener('keydown',e=>{
 if(e.key==='Escape'){document.querySelectorAll('.modal-backdrop.open').forEach(m=>m.classList.remove('open'));document.body.classList.remove('drawer-open');return}
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openPalette();return}
 const tg=(e.target.tagName||'').toLowerCase();if(tg==='input'||tg==='textarea'||tg==='select'||e.ctrlKey||e.metaKey||e.altKey)return;
 if(e.key==='?'){openModal('helpModal');return}
 if(gWait&&Date.now()-gWait<1200){const u=GO[e.key.toLowerCase()];gWait=0;if(u){location.href=u}return}
 if(e.key.toLowerCase()==='g')gWait=Date.now()});
/* Sắp xếp cột: bấm tiêu đề bảng (bỏ qua bảng có data-nosort) */
const NUM=x=>{const m=x.match(/-?\d[\d,]*\.?\d*/);return m?parseFloat(m[0].replace(/,/g,'')):NaN};
document.querySelectorAll('.data-table:not([data-nosort])').forEach(t=>{t.querySelectorAll('thead th').forEach((th,i)=>{if(!th.textContent.trim())return;th.classList.add('sortable');th.addEventListener('click',()=>{const asc=!th.classList.contains('asc');t.querySelectorAll('th').forEach(x=>x.classList.remove('asc','desc'));th.classList.add(asc?'asc':'desc');const tb=t.querySelector('tbody'),rows=[...tb.querySelectorAll('tr')],val=r=>{const c=r.children[i];return c?c.innerText.trim():''};rows.sort((a,b)=>{const x=val(a),y=val(b),nx=NUM(x),ny=NUM(y);const r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y,'vi');return asc?r:-r});rows.forEach(r=>tb.appendChild(r));if(typeof renderPredictionRows==='function')renderPredictionRows()})})});
/* Drawer + tải PNG biểu đồ */
function openDrawer(t,h){document.getElementById('drawerTitle').textContent=t;document.getElementById('drawerBody').innerHTML=h;document.getElementById('drawer').classList.add('open')}
function closeDrawer(){document.getElementById('drawer').classList.remove('open')}
function dlChart(id,name){const c=document.getElementById(id);if(!c)return;const a=document.createElement('a');a.href=c.toDataURL('image/png');a.download=name+'.png';a.click();toast('Đã tải PNG','info')}
/* Chọn nhiều key (chỉ trang /admin/keys): dùng lại các endpoint revoke/delete/extend có sẵn */
if(location.pathname==='/admin/keys'){const cards=()=>[...document.querySelectorAll('.kcard')],keyOf=c=>c.querySelector('.keyline .mono').textContent.trim(),picked=()=>cards().filter(c=>c.querySelector('.kc')&&c.querySelector('.kc').checked);
 cards().forEach(c=>{const l=document.createElement('label');l.className='kcheck';l.innerHTML='<input type="checkbox" class="kc">';c.appendChild(l);l.firstChild.addEventListener('change',()=>{c.classList.toggle('sel',l.firstChild.checked);bulkPaint()})});
 const act=document.querySelector('.page-head .actions');if(act){const b=document.createElement('button');b.className='btn';b.textContent='Chọn tất cả';b.onclick=()=>{const vis=cards().filter(c=>c.style.display!=='none');const all=vis.every(c=>c.querySelector('.kc').checked);vis.forEach(c=>{c.querySelector('.kc').checked=!all;c.classList.toggle('sel',!all)});bulkPaint()};act.prepend(b)}
 window.bulkPaint=()=>{const n=picked().length;document.getElementById('bulkCount').textContent=n;document.getElementById('bulkBar').classList.toggle('show',n>0)};
 window.bulkClear=()=>{cards().forEach(c=>{const k=c.querySelector('.kc');if(k)k.checked=false;c.classList.remove('sel')});bulkPaint()};
 window.bulkCopy=()=>copyText(picked().map(keyOf).join('\n'));
 const run=async(path,body)=>{let ok=0;for(const c of picked()){try{const r=await fetch('/admin/keys/'+encodeURIComponent(keyOf(c))+'/'+path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body||''});if(r.ok)ok++}catch(e){}}return ok};
 window.bulkDo=async p=>{const n=picked().length;if(!confirm((p==='delete'?'XÓA vĩnh viễn ':'Thu hồi ')+n+' key đã chọn?'))return;const ok=await run(p);toast('Đã xử lý '+ok+'/'+n+' key',ok===n?'success':'warn');setTimeout(()=>location.reload(),900)};
 window.bulkExtend=async()=>{const n=picked().length;if(!confirm('Gia hạn +30 ngày cho '+n+' key?'))return;const ok=await run('extend','days=30');toast('Đã gia hạn '+ok+'/'+n+' key',ok===n?'success':'warn');setTimeout(()=>location.reload(),900)}}
/* Tự làm mới 15s (chỉ Dashboard, bật/tắt lưu localStorage) */
if(location.pathname==='/admin'){const w=document.getElementById('arWrap'),c=document.getElementById('autoRefresh');w.style.display='flex';try{c.checked=localStorage.getItem('paw-ar')!=='0'}catch(e){c.checked=true}c.addEventListener('change',()=>{try{localStorage.setItem('paw-ar',c.checked?'1':'0')}catch(e){}toast(c.checked?'Đã bật tự làm mới':'Đã tắt tự làm mới','info')});setInterval(()=>{if(c.checked&&!document.hidden&&!document.querySelector('.modal-backdrop.open'))location.reload()},15000)}
/* Chart.js theo theme */
if(window.Chart){Chart.defaults.font.family='Inter,sans-serif';const dk=document.documentElement.dataset.theme==='dark';Chart.defaults.color=dk?'#a3a3a3':'#6b7280';Chart.defaults.borderColor=dk?'#262626':'#e5e7eb'}
</script></body></html>'''

# Nhóm điều hướng: (nhãn nhóm, [(key, href, icon, label)])
NAV_GROUPS = [
    ("Tổng quan", [("dashboard", "/admin", "grid", "Dashboard")]),
    ("Bàn chơi", [("hu", "/admin/hu", "dice", "Bàn Hũ"), ("md5", "/admin/md5", "hash", "Bàn MD5"), ("modules", "/admin/modules", "cpu", "Modules"), ("backtest", "/admin/backtest", "flask", "Backtest"), ("predictions", "/admin/predictions", "target", "Predictions"), ("resolutions", "/admin/resolutions", "check", "Resolutions")]),
    ("Quản lý", [("keys", "/admin/keys", "key", "Keys & Khách hàng"), ("codes", "/admin/codes", "ticket", "Mã kích hoạt")]),
    ("Hệ thống", [("health", "/admin/health", "heart", "Sức khỏe"), ("logs", "/admin/logs", "logs", "Nhật ký"), ("settings", "/admin/settings", "gear", "Cài đặt")]),
]
NAV = [(k, h, ic, lb) for _, items in NAV_GROUPS for k, h, ic, lb in items]


def _admin_notifications():
    """3 loại cảnh báo: key sắp hết hạn, worker lỗi, accuracy giảm. Lỗi DB thì bỏ qua."""
    out = []
    try:
        c = db()
        rows = c.execute("SELECT expires_at FROM api_keys WHERE is_active=1 AND activated=1 AND expires_at IS NOT NULL").fetchall()
        now = datetime.now(timezone.utc); soon = 0
        for r in rows:
            e = parse_dt(r["expires_at"])
            if e and 0 < (e - now).total_seconds() < 3 * 86400:
                soon += 1
        if soon:
            out.append(("var(--am)", f"{soon} key sắp hết hạn", "Dưới 3 ngày, xem tại Keys", "/admin/keys"))
        for t in c.execute("SELECT t.code,t.name,s.last_poll_error FROM tables_ t LEFT JOIN table_states s ON s.table_code=t.code").fetchall():
            if t["last_poll_error"]:
                out.append(("var(--rd)", f"Worker lỗi · {t['name']}", str(t["last_poll_error"])[:60], "/admin/hu" if t["code"] == "lc79_tx" else "/admin/md5"))
            else:
                n = c.execute("SELECT COUNT(*) n,SUM(result='win') w FROM predictions WHERE table_code=? AND result IS NOT NULL", (t["code"],)).fetchone()
                if int(n["n"] or 0) >= 30:
                    acc = accuracy(t["code"], 100)
                    if acc < 0.5:
                        out.append(("var(--am)", f"Accuracy giảm · {t['name']}", f"100 phiên gần nhất: {acc*100:.1f}%", "/admin/hu" if t["code"] == "lc79_tx" else "/admin/md5"))
        c.close()
    except Exception:
        pass
    return out


def render_admin(title, active, body):
    nav = ""
    for label, items in NAV_GROUPS:
        nav += f'<div class="nav-label">{label}</div>'
        nav += "".join(f'<a class="nav-item {"active" if k == active else ""}" href="{h}" data-tooltip="{lb}"><i>{ui_icon(ic)}</i><span class="nav-text">{lb}</span></a>' for k, h, ic, lb in items)
    notes = _admin_notifications()
    notifs = "".join(f'<a class="notif" href="{href}"><span class="nd" style="background:{col}"></span><div><b>{esc(t1)}</b><span>{esc(t2)}</span></div></a>' for col, t1, t2, href in notes) or '<div class="empty" style="padding:18px">Không có cảnh báo.</div>'
    return render_template_string(BASE, title=title, active=active, body=body, nav=nav, notifs=notifs, notif_count=len(notes),
                                  admin_user=session.get("admin_user", "Quản trị"), version=APP_VERSION, engine=ENGINE_VERSION,
                                  ico_chev=ui_icon("chev"), ico_menu=ui_icon("menu"), ico_search=ui_icon("search", 15), ico_help=ui_icon("help"),
                                  ico_bell=ui_icon("bell"), ico_gear=ui_icon("gear", 16), ico_out=ui_icon("out", 16),
                                  ico_sun_js=ui_icon("sun"), ico_moon_js=ui_icon("moon"))


def _login_page(error=""):
    err = f'<div class="alert error">{esc(error)}</div>' if error else ""
    html = ('<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Đăng nhập · LC79</title>' + THEME_BOOT
            + CSS + '</head><body><div class="login-page"><form class="login-card" method="post"><div class="login-brand"><div class="brand-mark">PAW</div><div><b>P A W</b><div class="small muted">LC79 CONTROL</div></div></div>'
            '<h1>Đăng nhập quản trị</h1><p>Quản lý key, khách hàng, thiết bị và hệ thống dự đoán.</p>' + err +
            '<div class="field"><label>Tên đăng nhập</label><input class="input" name="username" required autocomplete="username" autofocus></div>'
            '<div class="field"><label>Mật khẩu</label><input class="input" type="password" name="password" required autocomplete="current-password"></div>'
            '<button class="btn btn-primary" type="submit">Đăng nhập</button><div class="small muted" style="text-align:center;margin-top:16px">Phiên có hiệu lực tối đa 8 giờ</div></form></div></body></html>')
    return html


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    ip = request.remote_addr or "?"
    if request.method == "POST":
        now = time.time()
        fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < 300]
        _LOGIN_FAILS[ip] = fails
        if len(fails) >= 5:
            return _login_page("Sai quá nhiều lần. Thử lại sau 5 phút."), 429
        user = request.form.get("username", ""); password = request.form.get("password", "")
        expect_user = os.environ.get("ADMIN_USER", "admin"); expect_pass = os.environ.get("ADMIN_PASS", "")
        if expect_pass and secrets.compare_digest(user, expect_user) and secrets.compare_digest(password, expect_pass):
            _LOGIN_FAILS.pop(ip, None)
            session.clear(); session["admin_user"] = user; session["admin_until"] = time.time() + 8 * 3600; session.permanent = True
            return redirect(url_for("admin_dashboard"))
        fails.append(now); _LOGIN_FAILS[ip] = fails
        return _login_page("Tên đăng nhập hoặc mật khẩu không đúng."), 401
    if session.get("admin_user"):
        return redirect("/admin")
    return _login_page()


@app.route("/admin/logout")
def admin_logout():
    session.clear(); return redirect("/admin/login")


# ------------------------------- ADMIN V4: HELPERS ---------------------------
ICONS.update({
    "activity": "<path d='M3 12h4l3-8 4 16 3-8h4'/>", "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "server": "<rect x='3' y='3' width='18' height='7' rx='2'/><rect x='3' y='14' width='18' height='7' rx='2'/><path d='M7 6h.01M7 17h.01'/>",
    "target": "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/><circle cx='12' cy='12' r='1'/>",
    "download": "<path d='M12 3v12m-5-5 5 5 5-5M4 21h16'/>", "trash": "<path d='M3 6h18M8 6V4h8v2m3 0-1 15H6L5 6m4 4v7m6-7v7'/>",
    "cpu": "<rect x='6' y='6' width='12' height='12' rx='2'/><path d='M9 2v4m6-4v4M9 18v4m6-4v4M2 9h4m-4 6h4m12-6h4m-4 6h4'/>",
    "flask": "<path d='M9 3h6M10 3v6l-5.5 9.5A2 2 0 0 0 6.2 21h11.6a2 2 0 0 0 1.7-2.5L14 9V3'/>",
    "list": "<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>", "check": "<path d='m5 12 4 4L19 6'/>",
    "plus": "<path d='M12 5v14M5 12h14'/>", "heart": "<path d='M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8l1 1.1L12 21l7.8-7.5 1-1.1a5.5 5.5 0 0 0 0-7.8Z'/>",
    "play": "<path d='m6 4 14 8-14 8Z'/>", "x": "<path d='m6 6 12 12M18 6 6 18'/>",
})
TABLE_HREF = {"lc79_tx": "/admin/hu", "lc79_md5": "/admin/md5"}
TABLE_COLOR = {"lc79_tx": "#2563eb", "lc79_md5": "#7c3aed"}


def side_badge(p):
    """Badge cửa dự đoán: TÀI / XỈU."""
    if p == "TAI": return '<span class="badge tai">TÀI</span>'
    if p == "XIU": return '<span class="badge xiu">XỈU</span>'
    return badge(esc(p or "—"), "neutral")


def result_badge(r):
    if r == "win": return '<span class="badge success dot">Thắng</span>'
    if r == "lose": return '<span class="badge danger dot">Thua</span>'
    return '<span class="badge warning dot">Chờ</span>'


def regime_badge(r):
    return f'<span class="badge info">{esc(r)}</span>' if r else '<span class="muted">—</span>'


def delta_html(cur, prev, points=False):
    """Mũi tên xanh/đỏ so với kỳ trước."""
    if prev in (None, 0) and not points:
        return '<span class="muted">— so với hôm qua</span>' if not cur else '<span class="dl up">▲ mới</span>'
    d = (cur - prev) if points else ((cur - prev) / prev * 100)
    cls = "up" if d >= 0 else "down"
    arrow = "▲" if d >= 0 else "▼"
    unit = " điểm" if points else "%"
    return f'<span class="dl {cls}">{arrow} {abs(d):.1f}{unit}</span>'


def stat_card2(icon, label, value, note="", tone=""):
    return (f'<div class="card stat2 {tone}"><div class="stat2-top"><span class="stat2-ic">{ui_icon(icon, 16)}</span><span class="stat-label">{label}</span></div>'
            f'<div class="stat-value">{value}</div><div class="stat-note">{note}</div></div>')


def page_head(title, sub="", actions=""):
    return f'<div class="page-head"><div><div class="page-title">{title}</div><div class="page-sub">{sub}</div></div><div class="actions">{actions}</div></div>'


def table_select(name, val, all_label=None):
    opts = f'<option value="">{all_label}</option>' if all_label else ""
    opts += "".join(f'<option value="{c}" {"selected" if c == val else ""}>{esc(m["name"])}</option>' for c, m in TABLES.items())
    return f'<select class="select" name="{name}" style="max-width:170px">{opts}</select>'


def pager(total, page, per, path):
    """Phân trang kiểu 'X-Y / Z'."""
    pages = max(1, (total + per - 1) // per)
    a = max(0, (page - 1) * per + 1) if total else 0
    b = min(total, page * per)
    q = "&".join(f"{k}={quote(str(v))}" for k, v in request.args.items() if k != "page")
    q = (q + "&") if q else ""
    off = "pointer-events:none;opacity:.35"
    return (f'<div class="pagination"><span class="small muted">{a:,}-{b:,} / {total:,}</span>'
            f'<a class="btn btn-sm" style="{off if page <= 1 else ""}" href="{path}?{q}page={page - 1}">← Trước</a>'
            f'<a class="btn btn-sm" style="{off if page >= pages else ""}" href="{path}?{q}page={page + 1}">Sau →</a></div>')


def _page_arg():
    try: return max(1, int(request.args.get("page", 1)))
    except ValueError: return 1


def _csv_response(name, header, rows):
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(header); w.writerows(rows)
    r = make_response("\ufeff" + buf.getvalue())  # BOM UTF-8 cho Excel
    r.headers["Content-Type"] = "text/csv; charset=utf-8"; r.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return r


def acc_cell(a, n):
    """Ô accuracy + thanh tiến độ: >60% xanh, 50-60% vàng, <50% đỏ."""
    if a is None: return '<span class="muted">—</span>'
    cls = "good" if a > .6 else ("warn" if a >= .5 else "bad")
    return f'<div class="mono"><b>{a * 100:.1f}%</b> <span class="muted small">n={n}</span></div><div class="progress {cls}" style="margin-top:5px"><span style="width:{a * 100:.1f}%"></span></div>'


def _module_stats(code, window):
    c = db(); rows = c.execute("SELECT module_votes_json,actual FROM prediction_resolutions WHERE table_code=? ORDER BY session_id DESC LIMIT ?", (code, window)).fetchall(); c.close()
    out = {}
    for name in PredictionEngine.EXPERTS:
        n = ok = 0
        for r in rows:
            try: v = json.loads(r["module_votes_json"] or "{}").get(name)
            except Exception: v = None
            if not v or r["actual"] not in ("TAI", "XIU"): continue
            n += 1; ok += int(("TAI" if float(v.get("p", .5)) >= .5 else "XIU") == r["actual"])
        out[name] = (ok / n if n else None, n)
    return out


def _fmt_uptime(s):
    d, r = divmod(int(s), 86400); h, r = divmod(r, 3600); m = r // 60
    return f"{d}n {h}g {m}p" if d else f"{h}g {m}p"


def _flash_script():
    msg = request.args.get("ok") or ""
    return f"<script>toast({json.dumps(msg, ensure_ascii=False)})</script>" if msg else ""


# ------------------------------- DASHBOARD -----------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = db()
    keys = conn.execute("SELECT * FROM api_keys").fetchall()
    counts = {"active": 0, "pending": 0, "expired": 0, "revoked": 0}
    for k in keys:
        counts[key_status(k)[2]] += 1
    d_today = "date('now','+7 hours')"; d_yest = "date('now','+7 hours','-1 day')"
    k_today = conn.execute(f"SELECT COUNT(*) FROM api_keys WHERE date(created_at,'+7 hours')={d_today}").fetchone()[0]
    k_yest = conn.execute(f"SELECT COUNT(*) FROM api_keys WHERE date(created_at,'+7 hours')={d_yest}").fetchone()[0]
    p_today = conn.execute(f"SELECT COUNT(*) FROM predictions WHERE date(created_at,'+7 hours')={d_today}").fetchone()[0]
    p_yest = conn.execute(f"SELECT COUNT(*) FROM predictions WHERE date(created_at,'+7 hours')={d_yest}").fetchone()[0]

    def acc_between(a, b):
        r = conn.execute("SELECT SUM(result='win') w,SUM(result IN ('win','lose')) n FROM predictions WHERE created_at>=datetime('now',?) AND created_at<datetime('now',?)", (a, b)).fetchone()
        return (int(r["w"] or 0) / int(r["n"]) * 100) if r["n"] else 0.0
    acc7 = acc_between("-7 days", "+1 day"); acc7_prev = acc_between("-14 days", "-7 days")
    tables = conn.execute("SELECT t.*,s.last_seen_id,s.last_poll_at,s.last_poll_error FROM tables_ t LEFT JOIN table_states s ON s.table_code=t.code ORDER BY t.sort_order").fetchall()
    latest = {t["code"]: conn.execute("SELECT * FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT 1", (t["code"],)).fetchone() for t in tables}
    series = {}
    for t in tables:
        rows = conn.execute("SELECT date(created_at,'+7 hours') d,SUM(result='win') w,SUM(result IN ('win','lose')) n FROM predictions WHERE table_code=? AND created_at>=datetime('now','-30 days') GROUP BY d ORDER BY d", (t["code"],)).fetchall()
        series[t["code"]] = {r["d"]: (round(int(r["w"] or 0) / int(r["n"]) * 100, 1) if r["n"] else None) for r in rows}
    per_day = conn.execute("SELECT date(created_at,'+7 hours') d,COUNT(*) n FROM predictions WHERE created_at>=datetime('now','-7 days') GROUP BY d ORDER BY d").fetchall()
    activity = conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()

    cards = "".join([
        stat_card2("key", "Tổng keys", f"{len(keys):,}", delta_html(k_today, k_yest) + f' <span class="muted">· {counts["revoked"]} đã thu hồi</span>'),
        stat_card2("check", "Keys active", f"{counts['active']:,}", f'<span class="muted">{counts["pending"]} chờ kích hoạt · {counts["expired"]} hết hạn</span>', "good"),
        stat_card2("activity", "Predictions hôm nay", f"{p_today:,}", delta_html(p_today, p_yest), "info"),
        stat_card2("target", "Accuracy 7 ngày", f"{acc7:.1f}%", delta_html(acc7, acc7_prev, True) + ' <span class="muted">so với 7 ngày trước</span>', "good" if acc7 >= 50 else "bad"),
    ])
    tcards = ""
    for t in tables:
        code = t["code"]; lp = latest.get(code)
        health = "red" if t["last_poll_error"] else ("green" if t["last_poll_at"] else "yellow")
        a100 = accuracy(code, 100) * 100; a500 = accuracy(code, 500) * 100
        cur = (f'<div class="bigpred">{side_badge(lp["prediction"])}<div><div class="mono" style="font-size:20px;font-weight:700">{int(lp["confidence"] or 0)}%</div><div class="small muted">độ tin cậy · phiên #{int(lp["session_id"]):,}</div></div>{result_badge(lp["result"])}</div>'
               if lp else '<div class="empty" style="padding:14px">Chưa có dự đoán.</div>')
        tcards += (f'<div class="card"><div class="card-head"><div class="card-title"><span class="health {health}"></span> {esc(t["name"])}</div>{badge("Đang chạy" if t["is_active"] else "Tạm dừng", "success" if t["is_active"] else "warning")}</div>{cur}'
                   f'<div class="kv c2" style="margin:14px 0"><div class="kv-item"><div class="kv-label">Accuracy 100</div><div class="kv-value mono">{a100:.1f}%</div></div><div class="kv-item"><div class="kv-label">Accuracy 500</div><div class="kv-value mono">{a500:.1f}%</div></div>'
                   f'<div class="kv-item"><div class="kv-label">Phiên mới nhất</div><div class="kv-value mono">{int(t["last_seen_id"] or 0):,}</div></div><div class="kv-item"><div class="kv-label">Poll gần nhất</div><div class="kv-value">{ago(t["last_poll_at"])}</div></div></div>'
                   f'{("<div class=small style=color:var(--rd-t);margin-bottom:10px>" + esc(t["last_poll_error"]) + "</div>") if t["last_poll_error"] else ""}<a class="btn btn-sm" href="{TABLE_HREF.get(code, "/admin")}">Xem chi tiết →</a></div>')
    days = sorted({d for s in series.values() for d in s})
    data = json.dumps({"labels": [d[5:] for d in days], "names": {t["code"]: t["name"] for t in tables},
                       "acc": {c: [s.get(d) for d in days] for c, s in series.items()},
                       "pd_labels": [str(r["d"])[5:] for r in per_day], "pd_vals": [int(r["n"]) for r in per_day]}, ensure_ascii=False)
    js = """<script>const D=__DATA__;const COL={lc79_tx:'#2563eb',lc79_md5:'#7c3aed'};
if(window.Chart){new Chart(document.getElementById('cAcc'),{type:'line',data:{labels:D.labels,datasets:Object.keys(D.acc).map(c=>({label:D.names[c],data:D.acc[c],borderColor:COL[c]||'#10b981',backgroundColor:(COL[c]||'#10b981')+'22',tension:.3,spanGaps:true,pointRadius:2}))},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100,ticks:{callback:v=>v+'%'}}}}});
new Chart(document.getElementById('cPd'),{type:'bar',data:{labels:D.pd_labels,datasets:[{label:'Predictions',data:D.pd_vals,backgroundColor:'#2563eb',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}})}</script>""".replace("__DATA__", data)
    timeline = "".join(f'<div class="timeline-item"><div class="timeline-title"><b>{esc(a["action"])}</b> · <span class="mono">{esc((a["target"] or "Hệ thống")[:40])}</span></div><div class="timeline-meta">{esc(a["admin_user"] or "Hệ thống")} · {ago(a["created_at"])}</div></div>' for a in activity) or '<div class="empty">Chưa có hoạt động.</div>'
    quick = ('<div class="card quick"><div class="card-title" style="margin-bottom:10px">Thao tác nhanh</div><div class="actions"><a class="btn btn-primary" href="/admin/keys">' + ui_icon("plus", 15) + ' Tạo key</a><a class="btn" href="/admin/codes">' + ui_icon("ticket", 15) + ' Tạo mã</a>'
             '<a class="btn" href="/admin/logs">' + ui_icon("list", 15) + ' Xem logs</a><a class="btn" href="/admin/health">' + ui_icon("heart", 15) + ' Sức khỏe hệ thống</a><a class="btn" href="/admin/settings">' + ui_icon("gear", 15) + ' Cài đặt</a></div></div>')
    body = (page_head("Dashboard", "Tổng quan keys, hai bàn và hoạt động gần đây.", '<a class="btn btn-primary" href="/admin/keys">+ Tạo key</a>')
            + f'<div class="grid stats">{cards}</div><div class="grid two">{tcards}</div>'
            '<div class="grid two" style="margin-top:16px"><div class="card"><div class="card-head"><div><div class="card-title">Accuracy 30 ngày</div><div class="card-sub">Hũ (xanh) và MD5 (tím) · giờ VN</div></div><button class="btn btn-sm" onclick="dlChart(\'cAcc\',\'accuracy-30d\')">' + ui_icon("download", 14) + ' PNG</button></div><div class="chart-box"><canvas id="cAcc"></canvas></div></div>'
            '<div class="card"><div class="card-head"><div><div class="card-title">Predictions mỗi ngày</div><div class="card-sub">7 ngày gần nhất</div></div><button class="btn btn-sm" onclick="dlChart(\'cPd\',\'predictions-7d\')">' + ui_icon("download", 14) + ' PNG</button></div><div class="chart-box"><canvas id="cPd"></canvas></div></div></div>'
            f'<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Hoạt động gần đây</div><a class="btn btn-quiet btn-sm" href="/admin/logs">Nhật ký →</a></div><div class="timeline">{timeline}</div></div><div style="margin-top:16px">{quick}</div>{js}')
    return render_admin("Dashboard", "dashboard", body)


# ------------------------------- MODULES -------------------------------------
@app.route("/admin/modules")
@admin_required
def admin_modules():
    try: window = max(30, min(1000, int(request.args.get("window", 100))))
    except ValueError: window = 100
    stats = {code: _module_stats(code, window) for code in TABLES}
    names = list(PredictionEngine.EXPERTS)
    codes = list(TABLES)
    trs = ""
    for n in names:
        avg_vals = [stats[c][n][0] for c in codes if stats[c][n][0] is not None]
        avg = sum(avg_vals) / len(avg_vals) if avg_vals else -1
        trs += f'<tr><td><b>{esc(n.replace("_", " ").title())}</b><div class="small muted mono">{esc(n)}</div></td>' + "".join(f'<td style="min-width:180px">{acc_cell(*stats[c][n])}</td>' for c in codes) + f'<td class="mono">{avg * 100:.1f}%</td></tr>' if avg >= 0 else f'<tr><td><b>{esc(n)}</b></td>' + "<td>—</td>" * len(codes) + '<td class="mono">—</td></tr>'
    heads = "".join(f'<th>{esc(TABLES[c]["name"])}</th>' for c in codes)
    chart = json.dumps({"labels": [n.replace("_", " ").title() for n in names],
                        "sets": [{"label": TABLES[c]["name"], "data": [round((stats[c][n][0] or 0) * 100, 1) for n in names], "backgroundColor": TABLE_COLOR.get(c, "#10b981"), "borderRadius": 4} for c in codes]}, ensure_ascii=False)
    sel = "".join(f'<a class="chip {"on" if w == window else ""}" href="/admin/modules?window={w}">{w} phiên</a> ' for w in (100, 300, 500, 1000))
    body = (page_head("Modules", f"Độ chính xác từng module dự đoán trên {window} phiên đã phân định gần nhất.", sel)
            + f'<div class="grid two"><div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table"><thead><tr><th>Module</th>{heads}<th>Trung bình</th></tr></thead><tbody>{trs}</tbody></table></div></div>'
            '<div class="card"><div class="card-head"><div><div class="card-title">Xếp hạng module</div><div class="card-sub">Accuracy % theo bàn</div></div><button class="btn btn-sm" onclick="dlChart(\'cMod\',\'modules\')">' + ui_icon("download", 14) + ' PNG</button></div><div class="chart-box" style="height:' + str(80 + 44 * len(names)) + 'px"><canvas id="cMod"></canvas></div></div></div>'
            '<script>const M=' + chart + ';if(window.Chart)new Chart(document.getElementById("cMod"),{type:"bar",data:{labels:M.labels,datasets:M.sets},options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,scales:{x:{min:0,max:100}}}})</script>')
    return render_admin("Modules", "modules", body)


# ------------------------------- BACKTEST ------------------------------------
def _kv_rows(d):
    rows = "".join(f'<tr><td class="mono">{esc(k)}</td><td class="mono">{v[0]:,}</td><td class="mono">{v[1]:,}</td><td>{acc_cell(v[1] / v[0] if v[0] else None, v[0])}</td></tr>' for k, v in sorted(d.items()))
    return rows or '<tr><td colspan="4" class="empty">Không có dữ liệu</td></tr>'


@app.route("/admin/backtest")
@admin_required
def admin_backtest_page():
    code = request.args.get("table", "lc79_tx"); code = code if code in TABLES else "lc79_tx"
    try: n = max(100, min(2000, int(request.args.get("n", 500))))
    except ValueError: n = 500
    form = (f'<form class="card toolbar" method="get" style="padding:14px"><div class="field" style="min-width:160px"><label>Bàn</label>{table_select("table", code)}</div>'
            f'<div class="field" style="width:150px"><label>Số phiên (100-2000)</label><input class="input" type="number" name="n" min="100" max="2000" step="50" value="{n}"></div>'
            '<input type="hidden" name="run" value="1"><div class="field"><label>&nbsp;</label><button class="btn btn-primary" onclick="this.classList.add(\'loading\')">' + ui_icon("play", 14) + ' Chạy backtest</button></div></form>')
    res = None
    if request.args.get("run"):
        c = db(); rows = c.execute("SELECT actual FROM predictions WHERE table_code=? AND actual IN ('TAI','XIU') ORDER BY session_id DESC LIMIT ?", (code, n)).fetchall(); c.close()
        hist = [1 if r["actual"] == "TAI" else 0 for r in reversed(rows)]
        if hist:
            res = Backtest.run(hist); admin_log("Chạy backtest", code, {"n": n})
    if res is None:
        out = '<div class="card empty">' + ("Chưa đủ dữ liệu để backtest." if request.args.get("run") else "Chọn bàn và số phiên rồi bấm <b>Chạy backtest</b>.") + "</div>"
    else:
        tl = [1 if x["correct"] else 0 for x in res["timeline"]]
        roll = [round(sum(tl[max(0, i - 29):i + 1]) / len(tl[max(0, i - 29):i + 1]) * 100, 1) for i in range(len(tl))]
        stats = "".join([stat_card2("target", "Accuracy", f'{res["accuracy"] * 100:.2f}%', "", "good" if res["accuracy"] >= .5 else "bad"), stat_card2("check", "Đúng / Tổng", f'{res["correct"]:,}/{res["total_predictions"]:,}'),
                         stat_card2("activity", "Chuỗi thắng dài nhất", res["streak_wins"], "", "good"), stat_card2("activity", "Chuỗi thua dài nhất", res["streak_losses"], "", "bad")])
        bm = "".join(f'<tr><td class="mono">{esc(k)}</td><td class="mono">{v["votes"]:,}</td><td class="mono">{v["correct"]:,}</td><td>{acc_cell(v["accuracy"] if v["votes"] else None, v["votes"])}</td></tr>' for k, v in res["by_module"].items())
        def tbl(title, inner, first="Nhóm"):
            return f'<div class="card" style="padding:0"><div class="card-head" style="padding:14px 16px 0"><div class="card-title">{title}</div></div><div class="table-wrap" style="border:0"><table class="data-table"><thead><tr><th>{first}</th><th>Số phiên</th><th>Đúng</th><th>Accuracy</th></tr></thead><tbody>{inner}</tbody></table></div></div>'
        export = {k: v for k, v in res.items() if k != "timeline"}
        out = (f'<div class="grid stats">{stats}</div><div class="grid two">{tbl("Theo regime", _kv_rows(res["by_regime"]), "Regime")}{tbl("Theo mức tin cậy", _kv_rows(res["by_confidence_bucket"]), "Bucket")}'
               f'{tbl("Theo cửa", _kv_rows(res["by_side"]), "Cửa")}{tbl("Theo module", bm, "Module")}</div>'
               '<div class="card" style="margin-top:16px"><div class="card-head"><div><div class="card-title">Accuracy trượt 30 phiên</div></div><div class="actions"><button class="btn btn-sm" onclick="dlChart(\'cBt\',\'backtest\')">' + ui_icon("download", 14) + ' PNG</button><button class="btn btn-sm" onclick="dlJson()">' + ui_icon("download", 14) + ' Export JSON</button></div></div><div class="chart-box"><canvas id="cBt"></canvas></div></div>'
               '<script>const R=' + json.dumps(export, ensure_ascii=False) + ',RL=' + json.dumps(roll) + ';function dlJson(){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(R,null,2)],{type:"application/json"}));a.download="backtest.json";a.click()}'
               'if(window.Chart)new Chart(document.getElementById("cBt"),{type:"line",data:{labels:RL.map((_,i)=>i+1),datasets:[{label:"Accuracy %",data:RL,borderColor:"#2563eb",backgroundColor:"#2563eb22",fill:true,tension:.3,pointRadius:0}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{min:0,max:100}}}})</script>')
    return render_admin("Backtest", "backtest", page_head("Backtest", "Chạy lại engine trên lịch sử kết quả thật của từng bàn.") + form + out)


# ------------------------------- PREDICTIONS ---------------------------------
def _pred_query():
    table = request.args.get("table", ""); result = request.args.get("result", ""); q = request.args.get("q", "").strip()
    try: days = int(request.args.get("days", 0))
    except ValueError: days = 0
    where, params = "WHERE 1=1", []
    if table in TABLES: where += " AND p.table_code=?"; params.append(table)
    if result in ("win", "lose"): where += " AND p.result=?"; params.append(result)
    elif result == "pending": where += " AND p.result IS NULL"
    if days > 0: where += " AND p.created_at>=datetime('now',?)"; params.append(f"-{days} days")
    if q: where += " AND CAST(p.session_id AS TEXT) LIKE ?"; params.append(f"%{q}%")
    return where, params, table, result, days, q


_PRED_FROM = "FROM predictions p LEFT JOIN prediction_resolutions r ON r.table_code=p.table_code AND r.session_id=p.session_id"


@app.route("/admin/predictions")
@admin_required
def admin_predictions():
    where, params, table, result, days, q = _pred_query(); page = _page_arg(); per = 100
    c = db()
    total = c.execute(f"SELECT COUNT(*) {_PRED_FROM} {where}", params).fetchone()[0]
    rows = c.execute(f"SELECT p.*,r.regime {_PRED_FROM} {where} ORDER BY p.created_at DESC,p.session_id DESC LIMIT ? OFFSET ?", params + [per, (page - 1) * per]).fetchall(); c.close()
    trs = "".join(f'<tr class="clickrow" onclick="showDetail(\'{r["table_code"]}\',{int(r["session_id"])})"><td class="mono">#{int(r["session_id"]):,}</td><td>{esc(TABLES.get(r["table_code"], {}).get("name", r["table_code"]))}</td><td>{side_badge(r["prediction"])}</td><td class="mono">{int(r["confidence"] or 0)}%</td><td>{side_badge(r["actual"]) if r["actual"] else "<span class=muted>—</span>"}</td><td>{result_badge(r["result"])}</td><td>{regime_badge(r["regime"])}</td><td class="muted" data-tooltip="{esc(fmt_date(r["created_at"]))}">{ago(r["created_at"])}</td><td style="text-align:right"><span class="muted">›</span></td></tr>' for r in rows)
    trs = trs or '<tr><td colspan="9"><div class="empty">Không có dự đoán phù hợp.</div></td></tr>'
    sel = lambda name, opts, val: f'<select class="select" name="{name}" style="max-width:150px">' + "".join(f'<option value="{a}" {"selected" if str(a) == str(val) else ""}>{b}</option>' for a, b in opts) + "</select>"
    flt = (f'<form class="toolbar sticky-filter" method="get"><div class="searchbox">{ui_icon("search", 15)}<input class="input" name="q" value="{esc(q)}" placeholder="Tìm số phiên…"></div>{table_select("table", table, "Mọi bàn")}'
           + sel("result", [("", "Mọi kết quả"), ("win", "Thắng"), ("lose", "Thua"), ("pending", "Chờ")], result) + sel("days", [(0, "Tất cả ngày"), (1, "24 giờ"), (7, "7 ngày"), (30, "30 ngày")], days)
           + '<button class="btn btn-primary">Lọc</button>' + ('<a class="btn btn-quiet" href="/admin/predictions">Xóa filter</a>' if (q or table or result or days) else "") + "</form>")
    qs = request.query_string.decode()
    acts = (f'<a class="btn" href="/admin/predictions/export.csv?{qs}">{ui_icon("download", 15)} Export CSV</a><button class="btn btn-danger" onclick="openModal(\'purgeModal\')">{ui_icon("trash", 15)} Xóa cũ</button>')
    modal = ('<div class="modal-backdrop" id="purgeModal" onclick="if(event.target===this)closeModal(\'purgeModal\')"><form class="modal" method="post" action="/admin/predictions/purge"><div class="modal-title">Xóa dự đoán cũ</div><div class="modal-body">Xóa vĩnh viễn dự đoán (và bản ghi phân định) cũ hơn số ngày bên dưới.<div class="field" style="margin-top:12px"><label>Cũ hơn (ngày)</label><input class="input" type="number" name="days" min="1" value="30"></div></div>'
             '<div class="modal-footer"><button type="button" class="btn" onclick="closeModal(\'purgeModal\')">Hủy</button><button class="btn btn-danger">Xóa</button></div></form></div>')
    js = """<script>function esc2(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function showDetail(code,sid){openDrawer('Phiên #'+sid,'<div class="skeleton" style="height:90px"></div>');try{const r=await fetch('/admin/'+code+'/detail/'+sid),d=await r.json();if(!r.ok)throw Error(d.message||'Không tải được');const det=d.detail||{},mods=det.modules||{};
const rows=Object.entries(mods).map(([k,v])=>{const p=Math.round(Number(v.p||.5)*100);return '<div style="margin-bottom:10px"><div class="module-label"><b>'+esc2(k)+'</b><span>p(TÀI)='+p+'% · w='+Number(v.weight||0).toFixed(3)+'</span></div><div class="progress '+(p>=50?'':'warn')+'"><span style="width:'+p+'%"></span></div></div>'}).join('');
document.getElementById('drawerBody').innerHTML='<div class="kv c2"><div class="kv-item"><div class="kv-label">Dự đoán</div><div class="kv-value">'+esc2(d.prediction)+'</div></div><div class="kv-item"><div class="kv-label">Thực tế</div><div class="kv-value">'+esc2(d.actual||'Chưa có')+'</div></div><div class="kv-item"><div class="kv-label">Tin cậy</div><div class="kv-value">'+esc2(d.confidence)+'%</div></div><div class="kv-item"><div class="kv-label">Regime</div><div class="kv-value">'+esc2(det.regime||'—')+'</div></div></div><h4 style="margin:18px 0 10px">Chi tiết module</h4>'+(rows||'<div class="muted">Không có dữ liệu module.</div>')+'<p class="muted">'+esc2(det.explanation||d.explanation||'')+'</p>'}catch(e){document.getElementById('drawerBody').textContent=e.message}}</script>"""
    body = (page_head("Predictions", f"{total:,} dự đoán · 100 dòng / trang · bấm một dòng để xem chi tiết.", acts) + flt
            + f'<div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table" data-nosort><thead><tr><th>Phiên</th><th>Bàn</th><th>Dự đoán</th><th>Tin cậy</th><th>Thực tế</th><th>Kết quả</th><th>Regime</th><th>Thời gian</th><th></th></tr></thead><tbody>{trs}</tbody></table></div></div>{pager(total, page, per, "/admin/predictions")}{modal}{js}{_flash_script()}')
    return render_admin("Predictions", "predictions", body)


@app.get("/admin/predictions/export.csv")
@admin_required
def admin_predictions_csv():
    where, params, *_ = _pred_query(); c = db()
    rows = c.execute(f"SELECT p.session_id,p.table_code,p.prediction,p.confidence,p.actual,p.result,r.regime,p.created_at,p.resolved_at {_PRED_FROM} {where} ORDER BY p.created_at DESC LIMIT 50000", params).fetchall(); c.close()
    return _csv_response("predictions.csv", ["session_id", "table", "prediction", "confidence", "actual", "result", "regime", "created_at", "resolved_at"], [tuple(r) for r in rows])


@app.post("/admin/predictions/purge")
@admin_required
def admin_predictions_purge():
    try: days = max(1, int(request.form.get("days", 30)))
    except ValueError: days = 30
    c = db(); cut = f"-{days} days"
    a = c.execute("DELETE FROM predictions WHERE created_at<datetime('now',?)", (cut,)).rowcount
    b = c.execute("DELETE FROM prediction_resolutions WHERE created_at<datetime('now',?)", (cut,)).rowcount
    c.commit(); c.close(); admin_log("Xóa dự đoán cũ", f">{days} ngày", {"predictions": a, "resolutions": b})
    return redirect(f"/admin/predictions?ok={quote(f'Đã xóa {a} dự đoán, {b} phân định')}")


# ------------------------------- RESOLUTIONS ---------------------------------
@app.route("/admin/resolutions")
@admin_required
def admin_resolutions():
    table = request.args.get("table", "")
    try: days = int(request.args.get("days", 7))
    except ValueError: days = 7
    page = _page_arg(); per = 100
    where, params = "WHERE 1=1", []
    if table in TABLES: where += " AND table_code=?"; params.append(table)
    if days > 0: where += " AND created_at>=datetime('now',?)"; params.append(f"-{days} days")
    c = db()
    total = c.execute(f"SELECT COUNT(*) FROM prediction_resolutions {where}", params).fetchone()[0]
    rows = c.execute(f"SELECT * FROM prediction_resolutions {where} ORDER BY created_at DESC,session_id DESC LIMIT ? OFFSET ?", params + [per, (page - 1) * per]).fetchall(); c.close()
    trs = ""
    for r in rows:
        try: votes = json.loads(r["module_votes_json"] or "{}")
        except Exception: votes = {}
        vh = "".join(f'<div style="margin-bottom:8px"><div class="module-label"><b>{esc(k)}</b><span>p(TÀI)={float(v.get("p", .5)) * 100:.1f}%</span></div><div class="progress"><span style="width:{float(v.get("p", .5)) * 100:.1f}%"></span></div></div>' for k, v in votes.items() if isinstance(v, dict)) or '<span class="muted">Không có module_votes.</span>'
        trs += (f'<tr class="clickrow" onclick="this.nextElementSibling.classList.toggle(\'open\')"><td class="mono">#{int(r["session_id"]):,}</td><td>{esc(TABLES.get(r["table_code"], {}).get("name", r["table_code"]))}</td><td>{side_badge(r["prediction"])}</td><td>{side_badge(r["actual"])}</td><td>{result_badge(r["result"])}</td><td>{regime_badge(r["regime"])}</td><td class="mono">{esc(r["top_module"] or "—")}</td><td class="mono">{int(r["confidence"] or 0)}%</td></tr>'
                f'<tr class="xdetail"><td colspan="8"><div style="padding:6px 4px;max-width:620px">{vh}</div></td></tr>')
    trs = trs or '<tr><td colspan="8"><div class="empty">Không có bản ghi phân định.</div></td></tr>'
    dsel = "".join(f'<option value="{v}" {"selected" if v == days else ""}>{t}</option>' for v, t in ((1, "24 giờ"), (7, "7 ngày"), (30, "30 ngày"), (0, "Tất cả")))
    flt = f'<form class="toolbar" method="get">{table_select("table", table, "Mọi bàn")}<select class="select" name="days" style="max-width:140px">{dsel}</select><button class="btn btn-primary">Lọc</button>' + ('<a class="btn btn-quiet" href="/admin/resolutions">Xóa filter</a>' if table else "") + "</form>"
    body = (page_head("Resolutions", f"{total:,} phiên đã phân định · bấm dòng để xem phiếu bầu từng module.") + flt
            + f'<div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table" data-nosort><thead><tr><th>Phiên</th><th>Bàn</th><th>Dự đoán</th><th>Thực tế</th><th>Kết quả</th><th>Regime</th><th>Top module</th><th>Tin cậy</th></tr></thead><tbody>{trs}</tbody></table></div></div>{pager(total, page, per, "/admin/resolutions")}')
    return render_admin("Resolutions", "resolutions", body)


# ------------------------------- HEALTH --------------------------------------
@app.route("/admin/health")
@admin_required
def admin_health():
    c = db()
    tables = c.execute("SELECT t.code,t.name,t.is_active,s.last_seen_id,s.last_poll_at,s.last_poll_error FROM tables_ t LEFT JOIN table_states s ON s.table_code=t.code ORDER BY t.sort_order").fetchall()
    np_ = c.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]; nr = c.execute("SELECT COUNT(*) FROM prediction_resolutions").fetchone()[0]
    hrs = {r["h"]: r["n"] for r in c.execute("SELECT strftime('%H',created_at,'+7 hours') h,COUNT(*) n FROM predictions WHERE created_at>=datetime('now','-24 hours') GROUP BY h").fetchall()}
    c.close()
    path = os.environ.get("DATABASE_PATH", "/tmp/lc79.db"); size = os.path.getsize(path) / 1048576 if os.path.exists(path) else 0
    stats = "".join([stat_card2("clock", "Uptime", _fmt_uptime(time.time() - APP_STARTED)), stat_card2("server", "DB size", f"{size:.2f} MB"),
                     stat_card2("list", "Predictions", f"{np_:,}"), stat_card2("check", "Resolutions", f"{nr:,}")])
    cards = ""
    for t in tables:
        d = parse_dt(t["last_poll_at"]); age = (datetime.now(timezone.utc) - d).total_seconds() if d else None
        slow = age is None or age > 30
        h = "red" if t["last_poll_error"] else ("yellow" if slow else "green")
        warn = (f'<div class="alert error" style="margin:12px 0 0">Poll chậm {int(age)} giây — worker có thể đang lỗi.</div>' if (age is not None and age > 30) else ('<div class="alert error" style="margin:12px 0 0">Chưa poll lần nào.</div>' if age is None else ""))
        err = f'<div class="alert error" style="margin:12px 0 0">{esc(t["last_poll_error"])}</div>' if t["last_poll_error"] else ""
        cards += (f'<div class="card"><div class="card-head"><div class="card-title"><span class="health {h}"></span> {esc(t["name"])}</div><span class="mono muted small">{t["code"]}</span></div>'
                  f'<div class="kv c2"><div class="kv-item"><div class="kv-label">Poll gần nhất</div><div class="kv-value">{ago(t["last_poll_at"])}</div></div><div class="kv-item"><div class="kv-label">Phiên mới nhất</div><div class="kv-value mono">{int(t["last_seen_id"] or 0):,}</div></div></div>{warn}{err}</div>')
    post = lambda act, label, cls="": f'<form method="post" action="/admin/health/action" onsubmit="this.querySelector(\'button\').classList.add(\'loading\')"><input type="hidden" name="action" value="{act}"><button class="btn {cls}">{label}</button></form>'
    actions = (f'<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Hành động hệ thống</div></div><div class="actions">{post("poll_all", ui_icon("refresh", 15) + " Force poll tất cả", "btn-primary")}{post("restart", ui_icon("cpu", 15) + " Restart worker")}{post("clear_rl", ui_icon("trash", 15) + " Xóa rate limits")}</div></div>')
    hour_labels = [f"{h:02d}" for h in range(24)]; hour_vals = [int(hrs.get(f"{h:02d}", 0)) for h in range(24)]
    chart = ('<div class="card" style="margin-top:16px"><div class="card-head"><div><div class="card-title">Predictions theo giờ</div><div class="card-sub">24 giờ gần nhất · giờ VN</div></div><button class="btn btn-sm" onclick="dlChart(\'cHr\',\'predictions-24h\')">' + ui_icon("download", 14) + ' PNG</button></div><div class="chart-box"><canvas id="cHr"></canvas></div></div>'
             '<script>if(window.Chart)new Chart(document.getElementById("cHr"),{type:"line",data:{labels:' + json.dumps(hour_labels) + ',datasets:[{label:"Predictions",data:' + json.dumps(hour_vals) + ',borderColor:"#2563eb",backgroundColor:"#2563eb22",fill:true,tension:.3}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}})</script>')
    ver = (f'<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Phiên bản</div></div><div class="kv c3"><div class="kv-item"><div class="kv-label">Version</div><div class="kv-value mono">{APP_VERSION}</div></div><div class="kv-item"><div class="kv-label">Build date</div><div class="kv-value mono">{BUILD_DATE}</div></div><div class="kv-item"><div class="kv-label">Engine</div><div class="kv-value mono">{ENGINE_VERSION}</div></div></div></div>')
    return render_admin("Sức khỏe hệ thống", "health", page_head("Sức khỏe hệ thống", "Worker, cơ sở dữ liệu và phiên bản.") + f'<div class="grid stats">{stats}</div><div class="grid two">{cards}</div>{actions}{chart}{ver}{_flash_script()}')


@app.post("/admin/health/action")
@admin_required
def admin_health_action():
    act = request.form.get("action", ""); msg = "Không có thao tác"
    if act == "poll_all":
        done = 0
        for code in TABLES:
            lock = _ADMIN_POLL_LOCKS[code]
            if lock.acquire(blocking=False):
                try:
                    c = db(); row = c.execute("SELECT * FROM tables_ WHERE code=?", (code,)).fetchone(); c.close()
                    if row: _load_worker_module().process_table(dict(row)); done += 1
                except Exception as exc:
                    admin_log("Force poll lỗi", code, {"error": str(exc)[:300]})
                finally: lock.release()
        admin_log("Force poll tất cả", "system", {"tables": done}); msg = f"Đã poll {done}/{len(TABLES)} bàn"
    elif act == "restart":
        for code in TABLES: set_worker_control("force_restart:" + code, "1")
        admin_log("Restart worker", "system"); msg = "Đã gửi yêu cầu restart worker"
    elif act == "clear_rl":
        c = db(); n = c.execute("DELETE FROM rate_limits").rowcount; c.commit(); c.close()
        admin_log("Xóa rate limits", "system", {"rows": n}); msg = f"Đã xóa {n} bản ghi rate limit"
    return redirect(f"/admin/health?ok={quote(msg)}")


# --------------------------------- KEYS --------------------------------------
def key_card(r, devs, req, req24):
    label, kind, code = key_status(r)
    cname = _col(r, "customer_name"); contact = _col(r, "contact"); note = _col(r, "note")
    initial = esc((cname[:1] or "?").upper())
    pct = remaining_pct(r)
    bar_cls = "bad" if pct < 15 else ("warn" if pct < 35 else "")
    if code == "pending":
        exp_text = f"Gói {duration_label(r['days'])} · bắt đầu khi dùng lần đầu"
    else:
        exp_text = rel_date(r["expires_at"])
    dev_html = ""
    for d in devs[:4]:
        on = is_online(d["last_seen"])
        dev_html += (f'<div class="dev"><span class="dev-ic">{dev_icon(d["os"])}</span><div style="flex:1;min-width:0"><b>{esc(d["browser"] or "Không rõ")} · {esc(d["os"] or "Không rõ")}</b>'
                     f'<small>IP {esc(d["ip"] or "—")} · ID {esc((d["device_id"] or "")[:10])}… · {ago(d["last_seen"])}</small></div><span class="dot {"on" if on else ""}" title="{"Đang online" if on else "Không hoạt động"}"></span></div>')
    if not dev_html:
        dev_html = '<div class="small muted" style="padding:6px 2px">Chưa có thiết bị nào đang dùng key này.</div>'
    extra = f'<div class="small muted" style="margin-top:6px">+{len(devs) - 4} thiết bị khác</div>' if len(devs) > 4 else ""
    search = " ".join([r["key"], cname, contact, note, r["scope"] or ""]).lower()
    k = quote(r["key"])
    toggle = (f'<form method="post" action="/admin/keys/{k}/restore"><button class="btn btn-ok btn-sm">↺ Khôi phục</button></form>' if not r["is_active"]
              else f'<form method="post" action="/admin/keys/{k}/revoke" onsubmit="return confirmAction(\'Thu hồi key này?\')"><button class="btn btn-danger btn-sm">⛔ Thu hồi</button></form>')
    note_html = f'<div class="small muted">📝 {esc(note)}</div>' if note else ""
    return f'''<article class="kcard" data-status="{code}" data-search="{esc(search)}" data-created="{epoch(r['created_at'])}" data-exp="{epoch(r['expires_at'])}" data-req="{req['n'] if req else 0}" data-last="{epoch(_col(r, 'last_used_at'))}">
<div class="khead"><div class="avatar">{initial}</div><div style="flex:1;min-width:0"><div class="kname">{esc(cname or "Chưa đặt tên")}</div><div class="kcontact">{esc(contact) if contact else "Chưa có liên hệ"}</div></div>{badge(label, kind)}</div>
<div class="keyline"><span class="mono">{r["key"]}</span><button class="btn btn-quiet btn-sm" onclick="copyText('{r["key"]}')">⧉ Copy</button></div>
<div class="krow"><div class="kcell"><small>Phạm vi</small><b>{scope_chips(r["scope"])}</b></div><div class="kcell"><small>Hết hạn</small><b>{"—" if code == "pending" else fmt_date(r["expires_at"])}</b></div><div class="kcell"><small>Thiết bị</small><b>{len(devs)}/{r["max_devices"]} đang dùng</b></div></div>
<div><div class="sec-label"><span>Thời hạn</span><span style="text-transform:none;letter-spacing:0;color:var(--tx2)">{exp_text}</span></div><div class="progress {bar_cls}"><span style="width:{pct:.1f}%"></span></div></div>
<div><div class="sec-label"><span>Thiết bị đang dùng</span></div>{dev_html}{extra}</div>
<div class="krow"><div class="kcell"><small>Tổng request</small><b>{(req['n'] if req else 0):,}</b></div><div class="kcell"><small>24 giờ qua</small><b>{req24:,}</b></div><div class="kcell"><small>Dùng lần cuối</small><b>{ago(_col(r, "last_used_at"))}</b></div></div>
{note_html}<div class="small muted">Tạo lúc {fmt_date(r["created_at"])}</div>
<div class="kfoot"><a class="btn btn-primary btn-sm" href="/admin/keys/{k}">Chi tiết đầy đủ →</a><a class="btn btn-sm" href="/admin/keys/{k}#edit">✎ Sửa</a><form method="post" action="/admin/keys/{k}/unlock"><button class="btn btn-sm">🔓 Mở khóa</button></form>{toggle}</div></article>'''


@app.route("/admin/keys", methods=["GET", "POST"])
@admin_required
def admin_keys():
    conn = db()
    if request.method == "POST":
        scope = request.form.get("scope", "lc79_tx,lc79_md5")
        if scope not in ("lc79_tx,lc79_md5", "lc79_tx", "lc79_md5"):
            scope = "lc79_tx,lc79_md5"
        cname = request.form.get("customer_name", "").strip()[:100]
        contact = request.form.get("contact", "").strip()[:120]
        note = request.form.get("note", "").strip()[:200]
        raw_days = request.form.get("custom_days", "").strip() or request.form.get("days", 30)
        try: days = max(60 / 86400, min(3650, float(raw_days)))
        except (TypeError, ValueError): days = 30.0
        try: max_devices = max(1, min(10, int(request.form.get("max_devices", 1))))
        except (TypeError, ValueError): max_devices = 1
        try: amount = max(1, min(500, int(request.form.get("amount", 1))))
        except (TypeError, ValueError): amount = 1
        made = []
        for _ in range(amount):
            key = "LC79-" + secrets.token_hex(12).upper()
            conn.execute("INSERT INTO api_keys(key,scope,note,expires_at,days,max_devices,activated,customer_name,contact) VALUES(?,?,?,?,?,?,0,?,?)",
                         (key, scope, note, None, days, max_devices, cname, contact))
            made.append(key)
        conn.commit(); conn.close()
        admin_log("Tạo key hàng loạt" if amount > 1 else "Tạo key", f"{amount} key · {cname or 'chưa đặt tên'}",
                  {"scope": scope, "duration": duration_label(days), "max_devices": max_devices})
        session["new_keys"] = made; session["new_keys_owner"] = cname
        return redirect("/admin/keys")

    rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
    dev_rows = conn.execute("SELECT * FROM api_key_devices WHERE released_at IS NULL ORDER BY last_seen DESC").fetchall()
    req_rows = {r["key"]: r for r in conn.execute("SELECT key,COUNT(*) n FROM activation_log WHERE reason LIKE 'API %' GROUP BY key").fetchall()}
    r24 = {r["key"]: r["n"] for r in conn.execute("SELECT key,COUNT(*) n FROM activation_log WHERE reason LIKE 'API %' AND created_at>=datetime('now','-1 day') GROUP BY key").fetchall()}
    conn.close()
    devs = {}
    for d in dev_rows:
        devs.setdefault(d["key"], []).append(d)
    cnt = {"active": 0, "pending": 0, "expired": 0, "revoked": 0}
    cards = []
    for r in rows:
        cnt[key_status(r)[2]] += 1
        cards.append(key_card(r, devs.get(r["key"], []), req_rows.get(r["key"]), r24.get(r["key"], 0)))
    grid = "".join(cards) or '<div class="card empty" style="grid-column:1/-1">Chưa có key nào. Bấm “Tạo key” để bắt đầu.</div>'
    new_keys = session.pop("new_keys", []); owner = session.pop("new_keys_owner", "")
    key_text = "\n".join(new_keys)
    online = sum(1 for d in dev_rows if is_online(d["last_seen"], 600))

    stats = "".join([stat_card("Tổng key", f"{len(rows):,}"), stat_card("Hoạt động", cnt["active"], "", "good"), stat_card("Chưa kích hoạt", cnt["pending"], "", "warn"),
                     stat_card("Hết hạn / thu hồi", f"{cnt['expired']} / {cnt['revoked']}", "", "bad"), stat_card("Thiết bị online", online, "10 phút qua", "info")])
    chips = (f'<button class="chip on" onclick="setStatus(\'\',this)">Tất cả<em>{len(rows)}</em></button>'
             f'<button class="chip" onclick="setStatus(\'active\',this)">Hoạt động<em>{cnt["active"]}</em></button>'
             f'<button class="chip" onclick="setStatus(\'pending\',this)">Chưa kích hoạt<em>{cnt["pending"]}</em></button>'
             f'<button class="chip" onclick="setStatus(\'expired\',this)">Hết hạn<em>{cnt["expired"]}</em></button>'
             f'<button class="chip" onclick="setStatus(\'revoked\',this)">Thu hồi<em>{cnt["revoked"]}</em></button>')
    created_modal = (f'<div class="modal-backdrop {"open" if new_keys else ""}" id="keysCreated"><div class="modal"><div class="modal-title">✅ Đã tạo {len(new_keys)} key</div>'
                     f'<div class="modal-body">{"Khách hàng: <b>" + str(esc(owner)) + "</b> · " if owner else ""}Thời hạn chỉ bắt đầu tính khi khách dùng key lần đầu.</div>'
                     f'<textarea class="textarea" id="newKeys" readonly>{esc(key_text)}</textarea><div class="modal-footer"><button class="btn" onclick="closeModal(\'keysCreated\')">Đóng</button>'
                     f'<button class="btn" onclick="copyText(document.getElementById(\'newKeys\').value)">Sao chép tất cả</button><button class="btn btn-primary" onclick="downloadKeys()">Tải .txt</button></div></div></div>')
    create_modal = '''<div class="modal-backdrop" id="createKey" onclick="if(event.target===this)closeModal('createKey')"><form class="modal" method="post"><div class="modal-title">Tạo key mới</div><div class="modal-body">Điền thông tin khách hàng để dễ quản lý. Thời hạn chỉ chạy khi khách kích hoạt lần đầu.</div>
<div class="grid two"><div class="field"><label>Tên khách hàng</label><input class="input" name="customer_name" maxlength="100" placeholder="VD: Nguyễn Văn A"></div><div class="field"><label>Liên hệ (Telegram / SĐT)</label><input class="input" name="contact" maxlength="120" placeholder="@username hoặc 09xx"></div></div>
<div class="field" style="margin-top:12px"><label>Ghi chú</label><input class="input" name="note" maxlength="200" placeholder="Gói VIP, đã thanh toán…"></div>
<div class="grid two" style="margin-top:12px"><div class="field"><label>Phạm vi bàn</label><select class="select" name="scope"><option value="lc79_tx,lc79_md5">Cả hai bàn</option><option value="lc79_tx">Chỉ bàn Hũ</option><option value="lc79_md5">Chỉ bàn MD5</option></select></div>
<div class="field"><label>Thời hạn</label><select class="select" name="days"><option value="0.0208333333">30 phút</option><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7" selected>7 ngày</option><option value="15">15 ngày</option><option value="30">30 ngày</option><option value="90">90 ngày</option><option value="365">365 ngày</option></select></div></div>
<div class="grid three" style="margin-top:12px"><div class="field"><label>Hoặc số ngày tùy chọn</label><input class="input" name="custom_days" type="number" step="0.01" min="0.01" placeholder="VD: 45"></div><div class="field"><label>Thiết bị tối đa</label><input class="input" name="max_devices" type="number" min="1" max="10" value="1" required></div><div class="field"><label>Số lượng key</label><input class="input" name="amount" type="number" min="1" max="500" value="1" required></div></div>
<div class="modal-footer"><button type="button" class="btn" onclick="closeModal('createKey')">Hủy</button><button class="btn btn-primary" type="submit">Tạo key</button></div></form></div>'''
    js = """<script>let curStatus='';
function applyKeyFilter(){const q=document.getElementById('keySearch').value.toLowerCase().trim();let n=0;document.querySelectorAll('.kcard').forEach(c=>{const ok=(!curStatus||c.dataset.status===curStatus)&&(!q||c.dataset.search.includes(q));c.style.display=ok?'':'none';if(ok)n++});document.getElementById('keyCount').textContent=n+' key'}
function setStatus(s,el){curStatus=s;document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on',x===el));applyKeyFilter()}
function sortKeys(v){const g=document.getElementById('keyGrid'),cs=[...g.children],f={new:c=>-c.dataset.created,exp:c=>c.dataset.exp?+c.dataset.exp:9e15,use:c=>-c.dataset.req,last:c=>-(c.dataset.last||0)};cs.sort((a,b)=>f[v](a)-f[v](b));cs.forEach(c=>g.appendChild(c))}
function downloadKeys(){const b=new Blob([document.getElementById('newKeys').value],{type:'text/plain;charset=utf-8'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='lc79-keys.txt';a.click();URL.revokeObjectURL(a.href)}
applyKeyFilter();</script>"""
    body = f'''<div class="page-head"><div><div class="page-title">Keys & Khách hàng</div><div class="page-sub">Mỗi key hiển thị đầy đủ: khách hàng, liên hệ, thời hạn, thiết bị đang dùng, lượt request.</div></div><div class="actions"><a class="btn" href="/admin/keys/export.csv">↓ Xuất CSV</a><button class="btn btn-primary" onclick="openModal('createKey')">＋ Tạo key</button></div></div>
<div class="grid stats">{stats}</div>
<div class="toolbar"><div class="searchbox">{svg_icon("search", 16)}<input id="keySearch" class="input" placeholder="Tìm theo tên khách, liên hệ, key, ghi chú…" oninput="applyKeyFilter()"></div>{chips}<select class="select" style="max-width:190px;margin-left:auto" onchange="sortKeys(this.value)"><option value="new">Mới tạo nhất</option><option value="exp">Sắp hết hạn trước</option><option value="use">Dùng nhiều nhất</option><option value="last">Dùng gần đây</option></select><span class="small muted" id="keyCount"></span></div>
<div class="kgrid" id="keyGrid">{grid}</div>{create_modal}{created_modal}{js}'''
    return render_admin("Keys & Khách hàng", "keys", body)


@app.get("/admin/keys/export.csv")
@admin_required
def export_keys():
    c = db(); rows = c.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall(); c.close()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["key", "khach_hang", "lien_he", "ghi_chu", "pham_vi", "trang_thai", "goi", "tao_luc", "het_han", "thiet_bi_toi_da", "dung_lan_cuoi"])
    for r in rows:
        w.writerow([r["key"], _col(r, "customer_name"), _col(r, "contact"), _col(r, "note"), r["scope"], key_status(r)[0], duration_label(r["days"]),
                    fmt_date(r["created_at"]), fmt_date(r["expires_at"]) if r["expires_at"] else "", r["max_devices"], fmt_date(_col(r, "last_used_at"))])
    resp = make_response("\ufeff" + buf.getvalue()); resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="lc79-keys.csv"'; return resp


@app.route("/admin/keys/<path:key>")
@admin_required
def admin_key_detail(key):
    conn = db(); k = conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    if not k:
        conn.close(); return render_admin("Không tìm thấy", "keys", '<div class="card empty">Key không tồn tại. <a class="btn btn-sm" href="/admin/keys">← Quay lại</a></div>'), 404
    devices = conn.execute("SELECT * FROM api_key_devices WHERE key=? ORDER BY (released_at IS NULL) DESC, last_seen DESC LIMIT 50", (key,)).fetchall()
    first_seen = conn.execute("SELECT MIN(first_seen) FROM api_key_devices WHERE key=?", (key,)).fetchone()[0]
    logs = conn.execute("SELECT * FROM activation_log WHERE key=? ORDER BY id DESC LIMIT 60", (key,)).fetchall()
    total_req = conn.execute("SELECT COUNT(*) FROM activation_log WHERE key=? AND reason LIKE 'API %'", (key,)).fetchone()[0]
    req24 = conn.execute("SELECT COUNT(*) FROM activation_log WHERE key=? AND reason LIKE 'API %' AND created_at>=datetime('now','-1 day')", (key,)).fetchone()[0]
    daily = conn.execute("SELECT date(created_at,'+7 hours') d,COUNT(*) n FROM activation_log WHERE key=? AND reason LIKE 'API %' AND created_at>=datetime('now','-14 days') GROUP BY d ORDER BY d", (key,)).fetchall()
    kinds = conn.execute("SELECT reason,COUNT(*) n FROM activation_log WHERE key=? AND reason LIKE 'API %' GROUP BY reason ORDER BY n DESC", (key,)).fetchall()
    conn.close()
    label, kind, code = key_status(k)
    pct = remaining_pct(k); bar_cls = "bad" if pct < 15 else ("warn" if pct < 35 else "")
    cname = _col(k, "customer_name"); contact = _col(k, "contact"); note = _col(k, "note")
    active_devs = [d for d in devices if not d["released_at"]]
    kq = quote(key)

    by_type = {}; by_table = {}
    for x in kinds:
        t, b = parse_req_reason(x["reason"])
        if t:
            by_type[t] = by_type.get(t, 0) + x["n"]; by_table[b] = by_table.get(b, 0) + x["n"]
    mix = "".join(f'<div class="detail-line"><b>{esc(n)}</b><span>{c:,}</span></div>' for n, c in by_type.items()) or '<div class="muted small">Chưa có dữ liệu</div>'
    mixt = "".join(f'<div class="detail-line"><b>{esc(SCOPE_NAMES.get(n, n))}</b><span>{c:,}</span></div>' for n, c in by_table.items()) or '<div class="muted small">Chưa có dữ liệu</div>'

    dev_rows = ""
    for d in devices:
        released = bool(d["released_at"]); on = (not released) and is_online(d["last_seen"])
        st = badge("Online", "success") if on else (badge("Đang giữ", "info") if not released else badge("Đã nhả", "neutral"))
        action = "" if released else f'<form method="post" action="/admin/keys/{kq}/device/{d["id"]}/release" onsubmit="return confirmAction(\'Nhả thiết bị này?\')"><button class="btn btn-danger btn-sm">Nhả</button></form>'
        dev_rows += (f'<tr><td>{dev_icon(d["os"])} <b>{esc(d["browser"] or "Không rõ")}</b> · {esc(d["os"] or "Không rõ")}</td><td class="mono" title="{esc(d["device_id"])}">{esc((d["device_id"] or "")[:20])}…</td>'
                     f'<td>{esc(d["ip"] or "—")}</td><td>{fmt_date(d["first_seen"])}</td><td>{fmt_date(d["last_seen"])}<div class="small muted">{ago(d["last_seen"])}</div></td>'
                     f'<td>{st}<div class="small muted">{esc(d["released_reason"] or "")}</div></td><td title="{esc(d["user_agent"] or "")}" style="max-width:260px;overflow:hidden;text-overflow:ellipsis">{esc((d["user_agent"] or "—")[:60])}</td><td>{action}</td></tr>')
    dev_rows = dev_rows or '<tr><td colspan="8" class="empty">Chưa có thiết bị nào dùng key này.</td></tr>'

    log_rows = ""
    for x in logs:
        t, b = parse_req_reason(x["reason"])
        ua = x["user_agent"] or ""
        log_rows += (f'<tr><td>{fmt_date(x["created_at"])}</td><td>{badge(esc(t) if t else "Kích hoạt", "info" if t else "neutral")}</td><td>{esc(SCOPE_NAMES.get(b, b)) if b else "—"}</td>'
                     f'<td>{badge("OK" if x["success"] else "Lỗi", "success" if x["success"] else "danger")}</td><td>{esc(x["ip"] or "—")}</td><td>{esc(_browser_name(ua))} / {esc(_os_name(ua))}</td><td class="muted">{esc(x["reason"] if not t else "")}</td></tr>')
    log_rows = log_rows or '<tr><td colspan="7" class="empty">Chưa có yêu cầu.</td></tr>'

    revoke_btn = (f'<form method="post" action="/admin/keys/{kq}/restore"><button class="btn btn-ok">↺ Khôi phục</button></form>' if not k["is_active"]
                  else f'<form method="post" action="/admin/keys/{kq}/revoke" onsubmit="return confirmAction(\'Thu hồi key?\')"><button class="btn btn-danger">⛔ Thu hồi</button></form>')
    exp_text = "Chưa kích hoạt" if code == "pending" else fmt_date(k["expires_at"])
    left_text = f"Gói {duration_label(k['days'])} · chưa bắt đầu" if code == "pending" else rel_date(k["expires_at"])
    data = json.dumps({"days": [str(x["d"])[5:] for x in daily], "counts": [int(x["n"]) for x in daily]})
    js = """<script>const D=__DATA__;if(window.Chart)new Chart(document.getElementById('kc'),{type:'bar',data:{labels:D.days,datasets:[{data:D.counts,backgroundColor:'rgba(34,211,238,.65)',borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8ea2bd'},grid:{color:'rgba(255,255,255,.06)'}},y:{ticks:{color:'#8ea2bd'},grid:{color:'rgba(255,255,255,.06)'},beginAtZero:true}}}});if(location.hash==='#edit')openModal('editKey');</script>""".replace("__DATA__", data)

    body = f'''<div class="page-head"><div style="display:flex;gap:14px;align-items:center"><div class="avatar" style="width:54px;height:54px;font-size:20px">{esc((cname[:1] or "?").upper())}</div><div><div class="page-title">{esc(cname or "Chưa đặt tên")} {badge(label, kind)}</div><div class="page-sub">{esc(contact) if contact else "Chưa có thông tin liên hệ"} · <a href="/admin/keys" style="color:var(--cy)">← Danh sách key</a></div></div></div>
<div class="actions"><button class="btn" onclick="openModal('editKey')">✎ Sửa thông tin</button><button class="btn" onclick="openModal('extendKey')">⏱ Gia hạn</button><form method="post" action="/admin/keys/{kq}/unlock"><button class="btn">🔓 Mở khóa thiết bị</button></form>{revoke_btn}<form method="post" action="/admin/keys/{kq}/delete" onsubmit="return confirmAction('XÓA VĨNH VIỄN key này cùng toàn bộ lịch sử thiết bị? Không thể hoàn tác.')"><button class="btn btn-danger">🗑 Xóa</button></form></div></div>
<div class="card" style="margin-bottom:16px"><div class="sec-label"><span>API Key</span></div><div class="keyline"><span class="mono" style="font-size:14px">{key}</span><button class="btn btn-sm" onclick="copyText('{key}')">⧉ Copy key</button></div></div>
<div class="grid stats">{stat_card("Trạng thái", label, left_text, "good" if code == "active" else ("warn" if code == "pending" else "bad"))}{stat_card("Tổng request", f"{total_req:,}", f"{req24:,} trong 24 giờ", "info")}{stat_card("Thiết bị đang dùng", f"{len(active_devs)}/{k['max_devices']}", "Đang giữ khóa")}{stat_card("Dùng lần cuối", ago(_col(k, "last_used_at")), fmt_date(_col(k, "last_used_at")))}</div>
<div class="card" style="margin-bottom:16px"><div class="card-head"><div><div class="card-title">Thời hạn sử dụng</div><div class="card-sub">{left_text}</div></div><b>{pct:.0f}%</b></div><div class="progress {bar_cls}" style="height:10px"><span style="width:{pct:.1f}%"></span></div></div>
<div class="card" style="margin-bottom:16px"><div class="card-head"><div class="card-title">Thông tin khách hàng & gói</div></div><div class="kv"><div class="kv-item"><div class="kv-label">Khách hàng</div><div class="kv-value">{esc(cname or "—")}</div></div><div class="kv-item"><div class="kv-label">Liên hệ</div><div class="kv-value">{esc(contact or "—")}</div></div><div class="kv-item"><div class="kv-label">Ghi chú</div><div class="kv-value">{esc(note or "—")}</div></div><div class="kv-item"><div class="kv-label">Phạm vi</div><div class="kv-value">{scope_chips(k["scope"])}</div></div>
<div class="kv-item"><div class="kv-label">Gói thời hạn</div><div class="kv-value">{duration_label(k["days"])}</div></div><div class="kv-item"><div class="kv-label">Ngày tạo</div><div class="kv-value">{fmt_date(k["created_at"])}</div></div><div class="kv-item"><div class="kv-label">Kích hoạt lần đầu</div><div class="kv-value">{fmt_date(first_seen) if first_seen else "Chưa kích hoạt"}</div></div><div class="kv-item"><div class="kv-label">Hết hạn</div><div class="kv-value">{exp_text}</div></div></div></div>
<div class="grid two" style="margin-bottom:16px"><div class="card"><div class="card-head"><div><div class="card-title">Request 14 ngày</div><div class="card-sub">Giờ Việt Nam</div></div></div><div class="chart-box" style="height:200px"><canvas id="kc"></canvas></div></div><div class="card"><div class="card-head"><div class="card-title">Phân loại request</div></div><div class="grid two"><div><div class="sec-label">Theo loại</div>{mix}</div><div><div class="sec-label">Theo bàn</div>{mixt}</div></div></div></div>
<div class="card" style="margin-bottom:16px"><div class="card-head"><div><div class="card-title">Thiết bị</div><div class="card-sub">Thông tin đầy đủ từng thiết bị đã dùng key · tối đa 50</div></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Trình duyệt / HĐH</th><th>Device ID</th><th>IP</th><th>Lần đầu</th><th>Hoạt động cuối</th><th>Trạng thái</th><th>User-Agent</th><th></th></tr></thead><tbody>{dev_rows}</tbody></table></div></div>
<div class="card"><div class="card-head"><div><div class="card-title">Nhật ký request</div><div class="card-sub">60 bản ghi gần nhất</div></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Thời gian</th><th>Loại</th><th>Bàn</th><th>Kết quả</th><th>IP</th><th>Thiết bị</th><th>Ghi chú</th></tr></thead><tbody>{log_rows}</tbody></table></div></div>
<div class="modal-backdrop" id="editKey" onclick="if(event.target===this)closeModal('editKey')"><form class="modal" method="post" action="/admin/keys/{kq}/edit"><div class="modal-title">Sửa thông tin</div><div class="modal-body">Cập nhật khách hàng và giới hạn thiết bị.</div><div class="field"><label>Tên khách hàng</label><input class="input" name="customer_name" maxlength="100" value="{esc(cname)}"></div><div class="field" style="margin-top:12px"><label>Liên hệ</label><input class="input" name="contact" maxlength="120" value="{esc(contact)}"></div><div class="field" style="margin-top:12px"><label>Ghi chú</label><input class="input" name="note" maxlength="200" value="{esc(note)}"></div><div class="field" style="margin-top:12px"><label>Số thiết bị tối đa</label><input class="input" type="number" name="max_devices" min="1" max="10" value="{k["max_devices"]}"></div><div class="modal-footer"><button type="button" class="btn" onclick="closeModal('editKey')">Hủy</button><button class="btn btn-primary">Lưu</button></div></form></div>
<div class="modal-backdrop" id="extendKey" onclick="if(event.target===this)closeModal('extendKey')"><form class="modal" method="post" action="/admin/keys/{kq}/extend"><div class="modal-title">Gia hạn key</div><div class="modal-body">Cộng thêm thời gian vào key. Nếu key chưa kích hoạt, gói sẽ được cộng thêm.</div><div class="field"><label>Cộng thêm (ngày)</label><select class="select" name="days"><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7" selected>7 ngày</option><option value="15">15 ngày</option><option value="30">30 ngày</option><option value="90">90 ngày</option><option value="365">365 ngày</option></select></div><div class="field" style="margin-top:12px"><label>Hoặc nhập số ngày</label><input class="input" type="number" step="0.01" min="0.01" name="custom_days" placeholder="VD: 45"></div><div class="modal-footer"><button type="button" class="btn" onclick="closeModal('extendKey')">Hủy</button><button class="btn btn-primary">Gia hạn</button></div></form></div>{js}'''
    return render_admin("Chi tiết key", "keys", body)


@app.post("/admin/keys/<path:key>/revoke")
@admin_required
def revoke_key(key):
    c = db(); c.execute("UPDATE api_keys SET is_active=0 WHERE key=?", (key,))
    c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị thu hồi key' WHERE key=? AND released_at IS NULL", (now_iso(), key))
    c.commit(); c.close(); admin_log("Thu hồi key", key); return redirect(request.referrer or "/admin/keys")


@app.post("/admin/keys/<path:key>/restore")
@admin_required
def restore_key(key):
    c = db(); c.execute("UPDATE api_keys SET is_active=1 WHERE key=?", (key,)); c.commit(); c.close(); admin_log("Khôi phục key", key)
    return redirect(request.referrer or "/admin/keys")


@app.post("/admin/keys/<path:key>/unlock")
@admin_required
def unlock_key(key):
    c = db(); c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị mở khóa' WHERE key=? AND released_at IS NULL", (now_iso(), key))
    c.commit(); c.close(); admin_log("Mở khóa thiết bị", key); return redirect(request.referrer or "/admin/keys")


@app.post("/admin/keys/<path:key>/device/<int:did>/release")
@admin_required
def release_device(key, did):
    c = db(); c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị nhả thiết bị' WHERE id=? AND key=? AND released_at IS NULL", (now_iso(), did, key))
    c.commit(); c.close(); admin_log("Nhả thiết bị", key, {"device_row": did}); return redirect(f"/admin/keys/{quote(key)}")


@app.post("/admin/keys/<path:key>/edit")
@admin_required
def edit_key(key):
    try: md = max(1, min(10, int(request.form.get("max_devices", 1))))
    except (TypeError, ValueError): md = 1
    c = db(); c.execute("UPDATE api_keys SET customer_name=?,contact=?,note=?,max_devices=? WHERE key=?",
                        (request.form.get("customer_name", "").strip()[:100], request.form.get("contact", "").strip()[:120], request.form.get("note", "").strip()[:200], md, key))
    c.commit(); c.close(); admin_log("Sửa thông tin key", key); return redirect(f"/admin/keys/{quote(key)}")


@app.post("/admin/keys/<path:key>/extend")
@admin_required
def extend_key(key):
    raw = request.form.get("custom_days", "").strip() or request.form.get("days", 7)
    try: add = max(60 / 86400, min(3650, float(raw)))
    except (TypeError, ValueError): add = 7.0
    c = db(); k = c.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    if k:
        if int(k["activated"] or 0) and k["expires_at"]:
            base = max(datetime.now(timezone.utc), parse_dt(k["expires_at"]) or datetime.now(timezone.utc))
            exp = (base + timedelta(seconds=_duration_seconds(add))).replace(microsecond=0).isoformat()
            c.execute("UPDATE api_keys SET expires_at=?,days=days+? WHERE key=?", (exp, add, key))
        else:
            c.execute("UPDATE api_keys SET days=days+? WHERE key=?", (add, key))
        c.commit(); admin_log("Gia hạn key", key, {"them": duration_label(add)})
    c.close(); return redirect(f"/admin/keys/{quote(key)}")


@app.post("/admin/keys/<path:key>/delete")
@admin_required
def delete_key(key):
    c = db(); c.execute("DELETE FROM api_key_devices WHERE key=?", (key,)); c.execute("DELETE FROM api_keys WHERE key=?", (key,)); c.commit(); c.close()
    admin_log("Xóa key", key); return redirect("/admin/keys")


# --------------------------------- CODES -------------------------------------
@app.route("/admin/codes", methods=["GET", "POST"])
@admin_required
def admin_codes():
    conn = db()
    if request.method == "POST":
        scope = request.form.get("scope", "lc79_tx,lc79_md5")
        if scope not in ("lc79_tx,lc79_md5", "lc79_tx", "lc79_md5"): scope = "lc79_tx,lc79_md5"
        raw = request.form.get("custom_days", "").strip() or request.form.get("days", 30)
        try: days = max(60 / 86400, min(3650, float(raw)))
        except (TypeError, ValueError): days = 30.0
        try: amount = max(1, min(500, int(request.form.get("amount", 1))))
        except (TypeError, ValueError): amount = 1
        try: uses = max(-1, min(1000, int(request.form.get("max_uses", 1))))
        except (TypeError, ValueError): uses = 1
        if uses == 0: uses = 1
        cname = request.form.get("customer_name", "").strip()[:100]; note = request.form.get("note", "").strip()[:200]
        made = []
        for _ in range(amount):
            code = "PAW-" + secrets.token_hex(5).upper()
            conn.execute("INSERT INTO activation_codes(code,scope,days,max_uses,created_by,customer_name,note) VALUES(?,?,?,?,?,?,?)",
                         (code, scope, days, uses, session.get("admin_user"), cname, note))
            made.append(code)
        conn.commit(); conn.close(); admin_log("Tạo mã kích hoạt", f"{amount} mã · {cname or 'chưa đặt tên'}", {"scope": scope, "duration": duration_label(days)})
        session["new_codes"] = made; return redirect("/admin/codes")
    rows = conn.execute("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT 500").fetchall()
    used = {}
    for x in conn.execute("SELECT code,key,created_at FROM activation_log WHERE code IS NOT NULL AND success=1 AND key IS NOT NULL ORDER BY id DESC").fetchall():
        used.setdefault(x["code"], []).append(x)
    conn.close()
    cnt = {"ok": 0, "done": 0, "revoked": 0}; tr = ""; avail = []
    for r in rows:
        if r["revoked"]: st, kind, sc = "Đã thu hồi", "danger", "revoked"
        elif r["max_uses"] != -1 and r["used_count"] >= r["max_uses"]: st, kind, sc = "Đã dùng hết", "neutral", "done"
        elif r["expires_at"] and r["expires_at"] < now_iso(): st, kind, sc = "Hết hạn", "warning", "done"
        else: st, kind, sc = "Còn khả dụng", "success", "ok"
        cnt[sc] += 1
        if sc == "ok": avail.append(r["code"])
        ks = "".join(f'<a class="chip-s" href="/admin/keys/{quote(u["key"])}">{esc(u["key"][:14])}…</a>' for u in used.get(r["code"], [])[:3]) or '<span class="muted">—</span>'
        mu = "∞" if r["max_uses"] == -1 else r["max_uses"]
        search = " ".join([r["code"], _col(r, "customer_name"), _col(r, "note")]).lower()
        tr += (f'<tr data-state="{sc}" data-s="{esc(search)}"><td class="mono"><b>{r["code"]}</b> <button class="btn btn-quiet btn-sm" onclick="copyText(\'{r["code"]}\')">⧉</button></td>'
               f'<td>{esc(_col(r, "customer_name") or "—")}<div class="small muted">{esc(_col(r, "note"))}</div></td><td>{scope_chips(r["scope"])}</td><td>{duration_label(r["days"])}</td>'
               f'<td>{r["used_count"]}/{mu}</td><td>{ks}</td><td>{fmt_date(r["created_at"])}</td><td>{badge(st, kind)}</td>'
               f'<td><form method="post" action="/admin/codes/{quote(r["code"])}/revoke" onsubmit="return confirmAction(\'Thu hồi mã này?\')"><button class="btn btn-danger btn-sm" {"disabled" if r["revoked"] else ""}>Thu hồi</button></form></td></tr>')
    tr = tr or '<tr><td colspan="9" class="empty">Chưa có mã kích hoạt.</td></tr>'
    new_codes = session.pop("new_codes", []); modal_text = "\n".join(new_codes)
    dur = '<option value="0.0208333333">30 phút</option><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7">7 ngày</option><option value="15">15 ngày</option><option value="30" selected>30 ngày</option><option value="90">90 ngày</option><option value="365">365 ngày</option>'
    stats = "".join([stat_card("Tổng mã", f"{len(rows):,}"), stat_card("Còn khả dụng", cnt["ok"], "", "good"), stat_card("Đã dùng hết / hết hạn", cnt["done"]), stat_card("Đã thu hồi", cnt["revoked"], "", "bad")])
    avail_json = json.dumps("\n".join(avail))
    body = f'''<div class="page-head"><div><div class="page-title">Mã kích hoạt</div><div class="page-sub">Phát mã cho khách; khách nhập mã để nhận key. Theo dõi mã nào đã sinh ra key nào.</div></div><div class="actions"><button class="btn" onclick="copyText({esc(avail_json)})">⧉ Copy mã còn khả dụng</button><button class="btn btn-primary" onclick="openModal('createCode')">＋ Tạo mã</button></div></div>
<div class="grid stats">{stats}</div>
<div class="toolbar"><div class="searchbox">{svg_icon("search", 16)}<input id="codeSearch" class="input" placeholder="Tìm mã, tên khách, ghi chú…" oninput="codeFilter()"></div><select class="select" id="codeState" style="max-width:190px" onchange="codeFilter()"><option value="">Tất cả trạng thái</option><option value="ok">Còn khả dụng</option><option value="done">Đã dùng hết / hết hạn</option><option value="revoked">Đã thu hồi</option></select></div>
<div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table" id="codeTable"><thead><tr><th>Mã</th><th>Khách / ghi chú</th><th>Phạm vi</th><th>Thời hạn</th><th>Đã dùng</th><th>Key đã sinh</th><th>Tạo lúc</th><th>Trạng thái</th><th></th></tr></thead><tbody>{tr}</tbody></table></div></div>
<div class="modal-backdrop" id="createCode" onclick="if(event.target===this)closeModal('createCode')"><form class="modal" method="post"><div class="modal-title">Tạo mã kích hoạt</div><div class="modal-body">Tên khách và ghi chú sẽ được gắn tự động vào key khi khách kích hoạt.</div>
<div class="grid two"><div class="field"><label>Tên khách hàng</label><input class="input" name="customer_name" maxlength="100" placeholder="Tùy chọn"></div><div class="field"><label>Ghi chú</label><input class="input" name="note" maxlength="200" placeholder="Tùy chọn"></div></div>
<div class="grid two" style="margin-top:12px"><div class="field"><label>Phạm vi bàn</label><select class="select" name="scope"><option value="lc79_tx,lc79_md5">Cả hai bàn</option><option value="lc79_tx">Chỉ bàn Hũ</option><option value="lc79_md5">Chỉ bàn MD5</option></select></div><div class="field"><label>Thời hạn</label><select class="select" name="days">{dur}</select></div></div>
<div class="grid three" style="margin-top:12px"><div class="field"><label>Số ngày tùy chọn</label><input class="input" name="custom_days" type="number" step="0.01" min="0.01"></div><div class="field"><label>Số lượng mã</label><input class="input" name="amount" type="number" min="1" max="500" value="1"></div><div class="field"><label>Lượt/mã (-1 = ∞)</label><input class="input" name="max_uses" type="number" min="-1" value="1"></div></div>
<div class="modal-footer"><button type="button" class="btn" onclick="closeModal('createCode')">Hủy</button><button class="btn btn-primary">Tạo mã</button></div></form></div>
<div class="modal-backdrop {"open" if new_codes else ""}" id="codesModal"><div class="modal"><div class="modal-title">✅ Đã tạo {len(new_codes)} mã</div><div class="modal-body">Sao chép hoặc tải về để gửi cho khách.</div><textarea class="textarea" id="newCodes" readonly>{esc(modal_text)}</textarea><div class="modal-footer"><button class="btn" onclick="closeModal('codesModal')">Đóng</button><button class="btn" onclick="copyText(document.getElementById('newCodes').value)">Sao chép tất cả</button><button class="btn btn-primary" onclick="dlCodes()">Tải .txt</button></div></div></div>
<script>function codeFilter(){{const q=document.getElementById('codeSearch').value.toLowerCase(),s=document.getElementById('codeState').value;document.querySelectorAll('#codeTable tbody tr').forEach(r=>{{r.style.display=((!s||r.dataset.state===s)&&(!q||(r.dataset.s||'').includes(q)))?'':'none'}})}}function dlCodes(){{const b=new Blob([document.getElementById('newCodes').value],{{type:'text/plain'}}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='lc79-codes.txt';a.click();URL.revokeObjectURL(a.href)}}</script>'''
    return render_admin("Mã kích hoạt", "codes", body)


@app.post("/admin/codes/<path:code>/revoke")
@admin_required
def revoke_code(code):
    c = db(); c.execute("UPDATE activation_codes SET revoked=1 WHERE code=?", (code,)); c.commit(); c.close(); admin_log("Thu hồi mã", code); return redirect("/admin/codes")


# --------------------------------- LOGS --------------------------------------
@app.route("/admin/logs")
@admin_required
def admin_logs():
    tab = request.args.get("tab", "admin"); q = request.args.get("q", "").strip(); action = request.args.get("action", "")
    try: page = max(1, int(request.args.get("page", 1)))
    except ValueError: page = 1
    per = 100; off = (page - 1) * per
    conn = db(); like = f"%{q}%"
    if tab == "access":
        where = "WHERE 1=1"; params = []
        flt = request.args.get("ok", "")
        if flt in ("0", "1"): where += " AND l.success=?"; params.append(int(flt))
        if q: where += " AND (l.key LIKE ? OR l.ip LIKE ? OR l.reason LIKE ? OR k.customer_name LIKE ?)"; params += [like] * 4
        total = conn.execute(f"SELECT COUNT(*) FROM activation_log l LEFT JOIN api_keys k ON k.key=l.key {where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT l.*,k.customer_name cn FROM activation_log l LEFT JOIN api_keys k ON k.key=l.key {where} ORDER BY l.id DESC LIMIT ? OFFSET ?", params + [per, off]).fetchall()
        trs = ""
        for r in rows:
            t, b = parse_req_reason(r["reason"]); ua = r["user_agent"] or ""
            kcell = f'<a href="/admin/keys/{quote(r["key"])}" class="mono" style="color:var(--cy)">{esc(r["key"][:16])}…</a>' if r["key"] else "—"
            trs += (f'<tr><td>{fmt_date(r["created_at"])}</td><td>{esc(r["cn"] or "—")}</td><td>{kcell}</td><td>{badge(esc(t), "info") if t else badge("Kích hoạt", "neutral")}</td><td>{esc(SCOPE_NAMES.get(b, b)) if b else "—"}</td>'
                    f'<td>{badge("OK" if r["success"] else "Lỗi", "success" if r["success"] else "danger")}</td><td>{esc(r["ip"] or "—")}</td><td>{esc(_browser_name(ua))} / {esc(_os_name(ua))}</td><td class="muted">{esc(r["reason"] if not t else (r["code"] or ""))}</td></tr>')
        head = "<th>Thời gian</th><th>Khách</th><th>Key</th><th>Loại</th><th>Bàn</th><th>Kết quả</th><th>IP</th><th>Thiết bị</th><th>Ghi chú / Mã</th>"
        extra_filter = f'<select class="select" name="ok" style="max-width:160px"><option value="">Mọi kết quả</option><option value="1" {"selected" if flt == "1" else ""}>Thành công</option><option value="0" {"selected" if flt == "0" else ""}>Thất bại</option></select>'
        cols = 9
    else:
        where = "WHERE 1=1"; params = []
        if action: where += " AND action=?"; params.append(action)
        if q: where += " AND (target LIKE ? OR detail_json LIKE ? OR admin_user LIKE ? OR ip LIKE ?)"; params += [like] * 4
        total = conn.execute(f"SELECT COUNT(*) FROM admin_actions {where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM admin_actions {where} ORDER BY id DESC LIMIT ? OFFSET ?", params + [per, off]).fetchall()
        acts = [r[0] for r in conn.execute("SELECT DISTINCT action FROM admin_actions WHERE action IS NOT NULL ORDER BY action").fetchall()]
        trs = "".join(f'<tr><td>{fmt_date(r["created_at"])}</td><td>{esc(r["admin_user"] or "Hệ thống")}</td><td><b>{esc(r["action"])}</b></td><td class="mono">{esc((r["target"] or "—")[:40])}</td><td class="muted" style="max-width:380px;overflow:hidden;text-overflow:ellipsis" title="{esc(r["detail_json"] or "")}">{esc((r["detail_json"] or "")[:90])}</td><td>{esc(r["ip"] or "—")}</td></tr>' for r in rows)
        head = "<th>Thời gian</th><th>Quản trị</th><th>Thao tác</th><th>Đối tượng</th><th>Chi tiết</th><th>IP</th>"
        extra_filter = '<select class="select" name="action" style="max-width:240px"><option value="">Tất cả thao tác</option>' + "".join(f'<option value="{esc(x)}" {"selected" if x == action else ""}>{esc(x)}</option>' for x in acts) + "</select>"
        cols = 6
    conn.close()
    trs = trs or f'<tr><td colspan="{cols}" class="empty">Không có bản ghi phù hợp.</td></tr>'
    pages = max(1, (total + per - 1) // per)
    base_q = "&".join(f"{k}={quote(str(v))}" for k, v in request.args.items() if k != "page")
    pg = (f'<div class="pagination"><span class="small muted">{total:,} bản ghi · trang {page}/{pages}</span>'
          f'<a class="btn btn-sm" style="{"pointer-events:none;opacity:.35" if page <= 1 else ""}" href="/admin/logs?{base_q}&page={page - 1}">← Trước</a>'
          f'<a class="btn btn-sm" style="{"pointer-events:none;opacity:.35" if page >= pages else ""}" href="/admin/logs?{base_q}&page={page + 1}">Sau →</a></div>')
    body = f'''<div class="page-head"><div><div class="page-title">Nhật ký</div><div class="page-sub">Thao tác quản trị và toàn bộ lượt truy cập API / kích hoạt của khách.</div></div></div>
<div class="tabs"><a class="tab {"on" if tab != "access" else ""}" href="/admin/logs?tab=admin">Thao tác quản trị</a><a class="tab {"on" if tab == "access" else ""}" href="/admin/logs?tab=access">Truy cập & kích hoạt</a></div>
<form class="toolbar" method="get"><input type="hidden" name="tab" value="{esc(tab)}"><div class="searchbox">{svg_icon("search", 16)}<input class="input" name="q" value="{esc(q)}" placeholder="Tìm kiếm key, tên khách, IP, nội dung…"></div>{extra_filter}<button class="btn btn-primary">Lọc</button><a class="btn" href="/admin/logs?tab={esc(tab)}">Xóa lọc</a></form>
<div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table"><thead><tr>{head}</tr></thead><tbody>{trs}</tbody></table></div></div>{pg}'''
    return render_admin("Nhật ký", "logs", body)


# -------------------------------- SETTINGS -----------------------------------
@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        code = request.form.get("table_code", "")
        if code in TABLES:
            try: shrink = max(.1, min(1., float(request.form.get("shrink_extra", 1))))
            except ValueError: shrink = 1.
            try: minimum = max(50, min(85, int(request.form.get("min_confidence", 50))))
            except ValueError: minimum = 50
            enabled = set(request.form.getlist("enabled_modules"))
            disabled = [m for m in PredictionEngine.EXPERTS if m not in enabled]
            save_table_config(code, {"disabled_modules": disabled, "shrink_extra": shrink, "min_confidence": minimum})
            admin_log("Cập nhật cấu hình bàn", code, {"disabled": disabled, "shrink": shrink, "min_conf": minimum})
        return redirect("/admin/settings")
    parts = []
    for code, meta in TABLES.items():
        cfg = get_table_config(code); dis = set(cfg.get("disabled_modules", []))
        pills = "".join(f'<label class="pill"><input type="checkbox" name="enabled_modules" value="{m}" {"" if m in dis else "checked"}><span>{esc(m.replace("_", " ").title())}</span></label>' for m in PredictionEngine.EXPERTS)
        parts.append(f'<div class="card"><div class="card-head"><div><div class="card-title">{esc(meta["name"])}</div><div class="card-sub mono">{code}</div></div>{badge(f"{len(PredictionEngine.EXPERTS) - len(dis)}/{len(PredictionEngine.EXPERTS)} module bật", "info")}</div>'
                     f'<form method="post"><input type="hidden" name="table_code" value="{code}"><div class="sec-label">Module dự đoán (tick = bật)</div><div>{pills}</div>'
                     f'<div class="grid two" style="margin-top:12px"><div class="field"><label>Shrink extra (0.1–1)</label><input class="input" name="shrink_extra" type="number" min="0.1" max="1" step="0.1" value="{cfg.get("shrink_extra", 1)}"></div><div class="field"><label>Độ tin cậy tối thiểu (50–85)</label><input class="input" name="min_confidence" type="number" min="50" max="85" value="{cfg.get("min_confidence", 50)}"></div></div>'
                     f'<button class="btn btn-primary" style="margin-top:16px">Lưu cấu hình</button></form></div>')
    try: bc = get_broadcast()
    except Exception: bc = ""
    path = os.environ.get("DATABASE_PATH", "/tmp/lc79.db"); size = os.path.getsize(path) / 1048576 if os.path.exists(path) else 0
    up = int(time.time() - APP_STARTED)
    sysinfo = (f'<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Thông tin hệ thống</div></div><div class="kv"><div class="kv-item"><div class="kv-label">Phiên bản</div><div class="kv-value">{APP_VERSION}</div></div>'
               f'<div class="kv-item"><div class="kv-label">Engine</div><div class="kv-value">{ENGINE_VERSION}</div></div><div class="kv-item"><div class="kv-label">Uptime</div><div class="kv-value">{up // 3600}h {(up % 3600) // 60}m</div></div>'
               f'<div class="kv-item"><div class="kv-label">Dung lượng DB</div><div class="kv-value">{size:.2f} MB</div></div></div>'
               f'<div class="detail-line" style="margin-top:12px"><span>Broadcast đang phát</span><b>{esc(bc) if bc else "Không có"}</b></div><div class="detail-line"><span>Phiên quản trị</span><b>{esc(session.get("admin_user", ""))} · hết hạn {fmt_date(datetime.fromtimestamp(session.get("admin_until", 0), timezone.utc).isoformat())}</b></div></div>')
    body = ('<div class="page-head"><div><div class="page-title">Cài đặt</div><div class="page-sub">Bật/tắt module và tinh chỉnh engine cho từng bàn.</div></div></div><div class="grid two">'
            + "".join(parts) + "</div>" + sysinfo)
    return render_admin("Cài đặt", "settings", body)


# === END app.py ===

# Analytics endpoints: same key scope and per-key 60 req/min limiter as /makey.
def _analytics_access():
    table=request.args.get("table","").strip()
    if table not in TABLES:return None,None,api_error("invalid_table","Mã bàn không hợp lệ",400)
    row,error=_key_access(request.args.get("key","").strip(),table)
    return table,row,error

@app.get("/history")
def api_history():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:limit=max(1,min(105,int(request.args.get("limit",105))))
    except ValueError:limit=105
    c=db();rows=c.execute("SELECT session_id,prediction,confidence,actual,result FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT ?",(table,limit)).fetchall();c.close()
    items=[{"phien":r["session_id"],"dudoan":r["prediction"],"confidence":r["confidence"],"ketqua":r["actual"] or "chuacoketqua","trangthai":"" if not r["actual"] else ("win" if r["result"]=="win" else "lose")} for r in rows]
    return jsonify({"ok":True,"table":table,"table_name":TABLES[table]["name"],"count":len(items),"items":items})

@app.get("/stats")
def api_stats():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:days=max(1,min(365,int(request.args.get("days",7))))
    except ValueError:days=7
    c=db();rows=c.execute("SELECT date(created_at) day,COUNT(*) total,SUM(result='win') wins,SUM(result='lose') losses,SUM(result IS NULL) pending FROM predictions WHERE table_code=? AND created_at>=datetime('now',?) GROUP BY date(created_at) ORDER BY day",(table,f"-{days} days")).fetchall();tot=c.execute("SELECT COUNT(*) total,SUM(result='win') wins,SUM(result='lose') losses,SUM(result IS NULL) pending FROM predictions WHERE table_code=? AND created_at>=datetime('now',?)",(table,f"-{days} days")).fetchone();reg=c.execute("SELECT regime,COUNT(*) n,SUM(result='win') wins FROM prediction_resolutions WHERE table_code=? AND created_at>=datetime('now',?) GROUP BY regime",(table,f"-{days} days")).fetchall();conf=c.execute("SELECT CASE WHEN confidence<60 THEN '50-59' WHEN confidence<70 THEN '60-69' WHEN confidence<80 THEN '70-79' ELSE '80-85' END bucket,COUNT(*) n,SUM(result='win') wins FROM predictions WHERE table_code=? AND result IS NOT NULL AND created_at>=datetime('now',?) GROUP BY bucket",(table,f"-{days} days")).fetchall();c.close()
    total=tot["total"] or 0;wins=tot["wins"] or 0;decided=wins+(tot["losses"] or 0)
    return jsonify({"total":total,"wins":wins,"losses":tot["losses"] or 0,"accuracy":wins/decided if decided else 0,"pending":tot["pending"] or 0,"by_day":[dict(x) for x in rows],"by_regime":[dict(x) for x in reg],"by_confidence":[dict(x) for x in conf]})

@app.get("/regime")
def api_regime():
    table,keyrow,error=_analytics_access()
    if error:return error
    pred=load_engine(table).predict_detail();c=db();rows=c.execute("SELECT actual FROM predictions WHERE table_code=? AND actual IS NOT NULL ORDER BY session_id DESC LIMIT 50",(table,)).fetchall();c.close();hist=[1 if r[0]=="TAI" else 0 for r in reversed(rows)]
    return jsonify({"regime":pred["regime"],"regime_conf":pred["regime_conf"],"regime_details":pred["regime_details"],"distribution_50":{"tai":sum(hist),"xiu":len(hist)-sum(hist)},"history_30":hist[-30:]})

@app.get("/modules")
def api_modules():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:window=max(1,min(1000,int(request.args.get("window",100))))
    except ValueError:window=100
    c=db();rows=c.execute("SELECT module_votes_json,result,actual,regime FROM prediction_resolutions WHERE table_code=? ORDER BY session_id DESC LIMIT ?",(table,window)).fetchall();c.close();out={}
    for name in PredictionEngine.EXPERTS:
        n=correct=0;conf_ok=[];conf_bad=[];reg={}
        for row in rows:
            try:v=json.loads(row["module_votes_json"] or "{}").get(name)
            except Exception:v=None
            if not v or row["actual"] not in ("TAI","XIU"):continue
            p=float(v.get("p",.5));conf=float(v.get("conf",0));ok=("TAI" if p>=.5 else "XIU")==row["actual"];n+=1;correct+=int(ok);(conf_ok if ok else conf_bad).append(conf)
            key=row["regime"] or "UNKNOWN";reg.setdefault(key,[0,0]);reg[key][0]+=1;reg[key][1]+=int(ok)
        ranked=sorted(((k,v[1]/v[0],v[0]) for k,v in reg.items() if v[0]>=3),key=lambda x:x[1]);out[name]={"accuracy":correct/n if n else None,"votes":n,"best_regime":ranked[-1][0] if ranked else None,"worst_regime":ranked[0][0] if ranked else None,"avg_conf_correct":sum(conf_ok)/len(conf_ok) if conf_ok else None,"avg_conf_wrong":sum(conf_bad)/len(conf_bad) if conf_bad else None}
    return jsonify(out)

@app.get("/backtest")
def api_backtest():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:n=max(30,min(5000,int(request.args.get("sessions",500))))
    except ValueError:n=500
    c=db();rows=c.execute("SELECT actual FROM predictions WHERE table_code=? AND actual IS NOT NULL ORDER BY session_id DESC LIMIT ?",(table,n)).fetchall();c.close();return jsonify(Backtest.run([1 if r[0]=="TAI" else 0 for r in reversed(rows)]))

@app.get("/detail")
def api_detail():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:sid=int(request.args.get("session_id","0"))
    except ValueError:return api_error("invalid_session","session_id không hợp lệ",400)
    c=db();r=c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=?",(table,sid)).fetchone();c.close()
    if not r:return api_error("not_found","Không tìm thấy phiên",404)
    try:d=json.loads(r["detail_json"] or "{}")
    except Exception:d={}
    return jsonify({"session_id":sid,"prediction":r["prediction"],"actual":r["actual"],"result":r["result"],"confidence":r["confidence"],"detail":d,"explanation":d.get("explanation","")})

@app.get("/resolutions")
def api_resolutions():
    table,keyrow,error=_analytics_access()
    if error:return error
    try:limit=max(1,min(500,int(request.args.get("limit",50))))
    except ValueError:limit=50
    c=db();rows=c.execute("SELECT * FROM prediction_resolutions WHERE table_code=? ORDER BY session_id DESC LIMIT ?",(table,limit)).fetchall();c.close();items=[]
    for r in rows:
        d=dict(r)
        try:d["module_votes"]=json.loads(d.pop("module_votes_json") or "{}")
        except Exception:d["module_votes"]={}
        items.append(d)
    return jsonify({"ok":True,"table":table,"count":len(items),"items":items})

@app.get("/health")
def api_health():
    c=db();tables=c.execute("SELECT t.code,s.last_poll_at,s.last_poll_error FROM tables_ t LEFT JOIN table_states s ON s.table_code=t.code").fetchall();pred=c.execute("SELECT COUNT(*) FROM predictions").fetchone()[0];res=c.execute("SELECT COUNT(*) FROM prediction_resolutions").fetchone()[0];c.close();path=os.environ.get("DATABASE_PATH","/tmp/lc79.db");size=os.path.getsize(path)/1048576 if os.path.exists(path) else 0
    return jsonify({"ok":True,"uptime_seconds":int(time.time()-APP_STARTED),"db_size_mb":round(size,3),"tables":[dict(x) for x in tables],"predictions":pred,"resolutions":res,"worker_ok":bool(tables) and all(not x["last_poll_error"] for x in tables)})
@app.get("/version")
def api_version():return jsonify({"version":APP_VERSION,"build_date":BUILD_DATE,"engine_version":ENGINE_VERSION})

# Admin pages for the expanded navigation. All are protected by admin_required.
def _admin_simple(title,active,content):return render_admin(title,active,content)
@app.get("/admin/hu")
@admin_required
def admin_hu():return _admin_table("lc79_tx","Bàn Hũ")
@app.get("/admin/md5")
@admin_required
def admin_md5():return _admin_table("lc79_md5","Bàn MD5")

_ADMIN_POLL_LOCKS = {"lc79_tx": threading.Lock(), "lc79_md5": threading.Lock()}
_WORKER_MODULE = None

def _load_worker_module():
    global _WORKER_MODULE
    if _WORKER_MODULE is not None:
        return _WORKER_MODULE
    worker_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker-4.py")
    spec = importlib.util.spec_from_file_location("lc79_runtime_worker", worker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Không tìm thấy worker-4.py cạnh app-19-2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _WORKER_MODULE = module
    return module

def _admin_table(code, title):
    c=db()
    state=c.execute("SELECT * FROM table_states WHERE table_code=?",(code,)).fetchone()
    table=c.execute("SELECT * FROM tables_ WHERE code=?",(code,)).fetchone()
    total=c.execute("SELECT COUNT(*) FROM predictions WHERE table_code=?",(code,)).fetchone()[0]
    wins=c.execute("SELECT COUNT(*) FROM predictions WHERE table_code=? AND result='win'",(code,)).fetchone()[0]
    losses=c.execute("SELECT COUNT(*) FROM predictions WHERE table_code=? AND result='lose'",(code,)).fetchone()[0]
    pending=total-wins-losses
    recent=c.execute("SELECT * FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT 100",(code,)).fetchall()
    chronological=list(reversed(recent))
    daily=c.execute("SELECT date(created_at) d,COUNT(*) n,SUM(result='win') w FROM predictions WHERE table_code=? AND result IS NOT NULL AND created_at>=datetime('now','-30 days') GROUP BY date(created_at) ORDER BY d",(code,)).fetchall()
    sides=c.execute("SELECT prediction side,COUNT(*) n FROM predictions WHERE table_code=? GROUP BY prediction",(code,)).fetchall()
    c.close()
    acc100,acc500,acc1000=(accuracy(code,n)*100 for n in (100,500,1000))
    try: pred=load_engine(code).predict_detail()
    except Exception: pred={}
    regime=pred.get('regime','WARMUP'); regime_conf=float(pred.get('regime_conf',0) or 0)
    modules=pred.get('modules',{}); weights=pred.get('weights',{})
    last_id=int(state['last_seen_id'] or 0) if state else 0
    poll_error=(state['last_poll_error'] or '') if state else 'Chưa có trạng thái worker'
    poll_at=state['last_poll_at'] if state else None
    health='red' if poll_error else ('green' if poll_at else 'yellow')
    roll_labels=[]; roll_values=[]
    for i in range(len(chronological)):
        win=[x for x in chronological[max(0,i-19):i+1] if x['result'] in ('win','lose')]
        if win:
            roll_labels.append(str(chronological[i]['session_id']))
            roll_values.append(round(sum(x['result']=='win' for x in win)/len(win)*100,2))
    daily_labels=[str(x['d']) for x in daily]
    daily_values=[round((x['w'] or 0)/x['n']*100,2) if x['n'] else 0 for x in daily]
    side_map={x['side']:x['n'] for x in sides}
    side_tai=int(side_map.get('TAI',0)); side_xiu=int(side_map.get('XIU',0))
    from markupsafe import escape
    trs=[]
    for r in recent:
        status='Chờ' if not r['result'] else ('Thắng' if r['result']=='win' else 'Thua')
        kind='neutral' if not r['result'] else ('success' if r['result']=='win' else 'danger')
        conf=max(0,min(100,int(r['confidence'] or 0)))
        side_class='side-tai' if r['prediction']=='TAI' else 'side-xiu' if r['prediction']=='XIU' else ''
        actual_class='side-tai' if r['actual']=='TAI' else 'side-xiu' if r['actual']=='XIU' else ''
        result_class='result-win' if r['result']=='win' else 'result-lose' if r['result']=='lose' else ''
        trs.append(f'''<tr data-status="{status}"><td class="mono">#{int(r['session_id'])}</td><td class="{side_class}"><b>{'TÀI' if r['prediction']=='TAI' else 'XỈU' if r['prediction']=='XIU' else escape(r['prediction'])}</b></td><td class="{actual_class}">{'TÀI' if r['actual']=='TAI' else 'XỈU' if r['actual']=='XIU' else escape(r['actual'] or '—')}</td><td class="{result_class}">{badge(status,kind)}</td><td><div class="progress compact"><span style="width:{conf}%"></span></div><small>{conf}%</small></td><td>{escape(fmt_date(r['created_at']))}</td><td><button class="btn btn-quiet btn-sm" onclick="showSessionDetail({int(r['session_id'])})">Chi tiết</button></td></tr>''')
    table_rows=''.join(trs) or '<tr><td colspan="7" class="empty">Chưa có dữ liệu dự đoán.</td></tr>'
    module_rows=[]
    for name in PredictionEngine.EXPERTS:
        item=modules.get(name,{})
        prob=float(item.get('p',.5) or .5); weight=float(weights.get(name,item.get('weight',0)) or 0)
        pct=max(0,min(100,prob*100))
        module_rows.append(f'''<div class="module-row"><div class="module-label"><b>{escape(name.replace('_',' ').title())}</b><span>{pct:.1f}% · w {weight:.3f}</span></div><div class="progress"><span style="width:{pct:.1f}%"></span></div></div>''')
    err_html=f'<div class="alert error">{escape(poll_error)}</div>' if poll_error else ''
    active_badge=badge('Đang chạy' if table and table['is_active'] else 'Tạm dừng','success' if table and table['is_active'] else 'warning')
    board_data=json.dumps({'code':code,'roll_labels':roll_labels,'roll_values':roll_values,'daily_labels':daily_labels,'daily_values':daily_values,'side_tai':side_tai,'side_xiu':side_xiu},ensure_ascii=False)
    body=f'''<div class="page-head"><div><div class="page-title">{title}</div><div class="page-sub"><span class="health {health}"></span> {code} · phiên mới nhất <b>{last_id:,}</b> · poll gần nhất {escape(fmt_date(poll_at) if poll_at else 'Chưa có')}</div></div><div class="actions">{active_badge}<form method="post" action="/admin/{code}/action"><input type="hidden" name="action" value="poll"><button class="btn btn-secondary">↻ Force poll</button></form><form method="post" action="/admin/{code}/action" onsubmit="return confirm('Reset bộ nhớ thích nghi của module cho bàn này?')"><input type="hidden" name="action" value="reset"><button class="btn btn-danger">Reset engine</button></form><a class="btn btn-secondary" href="/admin/{code}/export.csv">↓ CSV</a><button id="runBacktest" class="btn btn-primary" type="button">▶ Backtest</button><button class="btn btn-secondary" type="button" onclick="location.reload()">↻ Làm mới</button><a class="btn btn-secondary" href="/admin/settings">⚙ Cấu hình</a></div></div>
{err_html}
<div class="grid stats six"><div class="card"><div class="stat-label">Accuracy · 100</div><div class="stat-value">{acc100:.1f}%</div><div class="stat-note">Kết quả gần nhất</div></div><div class="card"><div class="stat-label">Accuracy · 500</div><div class="stat-value">{acc500:.1f}%</div><div class="stat-note">Cửa sổ trung hạn</div></div><div class="card"><div class="stat-label">Accuracy · 1000</div><div class="stat-value">{acc1000:.1f}%</div><div class="stat-note">Cửa sổ dài hạn</div></div><div class="card"><div class="stat-label">Tổng dự đoán</div><div class="stat-value">{total:,}</div><div class="stat-note">Tất cả phiên đã ghi</div></div><div class="card"><div class="stat-label">Thắng / Thua</div><div class="stat-value">{wins:,} / {losses:,}</div><div class="stat-note">Đã phân định {wins+losses:,}</div></div><div class="card"><div class="stat-label">Đang chờ</div><div class="stat-value">{pending:,}</div><div class="stat-note">Regime {escape(regime)} · {regime_conf*100:.0f}%</div></div></div>
<div class="grid two"><div class="card"><div class="card-head"><div><div class="card-title">Accuracy rolling · 20 phiên</div><div class="card-sub">Tỷ lệ thắng trượt trên dữ liệu đã phân định</div></div></div><div class="chart-box"><canvas id="accuracyChart"></canvas></div></div><div class="card"><div class="card-head"><div><div class="card-title">Phân bổ dự đoán</div><div class="card-sub">Tổng lượt dự đoán theo cửa</div></div></div><div class="chart-box"><canvas id="sideChart"></canvas></div><div class="split small muted"><span>TAI: {side_tai:,}</span><span>XỈU: {side_xiu:,}</span></div></div></div>
<div class="grid two" style="margin-top:18px"><div class="card"><div class="card-head"><div><div class="card-title">Hiệu suất theo ngày</div><div class="card-sub">Accuracy phiên phân định trong 30 ngày</div></div></div><div class="chart-box"><canvas id="dailyChart"></canvas></div></div><div class="card"><div class="card-head"><div><div class="card-title">Tám module dự đoán</div><div class="card-sub">Xác suất TÀI và trọng số hợp nhất</div></div><span class="badge neutral">{escape(regime)}</span></div><div class="module-list">{''.join(module_rows)}</div></div></div>
<div class="card" style="margin-top:18px"><div class="card-head"><div><div class="card-title">Lịch sử dự đoán</div><div class="card-sub">100 phiên mới nhất · lọc, tìm kiếm, phân trang, chi tiết</div></div><div class="actions"><span class="small muted" id="rowCount">{len(recent)} dòng</span><select class="select" id="pageSize" style="width:100px" onchange="renderPredictionRows()"><option>10</option><option selected>20</option><option>50</option><option>100</option></select></div></div><div class="toolbar"><div class="searchbox"><input id="predictionSearch" class="input" placeholder="Tìm phiên, dự đoán, kết quả…" oninput="renderPredictionRows()"></div><select class="select" id="predictionStatus" style="max-width:170px" onchange="renderPredictionRows()"><option value="">Tất cả trạng thái</option><option>Thắng</option><option>Thua</option><option>Chờ</option></select><button class="btn btn-secondary" onclick="resetPredictionFilters()">Xóa lọc</button></div><div class="table-wrap"><table class="data-table" id="predictionTable"><thead><tr><th>Phiên</th><th>Dự đoán</th><th>Thực tế</th><th>Trạng thái</th><th>Tin cậy</th><th>Thời gian</th><th></th></tr></thead><tbody>{table_rows}</tbody></table></div><div class="pagination"><button class="btn btn-secondary btn-sm" id="prevPage" onclick="changePredictionPage(-1)">← Trước</button><span id="pageInfo" class="small muted">Trang 1</span><button class="btn btn-secondary btn-sm" id="nextPage" onclick="changePredictionPage(1)">Sau →</button></div></div>
<div class="card" style="margin-top:18px"><div class="card-head"><div><div class="card-title">Thông báo tới tool</div><div class="card-sub">Broadcast hiển thị cho client khi gọi API dự đoán</div></div></div><form method="post" action="/admin/{code}/action" class="broadcast-form"><input type="hidden" name="action" value="broadcast"><input class="input" name="message" maxlength="300" placeholder="Nhập thông báo tối đa 300 ký tự"><button class="btn btn-primary">Phát thông báo</button><button class="btn btn-secondary" name="clear" value="1">Tắt thông báo</button></form></div>
<div class="modal-backdrop" id="sessionModal" onclick="if(event.target===this)closeModal('sessionModal')"><div class="modal modal-wide"><div class="split"><div class="modal-title" id="sessionTitle">Chi tiết phiên</div><button class="btn btn-quiet" onclick="closeModal('sessionModal')">✕</button></div><div id="sessionBody" class="modal-body">Đang tải…</div></div></div><div class="modal-backdrop" id="backtestModal" onclick="if(event.target===this)closeModal('backtestModal')"><div class="modal modal-wide"><div class="split"><div class="modal-title">Backtest · {title}</div><button class="btn btn-quiet" onclick="closeModal('backtestModal')">✕</button></div><div id="backtestBody" class="modal-body">Đang chạy backtest…</div></div></div>
<script>
const BOARD={board_data};let predictionPage=1;
function renderPredictionRows(){{const tb=document.querySelector('#predictionTable tbody'),all=[...tb.querySelectorAll('tr')],q=(document.getElementById('predictionSearch').value||'').toLowerCase(),st=document.getElementById('predictionStatus').value,size=Number(document.getElementById('pageSize').value)||20,filtered=all.filter(r=>(!q||r.innerText.toLowerCase().includes(q))&&(!st||r.dataset.status===st)),pages=Math.max(1,Math.ceil(filtered.length/size));predictionPage=Math.min(predictionPage,pages);all.forEach(r=>r.style.display='none');filtered.slice((predictionPage-1)*size,predictionPage*size).forEach(r=>r.style.display='');document.getElementById('rowCount').textContent=filtered.length+' dòng';document.getElementById('pageInfo').textContent='Trang '+predictionPage+' / '+pages;document.getElementById('prevPage').disabled=predictionPage<=1;document.getElementById('nextPage').disabled=predictionPage>=pages;}}
function changePredictionPage(n){{predictionPage=Math.max(1,predictionPage+n);renderPredictionRows()}}function resetPredictionFilters(){{document.getElementById('predictionSearch').value='';document.getElementById('predictionStatus').value='';predictionPage=1;renderPredictionRows()}}
function escapeHtml(v){{return String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}
async function showSessionDetail(sid){{openModal('sessionModal');document.getElementById('sessionTitle').textContent='Phiên #'+sid;const el=document.getElementById('sessionBody');el.textContent='Đang tải…';try{{const r=await fetch('/admin/'+BOARD.code+'/detail/'+sid),d=await r.json();if(!r.ok)throw Error(d.message||'Không tải được');const detail=d.detail||{{}},mods=detail.modules||{{}},rows=Object.entries(mods).map(([k,v])=>'<div class="detail-line"><b>'+escapeHtml(k)+'</b><span>p='+(Number(v.p||.5)*100).toFixed(1)+'% · w='+Number(v.weight||0).toFixed(3)+'</span></div>').join('');el.innerHTML='<div class="kv"><div class="kv-item"><div class="kv-label">Dự đoán</div><div class="kv-value">'+escapeHtml(d.prediction)+'</div></div><div class="kv-item"><div class="kv-label">Thực tế</div><div class="kv-value">'+escapeHtml(d.actual||'Chưa có')+'</div></div><div class="kv-item"><div class="kv-label">Tin cậy</div><div class="kv-value">'+escapeHtml(d.confidence)+'%</div></div><div class="kv-item"><div class="kv-label">Regime</div><div class="kv-value">'+escapeHtml(detail.regime||'WARMUP')+'</div></div></div><h4>Chi tiết 8 module</h4>'+rows+'<p>'+escapeHtml(detail.explanation||d.explanation||'')+'</p>'}}catch(e){{el.textContent=e.message}}}}
async function showBacktest(){{openModal('backtestModal');const el=document.getElementById('backtestBody');el.textContent='Đang chạy backtest…';try{{const r=await fetch('/admin/'+BOARD.code+'/backtest'),d=await r.json();if(!r.ok)throw Error(d.message||'Backtest lỗi');const bm=d.by_module||{{}};el.innerHTML='<div class="kv"><div class="kv-item"><div class="kv-label">Accuracy</div><div class="kv-value">'+(Number(d.accuracy||0)*100).toFixed(2)+'%</div></div><div class="kv-item"><div class="kv-label">Số mẫu</div><div class="kv-value">'+(d.total_predictions||d.total||0)+'</div></div><div class="kv-item"><div class="kv-label">Thắng</div><div class="kv-value">'+(d.correct||d.wins||0)+'</div></div><div class="kv-item"><div class="kv-label">Thua</div><div class="kv-value">'+Math.max(0,(d.total_predictions||d.total||0)-(d.correct||d.wins||0))+'</div></div></div><h4>Hiệu suất từng module</h4>'+Object.entries(bm).map(([k,v])=>'<div class="detail-line"><b>'+escapeHtml(k)+'</b><span>'+(Number(v.accuracy||0)*100).toFixed(1)+'% · '+(v.votes||v.total||v.n||0)+' mẫu</span></div>').join('')}}catch(e){{el.textContent=e.message}}}}
document.getElementById('runBacktest').addEventListener('click',showBacktest);renderPredictionRows();
if(window.Chart){{const base={{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#a9b8d0'}}}}}},scales:{{x:{{ticks:{{color:'#8294b2'}},grid:{{color:'rgba(255,255,255,.06)'}}}},y:{{ticks:{{color:'#8294b2'}},grid:{{color:'rgba(255,255,255,.06)'}},min:0,max:100}}}}}};new Chart(document.getElementById('accuracyChart'),{{type:'line',data:{{labels:BOARD.roll_labels,datasets:[{{label:'Accuracy %',data:BOARD.roll_values,borderColor:'#63e7ff',backgroundColor:'rgba(99,231,255,.12)',fill:true,tension:.35,pointRadius:0}}]}},options:base}});new Chart(document.getElementById('dailyChart'),{{type:'bar',data:{{labels:BOARD.daily_labels,datasets:[{{label:'Accuracy %',data:BOARD.daily_values,backgroundColor:'rgba(120,139,255,.75)',borderRadius:5}}]}},options:base}});new Chart(document.getElementById('sideChart'),{{type:'doughnut',data:{{labels:['TÀI','XỈU'],datasets:[{{data:[BOARD.side_tai,BOARD.side_xiu],backgroundColor:['#63e7ff','#9b8cff'],borderColor:'#0b1423',borderWidth:3}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'bottom',labels:{{color:'#a9b8d0'}}}}}}}}}})}}
</script>'''
    return render_admin(title,active='hu' if code=='lc79_tx' else 'md5',body=body)

@app.post("/admin/<table_code>/action")
@admin_required
def admin_table_action(table_code):
    if table_code not in TABLES:return redirect('/admin')
    action=request.form.get('action','')
    if action=='reset':
        set_worker_control('force_restart:'+table_code,'1')
        admin_log('Reset engine thích nghi',table_code)
    elif action=='poll':
        lock=_ADMIN_POLL_LOCKS[table_code]
        if lock.acquire(blocking=False):
            try:
                c=db();row=c.execute('SELECT * FROM tables_ WHERE code=?',(table_code,)).fetchone();c.close()
                if not row:raise RuntimeError('Không tìm thấy bàn')
                _load_worker_module().process_table(dict(row))
                admin_log('Force poll',table_code)
            except Exception as exc:admin_log('Force poll lỗi',table_code,{'error':str(exc)[:300]})
            finally:lock.release()
        else:admin_log('Force poll bị bỏ qua',table_code,{'reason':'poll đang chạy'})
    elif action=='broadcast':
        c=db()
        if request.form.get('clear'):
            c.execute('UPDATE broadcasts SET active=0 WHERE active=1');admin_log('Tắt broadcast',table_code)
        else:
            message=request.form.get('message','').strip()[:300]
            if message:
                c.execute('UPDATE broadcasts SET active=0 WHERE active=1');c.execute('INSERT INTO broadcasts(message,active) VALUES(?,1)',(message,));admin_log('Phát broadcast',table_code,{'message':message})
        c.commit();c.close()
    return redirect('/admin/hu' if table_code=='lc79_tx' else '/admin/md5')

@app.get('/admin/<table_code>/detail/<int:session_id>')
@admin_required
def admin_table_detail(table_code,session_id):
    if table_code not in TABLES:return api_error('invalid_table','Mã bàn không hợp lệ',404)
    c=db();r=c.execute('SELECT * FROM predictions WHERE table_code=? AND session_id=?',(table_code,session_id)).fetchone();c.close()
    if not r:return api_error('not_found','Không tìm thấy phiên',404)
    try:detail=json.loads(r['detail_json'] or '{}')
    except Exception:detail={}
    return jsonify({'session_id':session_id,'prediction':r['prediction'],'actual':r['actual'],'result':r['result'],'confidence':r['confidence'],'detail':detail,'explanation':detail.get('explanation','')})

@app.get('/admin/<table_code>/backtest')
@admin_required
def admin_table_backtest(table_code):
    if table_code not in TABLES:return api_error('invalid_table','Mã bàn không hợp lệ',404)
    c=db();rows=c.execute('SELECT actual FROM predictions WHERE table_code=? AND actual IS NOT NULL ORDER BY session_id DESC LIMIT 1000',(table_code,)).fetchall();c.close()
    return jsonify(Backtest.run([1 if r['actual']=='TAI' else 0 for r in reversed(rows)]))

@app.get('/admin/<table_code>/export.csv')
@admin_required
def admin_table_export(table_code):
    if table_code not in TABLES:return api_error('invalid_table','Mã bàn không hợp lệ',404)
    c=db();rows=c.execute('SELECT session_id,prediction,actual,result,confidence,created_at,resolved_at FROM predictions WHERE table_code=? ORDER BY session_id DESC',(table_code,)).fetchall();c.close()
    buf=io.StringIO();writer=csv.writer(buf);writer.writerow(['session_id','prediction','actual','result','confidence','created_at','resolved_at']);writer.writerows([tuple(r) for r in rows])
    response=make_response('\ufeff'+buf.getvalue());response.headers['Content-Type']='text/csv; charset=utf-8';response.headers['Content-Disposition']=f'attachment; filename="{table_code}-predictions.csv"';return response

# === END app.py ===
