# -*- coding: utf-8 -*-
"""LC79 API JSON và bảng điều khiển quản trị. Giao diện quản trị inline duy nhất tại đây."""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
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
        conn.execute("INSERT INTO api_keys(key,scope,note,expires_at,days,max_devices,activated) VALUES(?,?,?,?,?,?,0)",
                     (newkey,c["scope"],"Kích hoạt từ mã "+code,expiry,float(c["days"]),1))
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
# Inline admin design system and page shell.
# -----------------------------------------------------------------------------
CSS = r'''<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
:root{--bg:#f5f7fb;--surface:#fff;--surface-2:#f8fafc;--surface-3:#eef2f7;--bd:#e4e9f1;--bd-hi:#cfd8e5;--text:#172033;--text-1:#526078;--text-2:#8490a3;--blue:#2563eb;--blue-2:#1d4ed8;--green:#16a34a;--red:#dc2626;--yellow:#d97706;--r:14px;--r-sm:10px;--r-xs:7px}
*{box-sizing:border-box}html{background:var(--bg);color-scheme:light}body{margin:0;background:var(--bg);color:var(--text);font:13px Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;line-height:1.55}a{color:inherit;text-decoration:none}button,input,select,textarea{font:inherit}button{cursor:pointer}svg{vertical-align:middle}
.shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:248px;background:#fff;border-right:1px solid var(--bd);padding:24px 16px;z-index:20;box-shadow:2px 0 14px rgba(20,35,65,.025)}
.brand{display:flex;align-items:center;gap:12px;padding:0 8px 28px}.brand-mark{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(145deg,#2563eb,#60a5fa);color:#fff;font-weight:850;letter-spacing:-1px;box-shadow:0 5px 14px rgba(37,99,235,.22)}.brand-name{font-size:14px;font-weight:800;letter-spacing:.08em;color:#18243a}.brand-sub{font-size:10px;color:#91a0b5;letter-spacing:.12em}
.nav-label{font-size:10px;color:#9aa6b8;letter-spacing:.12em;text-transform:uppercase;padding:14px 12px 8px}.nav-item{height:42px;padding:0 12px;border-radius:9px;display:flex;align-items:center;gap:11px;color:#66748a;margin:3px 0;position:relative;transition:color .18s,background .18s,transform .18s}.nav-item:hover{background:#f4f7fc;color:#1f3b68;transform:translateX(2px)}.nav-item.active{background:#edf4ff;color:#1d4ed8;font-weight:650}.nav-item.active:before{content:"";position:absolute;left:0;top:9px;bottom:9px;width:3px;background:var(--blue);border-radius:3px}.sidebar-foot{position:absolute;bottom:20px;left:16px;right:16px;border-top:1px solid var(--bd);padding:16px 8px;color:#9aa6b8;font-size:11px}
.main{margin-left:248px;min-height:100vh}.topbar{height:62px;position:sticky;top:0;z-index:15;background:rgba(255,255,255,.9);backdrop-filter:blur(14px);border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;padding:0 32px}.crumb{color:#8995a8;font-size:12px}.top-user{display:flex;align-items:center;gap:10px;color:var(--text-1)}.avatar{width:30px;height:30px;border-radius:50%;background:#eaf1ff;border:1px solid #d7e5ff;display:grid;place-items:center;color:#2563eb;font-size:10px;font-weight:800}.content{max-width:1360px;padding:30px 32px;margin:0 auto}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:24px}.page-title{font-size:23px;line-height:1.25;font-weight:800;letter-spacing:-.04em;color:#172033}.page-sub{margin-top:6px;color:#8490a3;font-size:13px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.grid{display:grid;gap:16px}.stats{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:20px}.two{grid-template-columns:repeat(2,minmax(0,1fr))}.three{grid-template-columns:repeat(3,minmax(0,1fr))}.six{grid-template-columns:repeat(6,minmax(0,1fr))}
.card{background:var(--surface);border:1px solid var(--bd);border-radius:var(--r);padding:20px;box-shadow:0 2px 8px rgba(31,48,80,.035),0 8px 22px rgba(31,48,80,.025);min-width:0;transition:border-color .18s,transform .18s,box-shadow .18s}.card:hover{border-color:#d4deec;box-shadow:0 5px 18px rgba(31,48,80,.06);transform:translateY(-1px)}
.stat-label{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#8b97a9;font-weight:700}.stat-value{font-size:29px;line-height:1.2;font-weight:800;letter-spacing:-.045em;margin-top:8px;font-variant-numeric:tabular-nums;color:#172033}.stat-note{font-size:12px;color:#97a2b2;margin-top:8px}.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}.card-title{font-size:14px;font-weight:750;color:#23314a}.card-sub{font-size:11px;color:#8b97a9;margin-top:3px}
.health{width:8px;height:8px;display:inline-block;border-radius:50%;background:#aab4c3}.health.green{background:var(--green);box-shadow:0 0 0 4px rgba(22,163,74,.09);animation:pulse 2s infinite}.health.yellow{background:var(--yellow);box-shadow:0 0 0 4px rgba(217,119,6,.09)}.health.red{background:var(--red);box-shadow:0 0 0 4px rgba(220,38,38,.09);animation:pulse 1s infinite}@keyframes pulse{50%{box-shadow:0 0 0 7px rgba(255,255,255,0)}}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:8px 15px;border-radius:9px;font-size:12px;font-weight:700;border:1px solid transparent;transition:background .18s,border-color .18s,transform .18s,box-shadow .18s}.btn-primary{background:var(--blue);color:#fff;box-shadow:0 3px 8px rgba(37,99,235,.18)}.btn-primary:hover{background:var(--blue-2);transform:translateY(-1px);box-shadow:0 6px 14px rgba(37,99,235,.2)}.btn-primary:active{transform:translateY(0)}.btn-secondary{background:#fff;border-color:#dce3ed;color:#526078}.btn-secondary:hover{background:#f7f9fc;border-color:#cbd6e5;color:#243651}.btn-danger{background:#fff5f5;border-color:#fee2e2;color:#dc2626}.btn-danger:hover{background:#feecec}.btn-quiet{background:transparent;color:#718096;padding:7px 10px}.btn-quiet:hover{background:#f1f5fa;color:#334155}.btn-sm{padding:6px 10px;font-size:11px}
.field{display:flex;flex-direction:column;gap:7px}.field label,.field-label{font-size:10px;color:#7f8ba0;letter-spacing:.07em;text-transform:uppercase;font-weight:750}.input,.select,.textarea{width:100%;background:#fff;border:1px solid #dce3ed;border-radius:8px;color:#1f2937;padding:10px 12px;outline:none;transition:border-color .15s,box-shadow .15s}.input:focus,.select:focus,.textarea:focus{border-color:#80aaf8;box-shadow:0 0 0 3px rgba(37,99,235,.1)}.textarea{min-height:120px;resize:vertical}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}.searchbox{position:relative;flex:1;min-width:220px;max-width:360px}.searchbox .input{padding-left:36px}.searchbox svg{position:absolute;left:12px;top:10px;color:#9aa6b8}
.table-wrap{overflow:auto;border:1px solid var(--bd);border-radius:10px;background:#fff}.data-table{width:100%;border-collapse:separate;border-spacing:0;white-space:nowrap}.data-table thead{background:#f8fafd;position:sticky;top:0;z-index:2}.data-table th{padding:12px 16px;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#8b97a9;text-align:left;border-bottom:1px solid var(--bd);font-weight:800}.data-table td{padding:13px 16px;font-size:12px;color:#5b687d;border-bottom:1px solid #eef1f6}.data-table tbody tr:hover td{background:#fafcff}.data-table tbody tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.01em;color:#26354d}
.badge{display:inline-flex;align-items:center;padding:4px 8px;border-radius:6px;font-size:10px;font-weight:800;letter-spacing:.025em;border:1px solid}.badge.success{background:#ecfdf3;color:#15803d;border-color:#c8f0d5}.badge.danger{background:#fff1f2;color:#be123c;border-color:#ffd4dc}.badge.warning{background:#fffbeb;color:#b45309;border-color:#fde7b0}.badge.neutral{background:#f1f5f9;color:#64748b;border-color:#e2e8f0}
.progress{height:7px;background:#edf1f6;border-radius:10px;overflow:hidden}.progress>span{height:100%;display:block;background:linear-gradient(90deg,#60a5fa,#2563eb);border-radius:10px;transition:width .4s}.progress-row{display:flex;align-items:center;gap:12px}.progress-row .progress{flex:1}.muted{color:#8b97a9}.small{font-size:11px}.empty{padding:32px;text-align:center;color:#9aa6b8}.split{display:flex;align-items:center;justify-content:space-between;gap:16px}.kv{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.kv-item{padding:13px;background:#f8fafd;border:1px solid #edf1f6;border-radius:9px}.kv-label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#8b97a9;font-weight:700}.kv-value{font-size:14px;font-weight:750;margin-top:6px;overflow-wrap:anywhere;color:#26354d}
.timeline{position:relative;padding-left:24px}.timeline:before{content:"";position:absolute;left:7px;top:8px;bottom:8px;width:1px;background:#dfe6ef}.timeline-item{position:relative;padding:0 0 20px 12px}.timeline-item:before{content:"";position:absolute;left:-20px;top:5px;width:8px;height:8px;border-radius:50%;background:#7da7ef;border:2px solid #fff;box-shadow:0 0 0 1px #cbdaf2}.timeline-title{font-size:12px;color:#334155}.timeline-meta{font-size:11px;color:#94a0b1;margin-top:3px}
.chart{width:100%;height:auto;display:block;overflow:visible}.alert{padding:12px 14px;border:1px solid #fde7b0;background:#fffbeb;color:#a16207;border-radius:9px;margin-bottom:18px}.alert.error{border-color:#fecdd3;background:#fff1f2;color:#be123c}
.modal-backdrop{position:fixed;inset:0;z-index:1000;background:rgba(15,23,42,.42);backdrop-filter:blur(5px);display:none;align-items:center;justify-content:center;padding:20px}.modal-backdrop.open{display:flex}.modal{width:100%;max-width:500px;background:#fff;border:1px solid #e5eaf1;border-radius:17px;padding:24px;box-shadow:0 24px 80px rgba(15,23,42,.2);animation:modalIn .2s ease both}.modal-title{font-size:18px;font-weight:800;color:#1e293b}.modal-body{font-size:13px;color:#748197;margin:10px 0 20px}.modal-footer{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap}
.toast-stack{position:fixed;top:20px;right:20px;z-index:9999;display:grid;gap:8px}.toast{background:#fff;border:1px solid #dce5ef;border-left:3px solid var(--green);padding:12px 16px;border-radius:9px;box-shadow:0 8px 25px rgba(15,23,42,.12);min-width:240px;animation:toastIn .2s ease;color:#334155}.toast.error{border-left-color:var(--red)}@keyframes toastIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:translateX(0)}}@keyframes modalIn{from{opacity:0;transform:scale(.97)}to{opacity:1;transform:scale(1)}}
.login-page{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top left,#e8f0ff 0,transparent 42%),var(--bg)}.login-card{width:100%;max-width:410px;background:#fff;border:1px solid var(--bd);border-radius:18px;padding:32px;box-shadow:0 18px 55px rgba(31,48,80,.09)}.login-brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.login-card h1{font-size:22px;margin:0 0 6px;letter-spacing:-.03em;color:#1e293b}.login-card p{color:#8793a5;margin:0 0 24px}.login-card .field{margin:16px 0}.login-card .btn{width:100%;margin-top:8px}.expert{display:grid;grid-template-columns:90px 1fr 42px;gap:12px;align-items:center;margin:12px 0}.expert-name{font-size:11px;color:#64748b}.expert-val{text-align:right;font-size:11px;color:#8b97a9;font-variant-numeric:tabular-nums}.mobile-menu{display:none}
@media(max-width:1050px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.six{grid-template-columns:repeat(3,minmax(0,1fr))}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.sidebar{width:68px;padding:18px 10px}.brand{padding:0 6px 24px}.brand-name,.brand-sub,.nav-label,.nav-item span,.sidebar-foot{display:none}.nav-item{justify-content:center;padding:0}.main{margin-left:68px}.topbar{padding:0 16px}.content{padding:22px 16px}.two,.three{grid-template-columns:1fr}.page-head{flex-direction:column}.six{grid-template-columns:repeat(2,minmax(0,1fr))}.stats{gap:10px}.card{padding:16px}.stat-value{font-size:24px}}
@media(max-width:420px){.stats,.six,.kv{grid-template-columns:1fr 1fr}.toolbar .searchbox{max-width:none;flex-basis:100%}.topbar{height:56px}.content{padding:18px 12px}.modal{padding:19px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}
</style>'''

BASE = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · LC79</title>''' + CSS + r'''</head><body><div class="shell"><aside class="sidebar"><a class="brand" href="/admin"><div class="brand-mark">P</div><div><div class="brand-name">P A W</div><div class="brand-sub">LC79 CONTROL</div></div></a><div class="nav-label">Tổng quan</div><a class="nav-item {{'active' if active=='dashboard' else ''}}" href="/admin">''' + svg_icon("grid") + r'''<span>Bảng điều khiển</span></a><a class="nav-item {{'active' if active=='monitor' else ''}}" href="/admin/monitor">''' + svg_icon("monitor") + r'''<span>Giám sát bàn</span></a><div class="nav-label">Bàn chơi</div><a class="nav-item" href="/admin/hu"><span>Bàn Hũ</span></a><a class="nav-item" href="/admin/md5"><span>Bàn MD5</span></a><a class="nav-item" href="/admin/modules"><span>Modules</span></a><a class="nav-item" href="/admin/backtest"><span>Backtest</span></a><a class="nav-item" href="/admin/predictions"><span>Dự đoán</span></a><a class="nav-item" href="/admin/resolutions"><span>Phân định</span></a><div class="nav-label">Quản lý</div><a class="nav-item {{'active' if active=='keys' else ''}}" href="/admin/keys">''' + svg_icon("key") + r'''<span>Quản lý key</span></a><a class="nav-item {{'active' if active=='codes' else ''}}" href="/admin/codes">''' + svg_icon("ticket") + r'''<span>Mã kích hoạt</span></a><div class="nav-label">Hệ thống</div><a class="nav-item" href="/admin/health"><span>Sức khỏe</span></a><a class="nav-item" href="/admin/settings"><span>Cài đặt</span></a><a class="nav-item {{'active' if active=='logs' else ''}}" href="/admin/logs">''' + svg_icon("logs") + r'''<span>Nhật ký quản trị</span></a><div class="sidebar-foot">PAW · Hệ thống LC79<br>Phiên quản trị bảo mật</div></aside><main class="main"><header class="topbar"><div class="crumb">Không gian quản trị <span class="muted">/</span> {{ title }}</div><div class="top-user"><span class="health green"></span><span>{{ admin_user }}</span><a class="btn btn-quiet btn-sm" href="/admin/logout">Đăng xuất</a></div></header><section class="content">{{ body|safe }}</section></main></div><div class="toast-stack" id="toasts"></div><script>
function toast(message,type='success'){const el=document.createElement('div');el.className='toast '+(type==='error'?'error':'');el.textContent=message;document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),type==='error'?5000:3000)}
function copyText(value){navigator.clipboard.writeText(value).then(()=>toast('Đã sao chép')).catch(()=>toast('Không thể sao chép','error'))}
function openModal(id){document.getElementById(id)?.classList.add('open')}
function closeModal(id){document.getElementById(id)?.classList.remove('open')}
function confirmAction(message){return window.confirm(message)}
function filterRows(inputId,tableId){const q=document.getElementById(inputId).value.toLowerCase();document.querySelectorAll('#'+tableId+' tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}
</script></body></html>'''

def render_admin(title,active,body):
    return render_template_string(BASE,title=title,active=active,body=body,admin_user=session.get("admin_user","Quản trị"))

@app.route("/admin/login",methods=["GET","POST"])
def admin_login():
    if request.method=="POST":
        user=request.form.get("username",""); password=request.form.get("password","")
        if user==os.environ.get("ADMIN_USER","admin") and password==os.environ.get("ADMIN_PASS","") and os.environ.get("ADMIN_PASS"):
            session.clear(); session["admin_user"]=user; session["admin_until"]=time.time()+8*3600; session.permanent=True
            return redirect(url_for("admin_dashboard"))
        return render_template_string(r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">''' + CSS + r'''</head><body><div class="login-page"><form class="login-card" method="post"><div class="login-brand"><div class="brand-mark">P</div><div><b>P A W</b><div class="small muted">LC79 CONTROL</div></div></div><h1>Đăng nhập quản trị</h1><p>Nhập thông tin quản trị để tiếp tục.</p><div class="alert error">Tên đăng nhập hoặc mật khẩu không đúng.</div><div class="field"><label>Tên đăng nhập</label><input class="input" name="username" required autocomplete="username"></div><div class="field"><label>Mật khẩu</label><input class="input" type="password" name="password" required autocomplete="current-password"></div><button class="btn btn-primary" type="submit">Đăng nhập</button></form></div></body></html>'''),401
    if session.get("admin_user"): return redirect("/admin")
    return render_template_string(r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Đăng nhập · LC79</title>''' + CSS + r'''</head><body><div class="login-page"><form class="login-card" method="post"><div class="login-brand"><div class="brand-mark">P</div><div><b>P A W</b><div class="small muted">LC79 CONTROL</div></div></div><h1>Đăng nhập quản trị</h1><p>Đăng nhập để quản lý key, mã kích hoạt và trạng thái hệ thống.</p><div class="field"><label>Tên đăng nhập</label><input class="input" name="username" required autocomplete="username" placeholder="Tên đăng nhập"></div><div class="field"><label>Mật khẩu</label><input class="input" type="password" name="password" required autocomplete="current-password" placeholder="Mật khẩu"></div><button class="btn btn-primary" type="submit">Đăng nhập</button><div class="small muted" style="text-align:center;margin-top:18px">Phiên quản trị có hiệu lực tối đa 8 giờ</div></form></div></body></html>''')

@app.route("/admin/logout")
def admin_logout(): session.clear(); return redirect("/admin/login")

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn=db()
    total_keys=conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    active_keys=conn.execute("SELECT COUNT(*) FROM api_keys WHERE is_active=1 AND (expires_at IS NULL OR expires_at>?)",(now_iso(),)).fetchone()[0]
    active_codes=conn.execute("SELECT COUNT(*) FROM activation_codes WHERE revoked=0 AND (max_uses=-1 OR used_count<max_uses)").fetchone()[0]
    total_predictions=conn.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]
    tables=conn.execute("SELECT t.*,s.last_seen_id,s.last_poll_at,s.last_poll_error FROM tables_ t LEFT JOIN table_states s ON s.table_code=t.code ORDER BY t.sort_order").fetchall()
    activity=conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 20").fetchall(); conn.close()
    cards=''.join(f'<div class="card"><div class="stat-label">{label}</div><div class="stat-value">{value:,}</div><div class="stat-note">Số liệu hiện tại</div></div>' for label,value in (("Tổng số key",total_keys),("Key đang hoạt động",active_keys),("Mã còn khả dụng",active_codes),("Tổng dự đoán",total_predictions)))
    table_html=''
    for t in tables:
        code=t["code"]; acc=accuracy(code,100); health="red" if t["last_poll_error"] else ("green" if t["last_poll_at"] else "yellow")
        n=conn_count_predictions(code)
        table_html+=f'''<div class="card"><div class="card-head"><div><div class="card-title"><span class="health {health}"></span> {t['name']}</div><div class="card-sub mono">{code}</div></div>{badge('Đang chạy' if t['is_active'] else 'Tạm dừng','success' if t['is_active'] else 'warning')}</div><div class="split"><span class="muted small">Độ chính xác 100 kết quả</span><b>{acc*100:.1f}%</b></div><div class="progress" style="margin:10px 0 18px"><span style="width:{acc*100:.1f}%"></span></div><div class="kv"><div class="kv-item"><div class="kv-label">Phiên mới nhất</div><div class="kv-value">{int(t['last_seen_id'] or 0):,}</div></div><div class="kv-item"><div class="kv-label">Dự đoán đã lưu</div><div class="kv-value">{n:,}</div></div></div><div class="actions" style="margin-top:16px"><a class="btn btn-secondary btn-sm" href="/admin/monitor/{code}">Chi tiết bàn</a></div></div>'''
    timeline=''.join(f'<div class="timeline-item"><div class="timeline-title">{a["action"]} · {a["target"] or "Hệ thống"}</div><div class="timeline-meta">{a["admin_user"] or "Hệ thống"} · {fmt_date(a["created_at"])}</div></div>' for a in activity) or '<div class="empty">Chưa có hoạt động.</div>'
    body=f'''<div class="page-head"><div><div class="page-title">Bảng điều khiển</div><div class="page-sub">Tổng quan hoạt động và trạng thái hai bàn LC79.</div></div><div class="actions"><a class="btn btn-secondary" href="/admin/monitor">{svg_icon('refresh',16)} Giám sát hệ thống</a></div></div><div class="grid stats">{cards}</div><div class="grid two">{table_html}</div><div class="card" style="margin-top:20px"><div class="card-head"><div><div class="card-title">Hoạt động gần đây</div><div class="card-sub">20 thao tác quản trị mới nhất</div></div><a class="btn btn-quiet btn-sm" href="/admin/logs">Xem nhật ký</a></div><div class="timeline">{timeline}</div></div><script>setTimeout(()=>location.reload(),15000)</script>'''
    return render_admin("Bảng điều khiển","dashboard",body)

def conn_count_predictions(code):
    c=db(); n=c.execute("SELECT COUNT(*) FROM predictions WHERE table_code=?",(code,)).fetchone()[0]; c.close(); return n

@app.route("/admin/keys",methods=["GET","POST"])
@admin_required
def admin_keys():
    conn=db()
    if request.method=="POST":
        scope=request.form.get("scope","lc79_tx,lc79_md5")
        note=request.form.get("note","")[:200]
        try: days=max(60/86400,min(3650,float(request.form.get("days",30))))
        except (TypeError,ValueError): days=30.0
        try: max_devices=max(1,min(10,int(request.form.get("max_devices",1))))
        except (TypeError,ValueError): max_devices=1
        try: amount=max(1,min(500,int(request.form.get("amount",1))))
        except (TypeError,ValueError): amount=1
        made=[]
        for _ in range(amount):
            key="LC79-"+secrets.token_hex(12).upper()
            conn.execute("INSERT INTO api_keys(key,scope,note,expires_at,days,max_devices,activated) VALUES(?,?,?,?,?,?,0)",
                         (key,scope,note,None,days,max_devices))
            made.append(key)
        conn.commit(); conn.close()
        admin_log("Tạo key hàng loạt" if amount>1 else "Tạo key",f"{amount} key",{"scope":scope,"duration":duration_label(days),"max_devices":max_devices})
        session["new_keys"]=made
        return redirect("/admin/keys")
    rows=conn.execute("SELECT k.*,COUNT(d.id) device_count FROM api_keys k LEFT JOIN api_key_devices d ON d.key=k.key AND d.released_at IS NULL GROUP BY k.key ORDER BY k.created_at DESC").fetchall()
    conn.close()
    tr=''
    for r in rows:
        if not r["is_active"]:
            status="Đã thu hồi"
        elif not int(r["activated"] or 0):
            status="Chưa kích hoạt"
        elif r["expires_at"] and r["expires_at"]<now_iso():
            status="Hết hạn"
        else:
            status="Hoạt động"
        kind="danger" if status in ("Đã thu hồi","Hết hạn") else ("warning" if status=="Chưa kích hoạt" else "success")
        short=r["key"][:12]+"…"
        expiry_label="Chưa kích hoạt" if not int(r["activated"] or 0) else rel_date(r["expires_at"])
        tr+=f'''<tr><td><span class="mono">{short}</span> <button class="btn btn-quiet btn-sm" onclick="copyText('{r['key']}')">{svg_icon('copy',14)}</button></td><td>{r["scope"]}</td><td>{r["note"] or '—'}</td><td>{expiry_label}</td><td>{r["device_count"]}/{r["max_devices"]}</td><td>{badge(status,kind)}</td><td><div class="actions"><a class="btn btn-secondary btn-sm" href="/admin/keys/{quote(r['key'])}">Chi tiết</a><form method="post" action="/admin/keys/{quote(r['key'])}/revoke" onsubmit="return confirmAction('Thu hồi key này?')"><button class="btn btn-danger btn-sm">Thu hồi</button></form><form method="post" action="/admin/keys/{quote(r['key'])}/unlock"><button class="btn btn-secondary btn-sm">Mở khóa</button></form></div></td></tr>'''
    tr_html=tr if tr else '<tr><td colspan="7" class="empty">Chưa có key.</td></tr>'
    new_keys=session.pop("new_keys",[])
    key_text="\n".join(new_keys)
    body=f'''<div class="page-head"><div><div class="page-title">Quản lý key</div><div class="page-sub">Tạo key đơn hoặc hàng loạt. Thời hạn chỉ bắt đầu khi khách nhập key vào tool và kích hoạt lần đầu.</div></div><button class="btn btn-primary" onclick="openModal('createKey')">{svg_icon('plus',16)} Tạo key</button></div><div class="toolbar"><div class="searchbox">{svg_icon('search',16)}<input id="keySearch" class="input" placeholder="Tìm key, ghi chú..." oninput="filterRows('keySearch','keyTable')"></div><select class="select" style="max-width:190px" onchange="filterStatus(this.value)"><option value="">Tất cả trạng thái</option><option>Chưa kích hoạt</option><option>Hoạt động</option><option>Hết hạn</option><option>Đã thu hồi</option></select></div><div class="card" style="padding:0"><div class="table-wrap" style="border:0"><table class="data-table" id="keyTable"><thead><tr><th>Key</th><th>Phạm vi</th><th>Ghi chú</th><th>Thời hạn</th><th>Thiết bị</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{tr_html}</tbody></table></div></div><div class="modal-backdrop" id="createKey" onclick="if(event.target===this)closeModal('createKey')"><form class="modal" method="post"><div class="modal-title">Tạo key mới</div><div class="modal-body">Key chưa chạy thời hạn cho đến lần khách kích hoạt đầu tiên.</div><div class="field"><label>Phạm vi bàn</label><select class="select" name="scope"><option value="lc79_tx,lc79_md5">Cả hai bàn</option><option value="lc79_tx">Chỉ bàn Hũ</option><option value="lc79_md5">Chỉ bàn MD5</option></select></div><div class="field" style="margin-top:14px"><label>Ghi chú</label><input class="input" name="note" maxlength="200" placeholder="Tên khách hàng hoặc ghi chú"></div><div class="grid two" style="margin-top:14px"><div class="field"><label>Thời hạn</label><select class="select" name="days"><option value="0.0208333333">30 phút</option><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7" selected>7 ngày</option><option value="30">30 ngày</option><option value="365">365 ngày</option></select></div><div class="field"><label>Số thiết bị tối đa</label><input class="input" name="max_devices" type="number" min="1" max="10" value="1" required></div></div><div class="field" style="margin-top:14px"><label>Số lượng key cần tạo</label><input class="input" name="amount" type="number" min="1" max="500" value="1" required></div><div class="modal-footer" style="margin-top:22px"><button type="button" class="btn btn-secondary" onclick="closeModal('createKey')">Hủy</button><button class="btn btn-primary" type="submit">Tạo key</button></div></form></div><div class="modal-backdrop {'open' if new_keys else ''}" id="keysCreated"><div class="modal"><div class="modal-title">Key vừa tạo</div><div class="modal-body">Sao chép danh sách hoặc tải xuống tệp TXT để lưu lại.</div><textarea class="textarea" id="newKeys" readonly>{key_text}</textarea><div class="modal-footer" style="margin-top:18px"><button class="btn btn-secondary" onclick="closeModal('keysCreated')">Đóng</button><button class="btn btn-secondary" onclick="copyText(document.getElementById('newKeys').value)">Sao chép tất cả</button><button class="btn btn-primary" onclick="downloadKeys()">Tải .txt</button></div></div></div><script>function filterStatus(v){{document.querySelectorAll('#keyTable tbody tr').forEach(r=>r.style.display=(!v||r.cells[5]?.innerText.includes(v))?'':'none')}}function downloadKeys(){{const b=new Blob([document.getElementById('newKeys').value],{{type:'text/plain;charset=utf-8'}});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='lc79-keys.txt';a.click();URL.revokeObjectURL(a.href)}}</script>'''
    return render_admin("Quản lý key","keys",body)


@app.route("/admin/keys/<path:key>")
@admin_required
def admin_key_detail(key):
    conn=db(); k=conn.execute("SELECT * FROM api_keys WHERE key=?",(key,)).fetchone()
    if not k: conn.close(); return render_admin("Không tìm thấy","keys",'<div class="empty">Key không tồn tại.</div>'),404
    devices=conn.execute("SELECT * FROM api_key_devices WHERE key=? ORDER BY id DESC LIMIT 10",(key,)).fetchall()
    requests_log=conn.execute("SELECT * FROM activation_log WHERE key=? ORDER BY id DESC LIMIT 20",(key,)).fetchall()
    daily=conn.execute("SELECT substr(created_at,1,10) day,COUNT(*) n FROM activation_log WHERE key=? AND success=1 AND created_at>=datetime('now','-7 days') GROUP BY day ORDER BY day",(key,)).fetchall(); conn.close()
    active=("Đã thu hồi" if not k["is_active"] else ("Chưa kích hoạt" if not int(k["activated"] or 0) else "Đang hoạt động"))
    exp="Chưa kích hoạt" if not int(k["activated"] or 0) else rel_date(k["expires_at"])
    devrows=''.join(f'<tr><td class="mono">{d["device_id"][:18]}…</td><td>{d["ip"] or "—"}</td><td>{d["browser"] or "—"} / {d["os"] or "—"}</td><td>{fmt_date(d["last_seen"])}</td><td>{badge("Đang dùng" if not d["released_at"] else "Đã nhả","success" if not d["released_at"] else "neutral")}</td></tr>' for d in devices) or '<tr><td colspan="5" class="empty">Chưa có thiết bị.</td></tr>'
    reqrows=''.join(f'<tr><td>{fmt_date(x["created_at"])}</td><td>{x["code"] or "—"}</td><td>{badge("Thành công" if x["success"] else "Thất bại","success" if x["success"] else "danger")}</td><td>{x["reason"] or "—"}</td></tr>' for x in requests_log) or '<tr><td colspan="4" class="empty">Chưa có yêu cầu.</td></tr>'
    maxv=max([x["n"] for x in daily],default=1); bars=''.join(f'<div style="flex:1;display:flex;flex-direction:column;justify-content:end;gap:8px;align-items:center"><div style="width:100%;height:{max(4,x["n"]/maxv*120)}px;background:#3b82f6;border-radius:4px 4px 0 0"></div><span class="small muted">{x["day"][5:]}</span></div>' for x in daily) or '<div class="empty">Chưa có dữ liệu 7 ngày.</div>'
    body=f'''<div class="page-head"><div><div class="page-title">Chi tiết key</div><div class="page-sub mono">{key} <button class="btn btn-quiet btn-sm" onclick="copyText('{key}')">{svg_icon('copy',14)}</button> {badge(active,'danger' if not k['is_active'] else ('warning' if not int(k['activated'] or 0) else 'success'))}</div></div><div class="actions"><form method="post" action="/admin/keys/{quote(key)}/revoke" onsubmit="return confirmAction('Thu hồi key?')"><button class="btn btn-danger">Thu hồi key</button></form><form method="post" action="/admin/keys/{quote(key)}/unlock"><button class="btn btn-secondary">Mở khóa thiết bị</button></form></div></div><div class="card"><div class="kv"><div class="kv-item"><div class="kv-label">Ngày tạo</div><div class="kv-value">{fmt_date(k['created_at'])}</div></div><div class="kv-item"><div class="kv-label">Ngày hết hạn</div><div class="kv-value">{'Chưa kích hoạt' if not int(k['activated'] or 0) else fmt_date(k['expires_at'])}</div></div><div class="kv-item"><div class="kv-label">Thời hạn còn lại</div><div class="kv-value">{exp}</div></div><div class="kv-item"><div class="kv-label">Lần sử dụng cuối</div><div class="kv-value">{fmt_date(k['last_used_at'])}</div></div></div><div class="split" style="margin-top:18px"><span class="muted">Phạm vi: {k['scope']} · Ghi chú: {k['note'] or '—'}</span><span class="muted">Thiết bị tối đa: {k['max_devices']}</span></div></div><div class="grid two" style="margin-top:18px"><div class="card"><div class="card-head"><div><div class="card-title">Thiết bị</div><div class="card-sub">10 thiết bị gần nhất</div></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Mã thiết bị</th><th>IP</th><th>Trình duyệt / HĐH</th><th>Hoạt động</th><th>Trạng thái</th></tr></thead><tbody>{devrows}</tbody></table></div></div><div class="card"><div class="card-head"><div><div class="card-title">Lượt sử dụng 7 ngày</div><div class="card-sub">Theo nhật ký kích hoạt thành công</div></div></div><div style="height:170px;display:flex;align-items:end;gap:12px;padding:12px 4px 0">{bars}</div></div></div><div class="card" style="margin-top:18px"><div class="card-head"><div class="card-title">Yêu cầu gần đây</div><div class="card-sub">Tối đa 20 bản ghi</div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Thời gian</th><th>Mã kích hoạt</th><th>Kết quả</th><th>Chi tiết</th></tr></thead><tbody>{reqrows}</tbody></table></div></div>'''
    return render_admin("Chi tiết key","keys",body)

@app.route("/admin/keys/<path:key>/revoke",methods=["POST"])
@admin_required
def revoke_key(key):
    c=db(); c.execute("UPDATE api_keys SET is_active=0 WHERE key=?",(key,)); c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị thu hồi key' WHERE key=? AND released_at IS NULL",(now_iso(),key)); c.commit(); c.close(); admin_log("Thu hồi key",key); return redirect("/admin/keys")

@app.route("/admin/keys/<path:key>/unlock",methods=["POST"])
@admin_required
def unlock_key(key):
    c=db(); c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị mở khóa' WHERE key=? AND released_at IS NULL",(now_iso(),key)); c.commit(); c.close(); admin_log("Mở khóa thiết bị",key); return redirect(request.referrer or "/admin/keys")

@app.route("/admin/codes",methods=["GET","POST"])
@admin_required
def admin_codes():
    conn=db()
    if request.method=="POST":
        scope=request.form.get("scope","lc79_tx,lc79_md5")
        try: days=max(60/86400,min(3650,float(request.form.get("days",30))))
        except (TypeError,ValueError): days=30.0
        amount=max(1,min(500,int(request.form.get("amount",1))))
        uses=max(-1,min(1000,int(request.form.get("max_uses",1))))
        made=[]
        for _ in range(amount):
            code="PAW-"+secrets.token_hex(5).upper()
            conn.execute("INSERT INTO activation_codes(code,scope,days,max_uses,created_by) VALUES(?,?,?,?,?)",(code,scope,days,uses,session.get("admin_user")))
            made.append(code)
        conn.commit(); conn.close(); admin_log("Tạo mã kích hoạt",f"{amount} mã",{"scope":scope,"days":days})
        session["new_codes"]=made
        return redirect("/admin/codes")
    rows=conn.execute("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT 500").fetchall(); conn.close()
    tr=''
    for r in rows:
        state="Đã thu hồi" if r["revoked"] else ("Đã dùng hết" if r["max_uses"]!=-1 and r["used_count"]>=r["max_uses"] else "Còn khả dụng")
        tr+=f'<tr><td class="mono">{r["code"]} <button class="btn btn-quiet btn-sm" onclick="copyText(\'{r["code"]}\')">{svg_icon("copy",14)}</button></td><td>{r["scope"]}</td><td>{duration_label(r["days"])}</td><td>{r["used_count"]}/{"Không giới hạn" if r["max_uses"]==-1 else r["max_uses"]}</td><td>{fmt_date(r["expires_at"])}</td><td>{badge(state,"success" if state=="Còn khả dụng" else "neutral")}</td><td><form method="post" action="/admin/codes/{quote(r["code"])}/revoke"><button class="btn btn-danger btn-sm">Thu hồi</button></form></td></tr>'
    tr_html=tr if tr else '<tr><td colspan="7" class="empty">Chưa có mã kích hoạt.</td></tr>'
    new_codes=session.pop("new_codes",[]); code_modal='\n'.join(new_codes)
    body=f'''<div class="page-head"><div><div class="page-title">Mã kích hoạt</div><div class="page-sub">Tạo mã đơn hoặc hàng loạt để cấp key cho khách hàng.</div></div></div><div class="grid two"><div class="card"><div class="card-head"><div class="card-title">Tạo mã đơn</div></div><form method="post"><input type="hidden" name="amount" value="1"><div class="field"><label>Phạm vi bàn</label><select class="select" name="scope"><option value="lc79_tx,lc79_md5">Cả hai bàn</option><option value="lc79_tx">Chỉ bàn Hũ</option><option value="lc79_md5">Chỉ bàn MD5</option></select></div><div class="field" style="margin-top:14px"><label>Thời hạn</label><select class="select" name="days"><option value="0.0208333333">30 phút</option><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7">7 ngày</option><option value="30" selected>30 ngày</option><option value="365">365 ngày</option></select></div><div class="field" style="margin-top:14px"><label>Số lượt sử dụng</label><input class="input" name="max_uses" type="number" min="1" value="1"></div><button class="btn btn-primary" style="margin-top:18px">Tạo mã đơn</button></form></div><div class="card"><div class="card-head"><div class="card-title">Tạo mã hàng loạt</div></div><form method="post"><div class="field"><label>Phạm vi bàn</label><select class="select" name="scope"><option value="lc79_tx,lc79_md5">Cả hai bàn</option><option value="lc79_tx">Chỉ bàn Hũ</option><option value="lc79_md5">Chỉ bàn MD5</option></select></div><div class="grid two" style="margin-top:14px"><div class="field"><label>Số lượng mã</label><input class="input" name="amount" type="number" min="1" max="500" value="10"></div><div class="field"><label>Thời hạn</label><select class="select" name="days"><option value="0.0208333333">30 phút</option><option value="0.0416666667">1 giờ</option><option value="1">1 ngày</option><option value="3">3 ngày</option><option value="7">7 ngày</option><option value="30" selected>30 ngày</option><option value="365">365 ngày</option></select></div></div><div class="field" style="margin-top:14px"><label>Lượt dùng mỗi mã (-1 không giới hạn)</label><input class="input" name="max_uses" type="number" min="-1" value="1"></div><button class="btn btn-primary" style="margin-top:18px">Tạo hàng loạt</button></form></div></div><div class="card" style="margin-top:20px;padding:0"><div class="card-head" style="padding:20px 20px 0"><div class="card-title">Danh sách mã</div></div><div class="table-wrap" style="border:0"><table class="data-table"><thead><tr><th>Mã</th><th>Phạm vi</th><th>Thời hạn</th><th>Đã dùng</th><th>Ngày hết hạn</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{tr_html}</tbody></table></div></div><div class="modal-backdrop {'open' if new_codes else ''}" id="codesModal"><div class="modal"><div class="modal-title">Mã kích hoạt vừa tạo</div><div class="modal-body">Sao chép danh sách mã hoặc tải xuống tệp văn bản.</div><textarea class="textarea" id="newCodes" readonly>{code_modal}</textarea><div class="modal-footer" style="margin-top:18px"><button class="btn btn-secondary" onclick="closeModal('codesModal')">Đóng</button><button class="btn btn-secondary" onclick="copyText(document.getElementById('newCodes').value)">Sao chép tất cả</button><button class="btn btn-primary" onclick="downloadCodes()">Tải .txt</button></div></div></div><script>function downloadCodes(){{const b=new Blob([document.getElementById('newCodes').value],{{type:'text/plain'}});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='lc79-codes.txt';a.click();URL.revokeObjectURL(a.href)}}</script>'''
    return render_admin("Mã kích hoạt","codes",body)

@app.route("/admin/codes/<path:code>/revoke",methods=["POST"])
@admin_required
def revoke_code(code):
    c=db(); c.execute("UPDATE activation_codes SET revoked=1 WHERE code=?",(code,)); c.commit(); c.close(); admin_log("Thu hồi mã",code); return redirect("/admin/codes")

@app.route("/admin/monitor")
@admin_required
def admin_monitor():
    conn=db(); rows=conn.execute("SELECT t.*,s.last_seen_id,s.last_poll_at,s.last_poll_error FROM tables_ t JOIN table_states s ON s.table_code=t.code ORDER BY t.sort_order").fetchall(); conn.close()
    unhealthy=any(r["last_poll_error"] for r in rows)
    cards=''
    for r in rows:
        code=r["code"]; acc=accuracy(code,100); count=conn_count_predictions(code); health="red" if r["last_poll_error"] else ("green" if r["last_poll_at"] else "yellow")
        cards+=f'''<div class="card"><div class="card-head"><div><div class="card-title"><span class="health {health}"></span> {r['name']}</div><div class="card-sub">{code}</div></div>{badge('Đang chạy' if r['is_active'] else 'Tạm dừng','success' if r['is_active'] else 'warning')}</div><div class="split"><span class="muted">Độ chính xác</span><b>{acc*100:.1f}%</b></div><div class="progress" style="margin:10px 0 18px"><span style="width:{acc*100:.1f}%"></span></div><div class="kv"><div class="kv-item"><div class="kv-label">Phiên mới nhất</div><div class="kv-value">{r['last_seen_id']:,}</div></div><div class="kv-item"><div class="kv-label">Dự đoán</div><div class="kv-value">{count:,}</div></div><div class="kv-item"><div class="kv-label">Lần poll</div><div class="kv-value">{fmt_date(r['last_poll_at'])}</div></div></div><div class="small muted" style="margin-top:12px">{r['last_poll_error'] or 'Không phát hiện lỗi gần nhất.'}</div><div class="actions" style="margin-top:16px"><a class="btn btn-secondary btn-sm" href="/admin/monitor/{code}">Chi tiết</a><form method="post" action="/admin/monitor/{code}/pause"><button class="btn btn-secondary btn-sm">{'Tạm dừng' if r['is_active'] else 'Tiếp tục'}</button></form><form method="post" action="/admin/monitor/{code}/restart" onsubmit="return confirmAction('Khởi động lại engine bàn này?')"><button class="btn btn-danger btn-sm">Khởi động lại</button></form></div></div>'''
    body=f'''<div class="page-head"><div><div class="page-title">Giám sát bàn</div><div class="page-sub">Theo dõi worker, độ chính xác và trạng thái từng bàn.</div></div><label class="small muted"><input id="autoRefresh" type="checkbox" checked> Tự làm mới mỗi 10 giây</label></div>{'<div class="alert error">Phát hiện bàn có lỗi lấy dữ liệu. Kiểm tra trạng thái upstream và nhật ký worker.</div>' if unhealthy else ''}<div class="grid two">{cards}</div><script>let timer=setInterval(()=>{{if(document.getElementById('autoRefresh')?.checked)location.reload()}},10000);</script>'''
    return render_admin("Giám sát bàn","monitor",body)

@app.route("/admin/monitor/<table_code>")
@admin_required
def admin_monitor_detail(table_code):
    if table_code not in TABLES:return render_admin("Không tìm thấy","monitor",'<div class="empty">Bàn không tồn tại.</div>'),404
    conn=db(); state=conn.execute("SELECT * FROM table_states WHERE table_code=?",(table_code,)).fetchone(); table=conn.execute("SELECT * FROM tables_ WHERE code=?",(table_code,)).fetchone()
    preds=conn.execute("SELECT * FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT 200",(table_code,)).fetchall(); conn.close()
    resolved=[p for p in preds if p["result"]]; acc=accuracy(table_code,100); wins=sum(p["result"]=="win" for p in resolved); losses=len(resolved)-wins
    chart_values=[]
    chronological=list(reversed(preds))
    for i in range(len(chronological)):
        window=[p for p in chronological[max(0,i-19):i+1] if p["result"]]
        if window: chart_values.append(sum(p["result"]=="win" for p in window)/len(window))
    engine_state=load_engine(table_code).predict(accuracy(table_code,100),accuracy(table_code,500))
    weights=engine_state.get("weights",{})
    total_weight=sum(weights.values()) or 1
    expert_html=''.join(f'<div class="expert"><span class="expert-name">{n.upper()}</span><div class="progress"><span style="width:{v/total_weight*100:.1f}%"></span></div><span class="expert-val">{v/total_weight*100:.1f}%</span></div>' for n,v in weights.items())
    history=''.join(f'<tr><td class="mono">{p["session_id"]}</td><td>{p["prediction"]}</td><td>{p["actual"] or "Chưa có"}</td><td>{badge("Thắng" if p["result"]=="win" else "Thua" if p["result"]=="lose" else "Chờ", "success" if p["result"]=="win" else "danger" if p["result"]=="lose" else "neutral")}</td><td>{fmt_date(p["created_at"])}</td></tr>' for p in preds[:50]) or '<tr><td colspan="5" class="empty">Chưa có lịch sử.</td></tr>'
    learned_count=len(json.loads(state["history_json"] or '{"history":[]}').get("history",[]))
    body=f'''<div class="page-head"><div><div class="page-title">{table['name']}</div><div class="page-sub mono">{table_code} · Phiên mới nhất {state['last_seen_id']:,}</div></div><div class="actions"><form method="post" action="/admin/monitor/{table_code}/pause"><button class="btn btn-secondary">{'Tạm dừng' if table['is_active'] else 'Tiếp tục'}</button></form><form method="post" action="/admin/monitor/{table_code}/restart" onsubmit="return confirmAction('Nhập RESTART để xác nhận khởi động lại engine?')"><input class="input" style="width:110px" name="confirm" placeholder="RESTART" required><button class="btn btn-danger">Khởi động lại</button></form><form method="post" action="/admin/monitor/{table_code}/unlock"><button class="btn btn-secondary">Mở khóa thiết bị</button></form></div></div><div class="grid six"><div class="card"><div class="stat-label">Độ chính xác</div><div class="stat-value">{acc*100:.1f}%</div></div><div class="card"><div class="stat-label">Đã dự đoán</div><div class="stat-value">{len(preds)}</div></div><div class="card"><div class="stat-label">Đã phân định</div><div class="stat-value">{len(resolved)}</div></div><div class="card"><div class="stat-label">Thắng</div><div class="stat-value">{wins}</div></div><div class="card"><div class="stat-label">Thua</div><div class="stat-value">{losses}</div></div><div class="card"><div class="stat-label">Phiên đã học</div><div class="stat-value">{learned_count}</div></div></div><div class="grid two" style="margin-top:18px"><div class="card"><div class="card-head"><div class="card-title">Độ chính xác 200 phiên gần nhất</div></div>{chart_svg(chart_values or [acc]*10,200)}</div><div class="card"><div class="card-head"><div class="card-title">Trọng số chuyên gia</div><div class="card-sub">Trọng số được tái tạo khi worker học phiên mới</div></div>{expert_html}</div></div><div class="card" style="margin-top:18px"><div class="card-head"><div class="card-title">Lịch sử 50 phiên gần nhất</div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Phiên</th><th>Dự đoán</th><th>Kết quả</th><th>Trạng thái</th><th>Thời gian</th></tr></thead><tbody>{history}</tbody></table></div></div>'''
    return render_admin("Chi tiết bàn","monitor",body)

@app.route("/admin/monitor/<table_code>/pause",methods=["POST"])
@admin_required
def monitor_pause(table_code):
    c=db(); row=c.execute("SELECT is_active FROM tables_ WHERE code=?",(table_code,)).fetchone()
    if row:c.execute("UPDATE tables_ SET is_active=? WHERE code=?",(0 if row[0] else 1,table_code))
    c.commit(); c.close(); admin_log("Đổi trạng thái bàn",table_code); return redirect(request.referrer or "/admin/monitor")

@app.route("/admin/monitor/<table_code>/restart",methods=["POST"])
@admin_required
def monitor_restart(table_code):
    if table_code not in TABLES:return redirect("/admin/monitor")
    if request.form.get("confirm") != "RESTART":return redirect(request.referrer or "/admin/monitor")
    set_worker_control("force_restart", "1")
    c=db(); c.execute("UPDATE table_states SET history_json=?,last_seen_id=0,last_poll_error=NULL WHERE table_code=?",(json.dumps({"history": []}),table_code)); c.execute("INSERT INTO engine_resets(table_code,reason,accuracy_before,sessions_at_reset) VALUES(?,?,?,?)",(table_code,"Quản trị khởi động lại engine",accuracy(table_code,100),0)); c.commit(); c.close(); admin_log("Khởi động lại engine",table_code); return redirect("/admin/monitor/"+table_code)

@app.route("/admin/monitor/<table_code>/unlock",methods=["POST"])
@admin_required
def monitor_unlock(table_code):
    c=db(); keys=c.execute("SELECT key,scope FROM api_keys").fetchall()
    matching=[r["key"] for r in keys if _scope_allows(r["scope"],table_code)]
    for key in matching:
        c.execute("UPDATE api_key_devices SET released_at=?,released_reason='Quản trị mở khóa tại bàn' WHERE key=? AND released_at IS NULL",(now_iso(),key))
    c.commit(); c.close(); admin_log("Mở khóa thiết bị",table_code,{"keys":len(matching)}); return redirect(request.referrer or "/admin/monitor")

@app.route("/admin/logs")
@admin_required
def admin_logs():
    action=request.args.get("action",""); conn=db()
    action_types=[r[0] for r in conn.execute("SELECT DISTINCT action FROM admin_actions WHERE action IS NOT NULL ORDER BY action").fetchall()]
    if action: rows=conn.execute("SELECT * FROM admin_actions WHERE action=? ORDER BY id DESC LIMIT 300",(action,)).fetchall()
    else: rows=conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 300").fetchall()
    conn.close()
    items=''.join(f'<div class="timeline-item"><div class="timeline-title">{svg_icon("activity",14)} <b>{r["action"]}</b> · {r["target"] or "Hệ thống"}</div><div class="timeline-meta">{r["admin_user"] or "Hệ thống"} · {fmt_date(r["created_at"])} · IP {r["ip"] or "—"}</div><div class="small muted">{r["detail_json"] or ""}</div></div>' for r in rows) or '<div class="empty">Chưa có nhật ký phù hợp.</div>'
    body=f'''<div class="page-head"><div><div class="page-title">Nhật ký quản trị</div><div class="page-sub">Dòng thời gian thao tác quản trị gần nhất.</div></div></div><form class="toolbar" method="get"><select class="select" style="max-width:280px" name="action"><option value="">Tất cả thao tác</option>{''.join(f'<option value="{x}" {"selected" if x==action else ""}>{x}</option>' for x in action_types)}</select><button class="btn btn-secondary">Lọc nhật ký</button></form><div class="card"><div class="timeline">{items}</div></div>'''
    return render_admin("Nhật ký quản trị","logs",body)



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
def _admin_table(code,title):
    c=db();rows=c.execute("SELECT * FROM predictions WHERE table_code=? ORDER BY session_id DESC LIMIT 100",(code,)).fetchall();c.close();trs="".join(f'<tr><td>{r["session_id"]}</td><td>{r["prediction"]}</td><td>{r["actual"] or "—"}</td><td>{r["result"] or "pending"}</td><td>{r["confidence"]}%</td><td>{r["created_at"]}</td></tr>' for r in rows) or '<tr><td colspan="6">Chưa có dữ liệu</td></tr>'
    body=f'<div class="page-head"><div><div class="page-title">{title}</div><div class="page-sub">Theo dõi dự đoán, kết quả và độ chính xác.</div></div><div class="actions"><a class="btn btn-secondary" href="/admin/monitor/{code}">Chi tiết</a><a class="btn btn-primary" href="/admin/backtest">Backtest</a></div></div><div class="grid stats"><div class="card"><div class="stat-label">Accuracy 100</div><div class="stat-value">{accuracy(code,100)*100:.1f}%</div></div><div class="card"><div class="stat-label">Accuracy 500</div><div class="stat-value">{accuracy(code,500)*100:.1f}%</div></div><div class="card"><div class="stat-label">Tổng dự đoán</div><div class="stat-value">{conn_count_predictions(code)}</div></div></div><div class="card"><div class="card-title">100 phiên gần nhất</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Phiên</th><th>Dự đoán</th><th>Thực tế</th><th>Kết quả</th><th>Tin cậy</th><th>Thời gian</th></tr></thead><tbody>{trs}</tbody></table></div></div>'
    return render_admin(title,active=code,body=body)
@app.get("/admin/modules")
@admin_required
def admin_modules():
    body=''.join(f'<div class="card"><h3>{m}</h3><p class="muted">Trọng số thích nghi được học theo log-loss từ dữ liệu đã quan sát.</p></div>' for m in PredictionEngine.EXPERTS)
    return _admin_simple("Phân tích module","modules",f'<div class="grid two">{body}</div>')
@app.get("/admin/backtest")
@admin_required
def admin_backtest():
    code=request.args.get("table","lc79_tx");code=code if code in TABLES else "lc79_tx";c=db();rows=c.execute("SELECT actual FROM predictions WHERE table_code=? AND actual IS NOT NULL ORDER BY session_id DESC LIMIT 500",(code,)).fetchall();c.close();res=Backtest.run([1 if r[0]=="TAI" else 0 for r in reversed(rows)])
    return _admin_simple("Backtest","backtest",f'<div class="grid stats"><div class="card"><div class="stat-label">Accuracy</div><div class="stat-value">{res["accuracy"]*100:.2f}%</div></div><div class="card"><div class="stat-label">Correct / Total</div><div class="stat-value">{res["correct"]}/{res["total_predictions"]}</div></div><div class="card"><div class="stat-label">Win streak</div><div class="stat-value">{res["streak_wins"]}</div></div><div class="card"><div class="stat-label">Loss streak</div><div class="stat-value">{res["streak_losses"]}</div></div></div><div class="card"><pre>{json.dumps(res,ensure_ascii=False,indent=2)}</pre></div>')
@app.get("/admin/predictions")
@admin_required
def admin_predictions():return _admin_table("lc79_tx","Dự đoán")
@app.get("/admin/resolutions")
@admin_required
def admin_resolutions():return _admin_table("lc79_tx","Kết quả phân định")
@app.get("/admin/health")
@admin_required
def admin_health():
    c=db();p=c.execute("SELECT COUNT(*) FROM predictions").fetchone()[0];r=c.execute("SELECT COUNT(*) FROM prediction_resolutions").fetchone()[0];c.close();path=os.environ.get("DATABASE_PATH","/tmp/lc79.db");size=os.path.getsize(path)/1048576 if os.path.exists(path) else 0
    return _admin_simple("Sức khỏe hệ thống","health",f'<div class="grid stats"><div class="card"><div class="stat-label">Uptime</div><div class="stat-value">{int(time.time()-APP_STARTED)}s</div></div><div class="card"><div class="stat-label">DB Size</div><div class="stat-value">{size:.2f} MB</div></div><div class="card"><div class="stat-label">Predictions</div><div class="stat-value">{p}</div></div><div class="card"><div class="stat-label">Resolutions</div><div class="stat-value">{r}</div></div></div>')
@app.route("/admin/settings",methods=["GET","POST"])
@admin_required
def admin_settings():
    if request.method=="POST":
        code=request.form.get("table_code","")
        if code in TABLES:
            try:shrink=max(.1,min(1.,float(request.form.get("shrink_extra",1))))
            except ValueError:shrink=1.
            try:minimum=max(50,min(85,int(request.form.get("min_confidence",50))))
            except ValueError:minimum=50
            save_table_config(code,{"disabled_modules":request.form.getlist("disabled_modules"),"shrink_extra":shrink,"min_confidence":minimum});admin_log("Cập nhật cấu hình bàn",code)
        return redirect("/admin/settings")
    parts=[]
    for code,meta in TABLES.items():
        cfg=get_table_config(code);checks="".join(f'<label style="display:inline-block;margin:7px"><input type="checkbox" name="disabled_modules" value="{m}" {"checked" if m in cfg.get("disabled_modules",[]) else ""}>{m}</label>' for m in PredictionEngine.EXPERTS)
        parts.append(f'<div class="card"><h3>{meta["name"]}</h3><form method="post"><input type="hidden" name="table_code" value="{code}"><div>{checks}</div><label>Shrink extra</label><input class="input" name="shrink_extra" type="number" min="0.1" max="1" step="0.1" value="{cfg.get("shrink_extra",1)}"><label>Min confidence</label><input class="input" name="min_confidence" type="number" min="50" max="85" value="{cfg.get("min_confidence",50)}"><button class="btn btn-primary">Lưu cấu hình</button></form></div>')
    return _admin_simple("Cài đặt","settings",'<div class="grid two">'+''.join(parts)+'</div>')

# === END app.py ===
