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
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
:root{--bg:#03050a;--surface:rgba(13,20,34,.58);--surface-2:rgba(8,14,25,.85);--surface-3:rgba(255,255,255,.06);--bd:rgba(255,255,255,.15);--bd-hi:rgba(99,231,255,.4);--text:#f4f8ff;--text-1:#dce7f7;--text-2:#91a0b8;--blue:#63e7ff;--blue-2:#5488ff;--green:#5df0b0;--red:#ff667e;--yellow:#ffd783;--r:22px;--r-sm:15px;--r-xs:12px}
*{box-sizing:border-box}html{background:var(--bg);color-scheme:dark}body{margin:0;background:#03050a;color:var(--text);font:13px Manrope,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;line-height:1.55}a{color:inherit;text-decoration:none}button,input,select,textarea{font:inherit}button{cursor:pointer}svg{vertical-align:middle}
.shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:248px;background:rgba(8,13,24,.72);border-right:1px solid var(--bd);backdrop-filter:blur(32px) saturate(180%);padding:24px 16px;z-index:20;box-shadow:2px 0 14px rgba(20,35,65,.025)}
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
.toast-stack{position:fixed;top:20px;right:20px;z-index:9999;display:grid;gap:8px}.toast{background:rgba(10,17,30,.94);border:1px solid var(--bd);border-left:3px solid var(--green);padding:12px 16px;border-radius:9px;box-shadow:0 8px 25px rgba(15,23,42,.12);min-width:240px;animation:toastIn .2s ease;color:#334155}.toast.error{border-left-color:var(--red)}@keyframes toastIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:translateX(0)}}@keyframes modalIn{from{opacity:0;transform:scale(.97)}to{opacity:1;transform:scale(1)}}
.login-page{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at top left,#e8f0ff 0,transparent 42%),var(--bg)}.login-card{width:100%;max-width:410px;background:rgba(10,17,30,.88);border:1px solid rgba(99,231,255,.25);border-radius:18px;padding:32px;box-shadow:0 18px 55px rgba(31,48,80,.09)}.login-brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.login-card h1{font-size:22px;margin:0 0 6px;letter-spacing:-.03em;color:#1e293b}.login-card p{color:#8793a5;margin:0 0 24px}.login-card .field{margin:16px 0}.login-card .btn{width:100%;margin-top:8px}.expert{display:grid;grid-template-columns:90px 1fr 42px;gap:12px;align-items:center;margin:12px 0}.expert-name{font-size:11px;color:#64748b}.expert-val{text-align:right;font-size:11px;color:#8b97a9;font-variant-numeric:tabular-nums}.mobile-menu{display:none}
@media(max-width:1050px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.six{grid-template-columns:repeat(3,minmax(0,1fr))}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.sidebar{width:68px;padding:18px 10px}.brand{padding:0 6px 24px}.brand-name,.brand-sub,.nav-label,.nav-item span,.sidebar-foot{display:none}.nav-item{justify-content:center;padding:0}.main{margin-left:68px}.topbar{padding:0 16px}.content{padding:22px 16px}.two,.three{grid-template-columns:1fr}.page-head{flex-direction:column}.six{grid-template-columns:repeat(2,minmax(0,1fr))}.stats{gap:10px}.card{padding:16px}.stat-value{font-size:24px}}
@media(max-width:420px){.stats,.six,.kv{grid-template-columns:1fr 1fr}.toolbar .searchbox{max-width:none;flex-basis:100%}.topbar{height:56px}.content{padding:18px 12px}.modal{padding:19px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}

/* ===== PAW ADMIN WHITE PRO ===== */
:root{--bg:#f4f7fb;--surface:#fff;--surface-2:#fff;--surface-3:#f7f9fc;--bd:#e5eaf2;--bd-hi:#bfd3f8;--text:#172033;--text-1:#34445e;--text-2:#718096;--blue:#2563eb;--blue-2:#1d4ed8;--green:#16a34a;--red:#dc2626;--yellow:#d97706;--r:18px;--r-sm:13px;--r-xs:9px}
html{background:#f4f7fb;color-scheme:light}body{background:#f4f7fb;color:#25324a;font-family:Inter,Manrope,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:13px}
.shell{background:#f4f7fb}.sidebar{width:258px;background:#fff;border-right:1px solid #e7ecf3;backdrop-filter:none;box-shadow:8px 0 30px rgba(25,45,80,.035);padding:22px 15px;z-index:40}
.brand{padding:2px 9px 25px;gap:12px}.brand-mark{width:42px;height:42px;border-radius:13px;background:linear-gradient(145deg,#2563eb,#60a5fa);box-shadow:0 7px 16px rgba(37,99,235,.2)}
.brand-name{font-size:15px;color:#172033;letter-spacing:.13em}.brand-sub{font-size:9px;color:#8794a8;letter-spacing:.16em}
.nav-label{color:#9aa6b8;font-size:9px;font-weight:800;padding:13px 12px 8px;letter-spacing:.14em}
.nav-item{height:44px;padding:0 13px;border-radius:11px;color:#68778e;margin:4px 0;gap:12px;font-weight:600}.nav-item>span:first-child{width:20px;text-align:center;font-size:17px;color:#8b9ab0}
.nav-item:hover{background:#f5f8ff;color:#2455a6;transform:translateX(2px)}.nav-item.active{background:#edf4ff;color:#1d4ed8;font-weight:800}.nav-item.active>span:first-child{color:#2563eb}.nav-item.active:before{top:9px;bottom:9px;width:3px;background:#2563eb}
.sidebar-foot{border-top:1px solid #edf0f5;color:#9aa6b8;font-size:10px;line-height:1.8}
.main{margin-left:258px;background:#f4f7fb}.topbar{height:66px;padding:0 30px;background:rgba(255,255,255,.94);backdrop-filter:blur(14px);border-bottom:1px solid #e8edf4;box-shadow:0 3px 12px rgba(20,40,80,.025)}
.crumb{color:#8491a5;font-size:12px;font-weight:600}.top-user{color:#34445e;font-size:12px;font-weight:700}
.content{max-width:1480px;padding:30px 32px 48px}.page-head{align-items:center;margin-bottom:22px}.page-title{font-size:25px;color:#172033;letter-spacing:-.045em;font-weight:850}.page-sub{color:#7d8aa0;font-size:12px;line-height:1.65}
.grid{gap:16px}.card{background:#fff;border:1px solid #e7ecf3;border-radius:16px;padding:20px;box-shadow:0 3px 12px rgba(30,55,90,.035);transition:box-shadow .18s,border-color .18s,transform .18s}
.card:hover{border-color:#d6e1f0;box-shadow:0 9px 24px rgba(30,55,90,.07);transform:translateY(-1px)}
.stat-label{color:#8491a5;font-size:9px;font-weight:850;letter-spacing:.1em}.stat-value{color:#172033;font-size:29px;font-weight:850}.stat-note{color:#91a0b4;font-size:11px}
.card-title{color:#25344d;font-size:14px;font-weight:800}.card-sub{color:#8a97aa;font-size:11px}
.health.green{background:#16a34a;box-shadow:0 0 0 4px rgba(22,163,74,.09)}.health.yellow{background:#d97706;box-shadow:0 0 0 4px rgba(217,119,6,.09)}.health.red{background:#dc2626;box-shadow:0 0 0 4px rgba(220,38,38,.09)}
.btn{border-radius:10px;font-size:11px;font-weight:800;min-height:35px}.btn-primary{background:#2563eb;color:#fff;border-color:#2563eb;box-shadow:0 4px 10px rgba(37,99,235,.16)}.btn-primary:hover{background:#1d4ed8;border-color:#1d4ed8}
.btn-secondary{background:#fff;border-color:#dce4ef;color:#50617a}.btn-secondary:hover{background:#f7f9fc;border-color:#c6d4e7;color:#1f3d70}.btn-danger{background:#fff5f5;border-color:#fee2e2;color:#c62828}.btn-quiet{color:#718096;background:transparent}
.input,.select,.textarea{background:#fff;color:#24324a;border:1px solid #dce4ef;border-radius:10px;min-height:38px;padding:9px 12px}.input::placeholder,.textarea::placeholder{color:#a1adbd}
.input:focus,.select:focus,.textarea:focus{border-color:#8bb2fa;box-shadow:0 0 0 3px rgba(37,99,235,.09)}.field label,.field-label{color:#718096;font-size:10px}
.toolbar{gap:9px}.searchbox{max-width:420px}.table-wrap{background:#fff;border:1px solid #e7ecf3;border-radius:13px}.data-table{background:#fff}.data-table thead{background:#f7f9fc}
.data-table th{color:#8794a8;font-size:9px;border-bottom:1px solid #e8edf4;padding:13px 15px}.data-table td{color:#53627a;border-bottom:1px solid #f0f3f7;padding:12px 15px;font-size:11px}.data-table tbody tr:hover td{background:#f8fbff}
.mono{color:#263852}.badge{border-radius:7px;font-size:9px;padding:4px 8px}.badge.success{background:#ecfdf3;color:#15803d;border-color:#c8f0d5}.badge.danger{background:#fff1f2;color:#be123c;border-color:#ffd4dc}.badge.warning{background:#fffbeb;color:#b45309;border-color:#fde7b0}.badge.neutral{background:#f1f5f9;color:#64748b;border-color:#e2e8f0}
.progress{background:#edf1f6;height:7px}.progress>span{background:linear-gradient(90deg,#60a5fa,#2563eb)}.kv-item{background:#f8fafd;border:1px solid #edf1f6;border-radius:11px}.kv-label{color:#8b97a9}.kv-value{color:#26354d}
.timeline:before{background:#e3eaf3}.timeline-item:before{background:#4f83e8;border-color:#fff;box-shadow:0 0 0 1px #cbdaf2}.timeline-title{color:#334155}.timeline-meta{color:#95a1b2}
.chart-box{background:#fff}.alert{border-radius:11px}.alert.error{background:#fff1f2;color:#be123c}
.modal-backdrop{background:rgba(25,40,65,.38);backdrop-filter:blur(4px)}.modal{background:#fff;border:1px solid #e5eaf1;border-radius:18px;box-shadow:0 24px 80px rgba(15,23,42,.18)}.modal-title{color:#1e293b}.modal-body{color:#64748b}
.toast{background:#fff;border:1px solid #e4eaf2;color:#334155;box-shadow:0 10px 30px rgba(15,23,42,.12)}
.login-page{background:radial-gradient(circle at 15% 15%,#eaf2ff,transparent 35%),#f4f7fb}.login-card{background:#fff!important;border:1px solid #e5eaf1!important;box-shadow:0 20px 60px rgba(30,55,90,.1)!important;color:#24324a!important}.login-card h1{color:#172033!important}.login-card p{color:#7d8aa0!important}.login-card .input{background:#fff!important;color:#24324a!important}
.side-tai{color:#dc3b54!important}.side-xiu{color:#0891b2!important}.result-win{color:#16a34a!important}.result-lose{color:#dc2626!important}
.module-row{border-bottom:1px solid #edf1f6}.pagination{border-top:1px solid #edf1f6}.empty{color:#94a0b1}
.mobile-nav-toggle{display:none}.quick-nav{width:min(270px,28vw);margin:0 auto 0 28px;position:relative}.quick-nav input{height:35px;padding:7px 12px 7px 34px;border:1px solid #e2e8f0;border-radius:10px;background:#f8fafc;width:100%;color:#26354d;outline:none}
.quick-nav:before{content:"⌕";position:absolute;left:12px;top:4px;font-size:21px;color:#93a1b5}.quick-nav input:focus{background:#fff;border-color:#9bbcf5;box-shadow:0 0 0 3px rgba(37,99,235,.08)}
@media(max-width:900px){.sidebar{transform:translateX(-105%);transition:transform .22s ease;box-shadow:12px 0 35px rgba(20,35,65,.13)}body.sidebar-open .sidebar{transform:translateX(0)}body.sidebar-open:after{content:"";position:fixed;inset:0;background:rgba(15,23,42,.28);z-index:30}.main{margin-left:0}.mobile-nav-toggle{display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;border:1px solid #e1e8f1;border-radius:10px;background:#fff;color:#334155;font-size:18px;margin-right:12px}.topbar{padding:0 16px}.quick-nav{width:min(230px,36vw);margin-left:0}.content{padding:22px 18px 38px}}
@media(max-width:650px){.topbar{height:60px}.crumb{font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.quick-nav{width:38px;margin-left:auto;flex:0 0 38px}.quick-nav input{padding-left:32px;color:transparent;cursor:pointer}.quick-nav input:focus{position:absolute;right:0;top:-17px;width:min(72vw,300px);z-index:60;color:#26354d;background:#fff;cursor:text}.top-user>span:not(.health){display:none}.top-user .btn{padding:6px 8px;min-height:31px;font-size:10px}.content{padding:18px 12px 32px}.page-head{display:block}.page-head .actions{margin-top:14px}.page-title{font-size:22px}.stats,.stats.six{grid-template-columns:repeat(2,minmax(0,1fr))!important}.two,.three{grid-template-columns:1fr!important}.card{padding:15px;border-radius:14px}.stat-value{font-size:24px}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}.toolbar{align-items:stretch}.toolbar>*{max-width:none!important}.searchbox{min-width:100%;max-width:none}.table-wrap{border-radius:10px}.data-table th,.data-table td{padding:10px 11px}.chart-box{height:205px!important}.modal{padding:17px}.toast-stack{left:12px;right:12px;top:12px}.toast{min-width:0}}
@media(max-width:380px){.stats,.stats.six{grid-template-columns:1fr 1fr!important;gap:9px}.stat-value{font-size:21px}.content{padding-left:9px;padding-right:9px}}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none!important;box-shadow:none!important}.data-table button:focus-visible,.btn:focus-visible,.nav-item:focus-visible{outline:3px solid rgba(37,99,235,.25);outline-offset:2px}

</style>
body:before,body:after{content:"";position:fixed;z-index:-3;pointer-events:none;border-radius:50%;filter:blur(90px);opacity:.35;animation:blobDrift 22s ease-in-out infinite alternate}
body:before{width:46vw;height:46vw;min-width:340px;min-height:340px;left:-12vw;top:-18vw;background:radial-gradient(circle,rgba(31,204,255,.7),transparent 68%)}
body:after{width:52vw;height:52vw;min-width:360px;min-height:360px;right:-18vw;bottom:-20vw;background:radial-gradient(circle,rgba(139,82,255,.65),transparent 68%)}
.shell:before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:.14;background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);background-size:54px 54px}
.card,.login-card,.modal,.stat-card{background:rgba(13,20,34,.58)!important;border:1px solid rgba(255,255,255,.15)!important;backdrop-filter:blur(40px) saturate(200%);-webkit-backdrop-filter:blur(40px) saturate(200%);border-radius:22px;box-shadow:0 24px 80px rgba(0,0,0,.42)}
.sidebar{width:240px;background:rgba(8,13,24,.72);backdrop-filter:blur(32px) saturate(180%)}
.main{margin-left:240px}.brand-mark{background:linear-gradient(145deg,#63e7ff,#a77aff);color:#06101d;box-shadow:0 0 28px rgba(99,231,255,.28)}
.nav-item.active{background:rgba(99,231,255,.1);color:#63e7ff;transform:translateX(4px);box-shadow:0 0 22px rgba(99,231,255,.08)}
.nav-item.active:before{background:#63e7ff;box-shadow:0 0 12px #63e7ff}
.page-title{background:linear-gradient(100deg,#fff,#a9eaff 50%,#bda8ff);background-clip:text;-webkit-background-clip:text;color:transparent}
.btn-primary,.pixel-btn{background:linear-gradient(115deg,#47dff5,#648bff 52%,#8272ff);color:#06101d;border-radius:16px;box-shadow:0 10px 30px rgba(67,163,255,.22)}
.input, input,select,textarea{background:rgba(3,8,18,.72);color:#f4f8ff;border-color:rgba(255,255,255,.15);font:600 12px 'JetBrains Mono'}
input:focus,select:focus,textarea:focus{border-color:#63e7ff;box-shadow:0 0 0 3px rgba(99,231,255,.1)}
table{background:transparent}thead{background:rgba(8,14,25,.85)}th{color:#91a0b8;font:700 9px 'JetBrains Mono';text-transform:uppercase}td{color:#dce7f7;font:500 10px 'JetBrains Mono';font-variant-numeric:tabular-nums}tbody tr:hover{background:rgba(99,231,255,.04)}
.topbar{background:rgba(3,7,15,.68);border-bottom:1px solid rgba(255,255,255,.1);backdrop-filter:blur(28px)}
.toast{background:rgba(10,17,30,.94);color:#eaf4ff;border-color:rgba(255,255,255,.15);border-left:3px solid #5df0b0;backdrop-filter:blur(24px)}
.modal-backdrop{background:rgba(1,4,11,.72);backdrop-filter:blur(18px)}.modal{background:rgba(10,17,30,.92)!important;border-color:rgba(99,231,255,.25)!important}
.login-page{background:transparent}.login-card{background:linear-gradient(145deg,rgba(18,29,49,.82),rgba(7,12,23,.78))!important;border-color:rgba(99,231,255,.25)!important}
.login-card:after{content:"";position:absolute;right:28px;top:25px;width:76px;height:76px;border-radius:50%;background:radial-gradient(circle at 32% 25%,#e8ffff 0 3%,#79eaff 10%,#267bc6 35%,#282c80 64%,#080d28 100%);box-shadow:0 0 25px rgba(67,218,255,.45),0 0 70px rgba(89,113,255,.25);animation:orbFloat 4s ease-in-out infinite}
.login-card h1{color:#f4f8ff}.login-card p,.muted,.small{color:#91a0b8}
.badge.success,.health.green{color:#5df0b0}.badge.danger,.health.red{color:#ff667e}.badge.warning,.health.yellow{color:#ffd783}
@keyframes blobDrift{to{transform:translate3d(5vw,4vh,0) scale(1.08)}}@keyframes orbFloat{50%{transform:translateY(-8px)}}@keyframes cardRise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}

.btn-secondary,.btn-quiet{background:rgba(255,255,255,.06)!important;border-color:rgba(255,255,255,.15)!important;color:#dce7f7!important;box-shadow:none}
.btn-danger{background:linear-gradient(115deg,#ff8798,#ff5c7c)!important;border-color:rgba(255,255,255,.24)!important;color:#26070e!important}
.btn-primary{background:linear-gradient(115deg,#47dff5,#648bff 52%,#8272ff)!important;color:#06101d!important}
.card-title,.brand-name,.login-card h1{color:#f4f8ff}
.table-wrap{border:1px solid rgba(255,255,255,.1);border-radius:16px;background:rgba(3,8,18,.35)}
.alert{background:rgba(99,231,255,.08);border:1px solid rgba(99,231,255,.2);color:#cdefff}
.badge.info{color:#63e7ff}.badge.purple{color:#a77aff}

/* Dark navy / glass visual system */
:root{--bg:#03050a;--surface:rgba(13,20,34,.72);--surface-2:#0b1423;--bd:rgba(151,177,218,.16);--text:#f4f8ff;--text-1:#dce7f7;--text-2:#91a0b8;--blue:#63e7ff;--blue-2:#4a9eff}
body{background:radial-gradient(ellipse at 18% 0%,rgba(36,94,153,.14),transparent 38%),radial-gradient(ellipse at 90% 12%,rgba(110,69,180,.12),transparent 32%),#03050a;color:#f4f8ff}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.12;background-image:linear-gradient(rgba(125,165,220,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(125,165,220,.08) 1px,transparent 1px);background-size:42px 42px;z-index:0}
.sidebar{background:rgba(7,13,24,.86);border-color:var(--bd);box-shadow:12px 0 42px rgba(0,0,0,.2)}.brand-name{color:#f4f8ff}.brand-sub,.nav-label{color:#8093b1}.nav-item{color:#9aabc5}.nav-item:hover{background:rgba(99,231,255,.08);color:#dffaff}.nav-item.active{background:linear-gradient(90deg,rgba(99,231,255,.16),rgba(84,136,255,.07));color:#8cecff}
.main{position:relative;z-index:1}.topbar{background:rgba(5,10,19,.82);border-color:var(--bd);backdrop-filter:blur(24px)}.crumb{color:#8fa2c0}.top-user{color:#e4efff}.avatar{background:rgba(99,231,255,.15);border-color:rgba(99,231,255,.3);color:#8cecff}
.page-title,.card-title,.modal-title{color:#f4f8ff}.page-sub,.stat-note,.card-sub,.muted{color:#8ea0bc}.card{background:linear-gradient(145deg,rgba(16,27,45,.86),rgba(8,15,27,.78));border-color:rgba(150,180,225,.15);box-shadow:0 12px 40px rgba(0,0,0,.16);backdrop-filter:blur(18px)}.card:hover{border-color:rgba(99,231,255,.35);box-shadow:0 16px 42px rgba(0,0,0,.24)}.stat-label{color:#8ea4c4}.stat-value{color:#f4f8ff}.kv-item{background:rgba(255,255,255,.035);border-color:var(--bd)}.kv-label{color:#91a4c0}.kv-value{color:#edf5ff}
.btn-secondary{background:rgba(255,255,255,.055);border-color:var(--bd);color:#dce8fa}.btn-secondary:hover{background:rgba(99,231,255,.1);border-color:rgba(99,231,255,.4);color:#fff}.btn-primary{background:linear-gradient(110deg,#42d9f4,#588dff);color:#04101c}.btn-primary:hover{background:linear-gradient(110deg,#76eaff,#7ca8ff)}.btn-danger{background:rgba(255,102,126,.1);border-color:rgba(255,102,126,.28);color:#ff91a4}.btn-quiet{color:#9eb0ca}.btn-quiet:hover{background:rgba(255,255,255,.07);color:#fff}
.input,.select,.textarea{background:rgba(4,10,19,.78);border-color:rgba(150,180,225,.2);color:#edf5ff}.input::placeholder,.textarea::placeholder{color:#7185a4}.input:focus,.select:focus,.textarea:focus{border-color:#63e7ff;box-shadow:0 0 0 3px rgba(99,231,255,.12)}.table-wrap{background:rgba(5,11,20,.65);border-color:var(--bd)}.data-table thead{background:#0d192b}.data-table th{color:#8ea4c4;border-color:var(--bd)}.data-table td{color:#d1def1;border-color:rgba(150,180,225,.1)}.data-table tbody tr:hover td{background:rgba(99,231,255,.055)}.mono{color:#b7d6ef}
.badge.success{background:rgba(93,240,176,.1);color:#75f2bc;border-color:rgba(93,240,176,.25)}.badge.danger{background:rgba(255,102,126,.1);color:#ff91a4;border-color:rgba(255,102,126,.25)}.badge.warning{background:rgba(255,215,131,.1);color:#ffd783;border-color:rgba(255,215,131,.25)}.badge.neutral{background:rgba(151,177,218,.08);color:#a9bad3;border-color:var(--bd)}.progress{background:rgba(255,255,255,.08)}.progress>span{background:linear-gradient(90deg,#63e7ff,#728dff)}
.modal-backdrop{background:rgba(0,3,10,.78);backdrop-filter:blur(10px)}.modal{background:linear-gradient(145deg,#111e31,#08111f);border-color:var(--bd);color:#dce8fa}.modal-body{color:#a9bad3}.toast{color:#edf5ff;background:rgba(9,18,31,.96)}.alert{background:rgba(255,215,131,.08);border-color:rgba(255,215,131,.2);color:#ffd783}.alert.error{background:rgba(255,102,126,.08);border-color:rgba(255,102,126,.24);color:#ff9bad}.login-page{background:radial-gradient(circle at 25% 20%,rgba(99,231,255,.12),transparent 34%),radial-gradient(circle at 80% 80%,rgba(120,100,255,.12),transparent 32%),#03050a}.login-card{background:rgba(12,21,36,.9);border:1px solid var(--bd);box-shadow:0 30px 100px rgba(0,0,0,.4);color:#f4f8ff}.login-card h1{color:#fff}.login-card p{color:#9aabc5}
.chart-box{height:250px;position:relative}.module-list{display:grid;gap:12px}.module-row{display:grid;gap:6px}.module-label{display:flex;justify-content:space-between;gap:10px;color:#dce8fa;font-size:11px}.module-label span{color:#8ea4c4;font:10px 'JetBrains Mono',monospace}.progress.compact{display:inline-block;width:72px;height:5px;vertical-align:middle;margin-right:6px}.pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;padding-top:14px}.pagination button:disabled{opacity:.35;cursor:not-allowed}.broadcast-form{display:flex;gap:10px;flex-wrap:wrap}.broadcast-form .input{flex:1;min-width:220px}.modal-wide{max-width:760px;max-height:85vh;overflow:auto}.detail-line{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--bd);font-size:12px;color:#dce8fa}.detail-line span{color:#91a4c0}.sidebar-foot{color:#8093b1}
@media(max-width:1050px){.sidebar{width:210px}.main{margin-left:210px}.content{padding:24px 20px}.stats.six{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:720px){.sidebar{position:relative;width:auto;height:auto;inset:auto;padding:12px;display:flex;align-items:center;gap:6px;overflow:auto}.brand{flex:0 0 auto;padding:0 12px 0 0}.sidebar .nav-label,.sidebar-foot{display:none}.nav-item{flex:0 0 auto;margin:0}.main{margin-left:0}.topbar{padding:0 14px}.content{padding:18px 12px}.stats,.stats.six,.two,.three{grid-template-columns:repeat(2,minmax(0,1fr))}.page-head{flex-direction:column}.chart-box{height:210px}}@media(max-width:440px){.stats,.stats.six,.two,.three{grid-template-columns:1fr}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}}

/* LC79 Admin Pro - consistent deep navy interface */
:root{color-scheme:dark;--bg:#070d17;--surface:#101b2b;--bd:rgba(148,163,184,.16);--text:#e7eef8;--text-2:#91a3ba}
html,body{background:#070d17!important;color:#e7eef8!important}body:before{opacity:.06!important}
.sidebar{background:#0a1321!important;border-right:1px solid rgba(148,163,184,.14)!important}
.topbar{background:rgba(7,13,23,.94)!important;border-bottom:1px solid rgba(148,163,184,.14)!important}
.card{background:#101b2b!important;border:1px solid rgba(148,163,184,.14)!important;border-radius:15px!important;box-shadow:0 8px 28px rgba(0,0,0,.16)!important}
.card:hover{transform:translateY(-1px);border-color:rgba(34,211,238,.28)!important}
.page-title{font-size:25px!important;letter-spacing:-.04em!important}.page-sub,.card-sub,.stat-note{color:#8fa2ba!important}
.stat-value{font-size:27px!important;font-variant-numeric:tabular-nums}.stat-label{font-size:10px!important;letter-spacing:.07em;text-transform:uppercase;color:#8fa2ba!important}
.btn{border-radius:9px!important;font-weight:700!important}.btn-primary{background:#22c5dd!important;color:#06202a!important;border-color:#22c5dd!important}.btn-secondary,.btn-quiet{background:#17263a!important;color:#d5e1ef!important;border-color:rgba(148,163,184,.2)!important}.btn-danger{background:#3a1b27!important;color:#ff9aaa!important;border-color:rgba(248,113,113,.25)!important}
.input,.select,.textarea{background:#091321!important;color:#e7eef8!important;border:1px solid rgba(148,163,184,.2)!important;border-radius:9px!important}.input:focus,.select:focus,.textarea:focus{border-color:#22c5dd!important;box-shadow:0 0 0 3px rgba(34,197,221,.1)!important}
.table-wrap{background:#0b1523!important;border:1px solid rgba(148,163,184,.15)!important;border-radius:12px!important}.data-table thead{background:#142238!important}.data-table th{font-size:9px!important;text-transform:uppercase;letter-spacing:.07em;color:#91a5be!important}.data-table td{font-size:11px!important}.data-table tbody tr:hover td{background:rgba(34,197,221,.045)!important}
.badge.success{background:rgba(34,197,94,.12)!important;color:#4ade80!important;border-color:rgba(34,197,94,.24)!important}.badge.danger{background:rgba(248,113,113,.12)!important;color:#f87171!important;border-color:rgba(248,113,113,.24)!important}.badge.warning{background:rgba(251,191,36,.12)!important;color:#fbbf24!important}
/* Explicit semantic colors: prediction side and resolution status */
.side-tai{color:#f87171!important;font-weight:800!important}.side-xiu{color:#67e8f9!important;font-weight:800!important}.result-win{color:#4ade80!important;font-weight:800!important}.result-lose{color:#f87171!important;font-weight:800!important}
.chart-box{height:235px!important}.module-row{padding:7px 0;border-bottom:1px solid rgba(148,163,184,.08)}.module-label{font-size:11px!important}.progress{height:7px!important;border-radius:10px!important;overflow:hidden}.progress>span{background:linear-gradient(90deg,#22c5dd,#648bff)!important}
.toolbar{gap:9px!important}.pagination{border-top:1px solid rgba(148,163,184,.1);margin-top:10px;padding-top:14px}
.modal{background:#101b2b!important;border:1px solid rgba(148,163,184,.2)!important;border-radius:16px!important}.modal-backdrop{background:rgba(0,0,0,.72)!important}
.health.green{background:#4ade80!important}.health.red{background:#f87171!important}.health.yellow{background:#fbbf24!important}
.page-head .actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
@media(max-width:720px){.stats.six{grid-template-columns:repeat(2,minmax(0,1fr))!important}.page-title{font-size:21px!important}.page-head .actions{width:100%}.page-head .actions .btn,.page-head .actions form{flex:1}.page-head .actions form button{width:100%}.chart-box{height:200px!important}}
@media(max-width:440px){.stats.six{grid-template-columns:repeat(2,minmax(0,1fr))!important}.stat-value{font-size:22px!important}.content{padding:14px 10px!important}}

</style>'''

BASE = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · LC79</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>''' + CSS + r'''</head><body><div class="shell"><aside class="sidebar"><a class="brand" href="/admin"><div class="brand-mark">P</div><div><div class="brand-name">P A W</div><div class="brand-sub">LC79 CONTROL</div></div></a><div class="nav-label">Điều khiển</div>
<a class="nav-item {{'active' if active=='dashboard' else ''}}" href="/admin"><span>◈</span><span>Dashboard</span></a>
<a class="nav-item {{'active' if active=='hu' else ''}}" href="/admin/hu"><span>◉</span><span>Bàn Hũ</span></a>
<a class="nav-item {{'active' if active=='md5' else ''}}" href="/admin/md5"><span>⬡</span><span>Bàn MD5</span></a>
<a class="nav-item {{'active' if active=='keys' else ''}}" href="/admin/keys"><span>⚿</span><span>Keys</span></a>
<a class="nav-item {{'active' if active=='codes' else ''}}" href="/admin/codes"><span>▤</span><span>Codes</span></a>
<a class="nav-item {{'active' if active=='logs' else ''}}" href="/admin/logs"><span>◷</span><span>Logs</span></a>
<a class="nav-item {{'active' if active=='settings' else ''}}" href="/admin/settings"><span>⚙</span><span>Settings</span></a><div class="sidebar-foot">PAW · Hệ thống LC79<br>Phiên quản trị bảo mật</div></aside><main class="main"><header class="topbar"><button class="mobile-nav-toggle" type="button" aria-label="Mở menu" onclick="document.body.classList.toggle('sidebar-open')">☰</button><div class="crumb">Không gian quản trị <span class="muted">/</span> {{ title }}</div><div class="quick-nav"><input id="adminQuickNav" type="search" list="adminQuickNavOptions" placeholder="Tìm nhanh trang quản trị…  ↵" aria-label="Tìm nhanh trang quản trị"><datalist id="adminQuickNavOptions"><option value="Dashboard"><option value="Bàn Hũ"><option value="Bàn MD5"><option value="Keys"><option value="Codes"><option value="Logs"><option value="Cài đặt"></datalist></div><div class="top-user"><span class="health green"></span><span>{{ admin_user }}</span><a class="btn btn-quiet btn-sm" href="/admin/logout">Đăng xuất</a></div></header><section class="content">{{ body|safe }}</section></main></div><div class="toast-stack" id="toasts"></div><script>
function toast(message,type='success'){const el=document.createElement('div');el.className='toast '+(type==='error'?'error':'');el.textContent=message;document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),type==='error'?5000:3000)}
function copyText(value){navigator.clipboard.writeText(value).then(()=>toast('Đã sao chép')).catch(()=>toast('Không thể sao chép','error'))}
function openModal(id){document.getElementById(id)?.classList.add('open')}
function closeModal(id){document.getElementById(id)?.classList.remove('open')}
function confirmAction(message){return window.confirm(message)}
(function(){
 const nav=document.getElementById('adminQuickNav');
 if(nav){
  const routes={'dashboard':'/admin','bàn hũ':'/admin/hu','hu':'/admin/hu','bàn md5':'/admin/md5','md5':'/admin/md5','keys':'/admin/keys','key':'/admin/keys','codes':'/admin/codes','mã':'/admin/codes','logs':'/admin/logs','nhật ký':'/admin/logs','cài đặt':'/admin/settings','settings':'/admin/settings'};
  nav.addEventListener('keydown',e=>{
   if(e.key!=='Enter')return;
   const q=nav.value.trim().toLocaleLowerCase('vi');
   const target=routes[q]||Object.entries(routes).find(([k])=>k.includes(q)||q.includes(k))?.[1];
   if(target){location.href=target}else{nav.setCustomValidity('Không tìm thấy trang quản trị phù hợp');nav.reportValidity();nav.setCustomValidity('')}
  });
 }
 document.querySelectorAll('.sidebar .nav-item').forEach(a=>a.addEventListener('click',()=>document.body.classList.remove('sidebar-open')));
 document.addEventListener('keydown',e=>{if(e.key==='Escape')document.body.classList.remove('sidebar-open')});
})();
function filterRows(inputId,tableId){const q=document.getElementById(inputId).value.toLowerCase();document.querySelectorAll('#'+tableId+' tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}
if(location.pathname==="/admin")setInterval(()=>{if(!document.hidden)location.reload()},15000);
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
    activity=conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 20").fetchall()
    resolved=conn.execute("SELECT COUNT(*) n,SUM(result='win') wins,SUM(result='lose') losses FROM predictions WHERE result IS NOT NULL").fetchone()
    daily=conn.execute("SELECT date(created_at) d,COUNT(*) n FROM predictions WHERE created_at>=datetime('now','-14 days') GROUP BY date(created_at) ORDER BY d").fetchall()
    by_table=conn.execute("SELECT table_code,COUNT(*) n FROM predictions GROUP BY table_code").fetchall()
    conn.close()
    decided=int(resolved['n'] or 0); wins_all=int(resolved['wins'] or 0); accuracy_all=(wins_all/decided*100) if decided else 0
    cards=''.join(f'<div class="card"><div class="stat-label">{label}</div><div class="stat-value">{value}</div><div class="stat-note">{note}</div></div>' for label,value,note in (("Tổng số key",f"{total_keys:,}","Key đã phát hành"),("Key đang hoạt động",f"{active_keys:,}","Chưa thu hồi / chưa hết hạn"),("Mã còn khả dụng",f"{active_codes:,}","Mã có thể kích hoạt"),("Tổng dự đoán",f"{total_predictions:,}","Hai bàn LC79"),("Accuracy tổng",f"{accuracy_all:.1f}%",f"{wins_all:,}/{decided:,} phiên phân định"),("Phiên đang chờ",f"{total_predictions-decided:,}","Chưa có kết quả thực tế")))
    dash_data=json.dumps({'days':[str(x['d']) for x in daily],'counts':[int(x['n']) for x in daily],'tables':{x['table_code']:int(x['n']) for x in by_table}},ensure_ascii=False)
    table_html=''
    for t in tables:
        code=t["code"]; acc=accuracy(code,100); health="red" if t["last_poll_error"] else ("green" if t["last_poll_at"] else "yellow")
        n=conn_count_predictions(code)
        table_html+=f'''<div class="card"><div class="card-head"><div><div class="card-title"><span class="health {health}"></span> {t['name']}</div><div class="card-sub mono">{code}</div></div>{badge('Đang chạy' if t['is_active'] else 'Tạm dừng','success' if t['is_active'] else 'warning')}</div><div class="split"><span class="muted small">Độ chính xác 100 kết quả</span><b>{acc*100:.1f}%</b></div><div class="progress" style="margin:10px 0 18px"><span style="width:{acc*100:.1f}%"></span></div><div class="kv"><div class="kv-item"><div class="kv-label">Phiên mới nhất</div><div class="kv-value">{int(t['last_seen_id'] or 0):,}</div></div><div class="kv-item"><div class="kv-label">Dự đoán đã lưu</div><div class="kv-value">{n:,}</div></div></div><div class="actions" style="margin-top:16px"><a class="btn btn-secondary btn-sm" href="{'/admin/hu' if code=='lc79_tx' else '/admin/md5'}">Chi tiết bàn</a></div></div>'''
    timeline=''.join(f'<div class="timeline-item"><div class="timeline-title">{a["action"]} · {a["target"] or "Hệ thống"}</div><div class="timeline-meta">{a["admin_user"] or "Hệ thống"} · {fmt_date(a["created_at"])}</div></div>' for a in activity) or '<div class="empty">Chưa có hoạt động.</div>'
    body=f'''<div class="page-head"><div><div class="page-title">Bảng điều khiển</div><div class="page-sub">Tổng quan hoạt động và trạng thái hai bàn LC79.</div></div><div class="actions"><a class="btn btn-secondary" href="/admin/hu">{svg_icon('refresh',16)} Giám sát hệ thống</a></div></div><div class="grid stats six">{cards}</div><div class="grid two"><div class="card"><div class="card-head"><div><div class="card-title">Lưu lượng dự đoán</div><div class="card-sub">Số phiên được ghi nhận mỗi ngày · 14 ngày</div></div></div><div class="chart-box"><canvas id="dashVolume"></canvas></div></div><div class="card"><div class="card-head"><div><div class="card-title">Phân bổ theo bàn</div><div class="card-sub">Tổng số dự đoán Hũ / MD5</div></div></div><div class="chart-box"><canvas id="dashTables"></canvas></div></div></div><div class="grid two" style="margin-top:18px">{table_html}</div><div class="card" style="margin-top:20px"><div class="card-head"><div><div class="card-title">Hoạt động gần đây</div><div class="card-sub">20 thao tác quản trị mới nhất</div></div><a class="btn btn-quiet btn-sm" href="/admin/logs">Xem nhật ký</a></div><div class="timeline">{timeline}</div></div><script>const DASH={dash_data};if(window.Chart){{new Chart(document.getElementById('dashVolume'),{{type:'bar',data:{{labels:DASH.days,datasets:[{{label:'Số dự đoán',data:DASH.counts,backgroundColor:'rgba(99,231,255,.65)',borderRadius:5}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#a9b8d0'}}}}}},scales:{{x:{{ticks:{{color:'#8294b2'}},grid:{{color:'rgba(255,255,255,.05)'}}}},y:{{ticks:{{color:'#8294b2'}},grid:{{color:'rgba(255,255,255,.05)'}},beginAtZero:true}}}}}}}});new Chart(document.getElementById('dashTables'),{{type:'doughnut',data:{{labels:['Bàn Hũ','Bàn MD5'],datasets:[{{data:[DASH.tables.lc79_tx||0,DASH.tables.lc79_md5||0],backgroundColor:['#63e7ff','#9b8cff'],borderColor:'#0b1423',borderWidth:3}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'bottom',labels:{{color:'#a9b8d0'}}}}}}}}}})}}setTimeout(()=>location.reload(),15000)</script>'''
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
