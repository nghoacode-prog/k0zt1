import os
import sys
import time
import json
import hashlib
import secrets
import string
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    jsonify, make_response
)
from markupsafe import Markup

sys.path.insert(0, os.path.dirname(__file__))
from engine import db, now_iso, init_db, seed_tables

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/var/data/app.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
BRANDING_NAME = os.environ.get("BRANDING_NAME", "P A W")
BRANDING_TELEGRAM = os.environ.get("BRANDING_TELEGRAM", "@K0ZT1")

# ─── AUTO INIT ────────────────────────────────────────────────────────────────

if not os.path.exists(DATABASE_PATH) or os.path.getsize(DATABASE_PATH) == 0:
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    init_db()
    seed_tables()

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def now_dt():
    return datetime.now(timezone.utc)

def iso_to_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

def days_left(expires_at_str):
    if not expires_at_str:
        return None
    dt = iso_to_dt(expires_at_str)
    if not dt:
        return None
    delta = dt - now_dt()
    return max(0, delta.days)

def gen_key(prefix="", length=24):
    chars = string.ascii_uppercase + string.digits
    rand = "".join(secrets.choice(chars) for _ in range(length))
    return (prefix + rand)[:32] if prefix else rand

def gen_code(prefix="TX", length=10):
    chars = string.ascii_uppercase + string.digits
    rand = "".join(secrets.choice(chars) for _ in range(length))
    return prefix + rand

def device_id_from_request():
    did = request.headers.get("X-Device-Id", "").strip()
    if did and len(did) >= 8:
        return did[:64]
    ip = request.remote_addr or ""
    ua = request.headers.get("User-Agent", "")
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]

def parse_ua(ua_string):
    ua = ua_string or ""
    browser = "Unknown"
    os_name = "Unknown"
    if "Chrome" in ua and "Edg" not in ua and "OPR" not in ua:
        browser = "Chrome"
    elif "Firefox" in ua:
        browser = "Firefox"
    elif "Safari" in ua and "Chrome" not in ua:
        browser = "Safari"
    elif "Edg" in ua:
        browser = "Edge"
    elif "OPR" in ua or "Opera" in ua:
        browser = "Opera"
    if "Windows" in ua:
        os_name = "Windows"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Linux" in ua:
        os_name = "Linux"
    elif "Mac" in ua:
        os_name = "macOS"
    return browser, os_name

def wants_html():
    fmt = request.args.get("format", "").lower()
    if fmt == "json":
        return False
    if fmt == "html":
        return True
    accept = request.headers.get("Accept", "")
    return "text/html" in accept and "application/json" not in accept

def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Device-Id"
    return resp

def json_error(code, error, message, status=400):
    resp = make_response(jsonify({"ok": False, "error": error, "message": message}), status)
    return add_cors(resp)

def html_error(title, message, status=400):
    html = render_error_page(title, message)
    return make_response(html, status)

# ─── RATE LIMIT ───────────────────────────────────────────────────────────────

def check_rate_limit(key_str, max_per_minute=30):
    window = str(int(time.time() // 60))
    rl_key = f"rl:{key_str}:{window}"
    conn = db()
    row = conn.execute(
        "SELECT count FROM rate_limits WHERE key=? AND window=?", (rl_key, window)
    ).fetchone()
    count = row["count"] if row else 0
    if count >= max_per_minute:
        conn.close()
        return False
    conn.execute("""
INSERT INTO rate_limits (key, window, count) VALUES (?, ?, 1)
ON CONFLICT(key, window) DO UPDATE SET count=count+1
""", (rl_key, window))
    conn.commit()
    conn.close()
    return True

# ─── DEVICE LOCK ──────────────────────────────────────────────────────────────

def handle_device_lock(key_row):
    """
    Returns (ok, error_msg)
    ok=True: device được phép tiếp tục
    """
    key = key_row["key"]
    max_devices = key_row["max_devices"] or 1
    scope = key_row["scope"] or ""

    if scope == "ADMIN_BYPASS":
        return True, None

    device_id = device_id_from_request()
    ip = request.remote_addr or ""
    ua = request.headers.get("User-Agent", "")
    browser, os_name = parse_ua(ua)
    now = now_iso()

    conn = db()
    active = conn.execute("""
SELECT * FROM api_key_devices WHERE key=? AND released_at IS NULL
""", (key,)).fetchall()
    active = [dict(r) for r in active]

    # Kiểm tra device hiện tại có trong active không
    matched = next((d for d in active if d["device_id"] == device_id), None)

    if matched:
        # Same device → refresh last_seen
        conn.execute(
            "UPDATE api_key_devices SET last_seen=?, ip=? WHERE id=?",
            (now, ip, matched["id"])
        )
        conn.commit()
        conn.close()
        return True, None

    if len(active) < max_devices:
        # Còn slot → lock device mới
        conn.execute("""
INSERT INTO api_key_devices (key, device_id, ip, user_agent, browser, os, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (key, device_id, ip, ua[:500], browser, os_name, now, now))
        conn.commit()
        conn.close()
        return True, None

    # Đủ max → tìm device idle >= 10min để release
    def idle_min(d):
        ls = iso_to_dt(d["last_seen"])
        if not ls:
            return 999
        return (now_dt() - ls).total_seconds() / 60

    idle_candidates = [d for d in active if idle_min(d) >= 10]
    if idle_candidates:
        oldest = min(idle_candidates, key=lambda d: d["last_seen"])
        conn.execute("""
UPDATE api_key_devices SET released_at=?, released_reason='idle_replaced'
WHERE id=?
""", (now, oldest["id"]))
        conn.execute("""
INSERT INTO api_key_devices (key, device_id, ip, user_agent, browser, os, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (key, device_id, ip, ua[:500], browser, os_name, now, now))
        conn.commit()
        conn.close()
        return True, None

    conn.close()
    return False, "Thiết bị này không được phép. Key đang được dùng trên thiết bị khác."

# ─── KEY ACTIVATION ON FIRST USE ──────────────────────────────────────────────

def activate_key_on_first_use(key_row):
    """
    Nếu key chưa được kích hoạt (activated=0, expires_at=NULL),
    set expires_at = now + days khi truy cập lần đầu.
    """
    if key_row["activated"]:
        return
    days = key_row["days"] or 7
    expires_at = (now_dt() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = db()
    conn.execute("""
UPDATE api_keys SET activated=1, expires_at=?, last_used_at=? WHERE key=?
""", (expires_at, now_iso(), key_row["key"]))
    conn.commit()
    conn.close()

# ─── KEY VALIDATION ───────────────────────────────────────────────────────────

def validate_key(key_str, table_code):
    """
    Returns (key_row, error_msg)
    """
    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    conn.close()

    if not row:
        return None, "Key không tồn tại"
    if not row["is_active"]:
        return None, "Key đã bị thu hồi"

    scope = row["scope"]

    # Activate on first use
    activate_key_on_first_use(row)

    # Re-read sau khi activate để có expires_at mới
    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    conn.close()

    # Kiểm tra hạn (chỉ sau khi activated=1)
    if row["activated"] and row["expires_at"]:
        dt = iso_to_dt(row["expires_at"])
        if dt and dt < now_dt():
            return None, "Key đã hết hạn"

    # Kiểm tra scope
    if scope == "ADMIN_BYPASS":
        pass
    elif scope == "ALL":
        if not table_code:
            return None, "Cần chỉ định ?table=lc79_tx hoặc lc79_md5"
    else:
        if table_code and scope != table_code:
            return None, f"Key này không có quyền truy cập bàn {table_code}"

    # Update last_used
    conn = db()
    conn.execute("UPDATE api_keys SET last_used_at=? WHERE key=?", (now_iso(), key_str))
    conn.commit()
    conn.close()

    return row, None

# ─── ADMIN AUTH ───────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

def log_admin_action(action, target, detail=None):
    conn = db()
    conn.execute("""
INSERT INTO admin_actions (admin_user, action, target, detail_json, ip, created_at)
VALUES (?, ?, ?, ?, ?, ?)
""", (
        session.get("admin_user", "admin"),
        action, target,
        json.dumps(detail) if detail else None,
        request.remote_addr,
        now_iso()
    ))
    conn.commit()
    conn.close()

# ─── CSS / JS SHARED ──────────────────────────────────────────────────────────

SHARED_CSS = """
:root {
  --bg: #0a0a0a;
  --surface: #111111;
  --surface2: #1a1a1a;
  --border: #222222;
  --border2: #333333;
  --text: #f0f0f0;
  --text2: #999999;
  --text3: #666666;
  --accent: #fafafa;
  --green: #22c55e;
  --yellow: #eab308;
  --red: #ef4444;
  --blue: #3b82f6;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 14px; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5; }
h1 { font-size: 20px; }
h2 { font-size: 18px; }
h3 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; }
label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text2); }
small { font-size: 12px; }
.mono { font-family: 'SF Mono', 'Fira Code', monospace; }
.big-num { font-size: 32px; font-family: 'SF Mono', monospace; }
a { color: var(--text); text-decoration: none; }
a:hover { color: var(--accent); }
button, .btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500;
  border: 1px solid var(--border2); background: var(--surface2);
  color: var(--text); cursor: pointer;
  transition: color 0.15s ease, background 0.15s ease, opacity 0.15s ease, transform 0.15s ease;
}
button:hover, .btn:hover { background: var(--border); }
button:active, .btn:active { transform: scale(0.97); }
.btn-primary { background: var(--accent); color: #0a0a0a; border-color: var(--accent); }
.btn-primary:hover { background: #e0e0e0; }
.btn-danger { background: #2a0a0a; color: var(--red); border-color: #5a1a1a; }
.btn-danger:hover { background: #3a0a0a; }
.btn-sm { padding: 4px 10px; font-size: 12px; }
input, select, textarea {
  background: var(--surface2); border: 1px solid var(--border2);
  color: var(--text); border-radius: 6px; padding: 8px 12px; font-size: 13px;
  width: 100%;
  transition: border-color 0.15s ease;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--border2); box-shadow: 0 0 0 2px rgba(255,255,255,0.05); }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
.card-sm { padding: 14px 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead { position: sticky; top: 0; background: var(--surface); z-index: 10; }
th { padding: 10px 12px; text-align: left; color: var(--text2); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--surface2); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 500; }
.badge-green { background: rgba(34,197,94,0.1); color: var(--green); border: 1px solid rgba(34,197,94,0.2); }
.badge-red { background: rgba(239,68,68,0.1); color: var(--red); border: 1px solid rgba(239,68,68,0.2); }
.badge-yellow { background: rgba(234,179,8,0.1); color: var(--yellow); border: 1px solid rgba(234,179,8,0.2); }
.badge-gray { background: rgba(255,255,255,0.05); color: var(--text2); border: 1px solid var(--border2); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-green { background: var(--green); animation: pulse-green 2s infinite; }
.dot-yellow { background: var(--yellow); animation: pulse-yellow 1s infinite; }
.dot-red { background: var(--red); animation: pulse-red 0.5s infinite; }
.dot-gray { background: var(--text3); }
@keyframes pulse-green { 0%,100%{opacity:1}50%{opacity:0.5} }
@keyframes pulse-yellow { 0%,100%{opacity:1}50%{opacity:0.4} }
@keyframes pulse-red { 0%,100%{opacity:1}50%{opacity:0.3} }
@keyframes shimmer {
  0%{background-position:-200% 0}
  100%{background-position:200% 0}
}
.skeleton {
  background: linear-gradient(90deg,#131313 0%,#1a1a1a 50%,#131313 100%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 4px; height: 14px;
}
.flex { display: flex; }
.flex-col { flex-direction: column; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.gap-2 { gap: 8px; }
.gap-3 { gap: 12px; }
.gap-4 { gap: 16px; }
.gap-6 { gap: 24px; }
.mt-1 { margin-top: 4px; }
.mt-2 { margin-top: 8px; }
.mt-3 { margin-top: 12px; }
.mt-4 { margin-top: 16px; }
.mt-6 { margin-top: 24px; }
.mb-2 { margin-bottom: 8px; }
.mb-4 { margin-bottom: 16px; }
.w-full { width: 100%; }
.text-center { text-align: center; }
.text-right { text-align: right; }
.text-muted { color: var(--text2); }
.text-green { color: var(--green); }
.text-red { color: var(--red); }
.text-yellow { color: var(--yellow); }
.overflow-x-auto { overflow-x: auto; }
.fab {
  position: fixed; bottom: 20px; right: 20px;
  width: 52px; height: 52px; border-radius: 50%;
  background: linear-gradient(180deg,#fafafa,#e0e0e0);
  color: #0a0a0a; border: none; cursor: pointer;
  box-shadow: 0 4px 16px rgba(0,0,0,0.4);
  display: flex; align-items: center; justify-content: center;
  transition: color 0.15s ease, background 0.15s ease, opacity 0.15s ease, transform 0.15s ease;
}
.fab:hover { transform: translateY(-2px); }
.fab:active { transform: translateY(0) scale(0.95); }
@keyframes fab-spin { to { transform: rotate(360deg); } }
.fab-spinning { animation: fab-spin 0.6s linear; }
#toast-container {
  position: fixed; top: 20px; right: 20px; z-index: 9999;
  display: flex; flex-direction: column; gap: 8px;
}
.toast {
  background: #131313; border-radius: 8px; padding: 12px 16px;
  display: flex; align-items: center; gap: 10px; font-size: 13px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  transform: translateX(120%); transition: transform 0.2s ease;
  min-width: 240px; max-width: 320px;
}
.toast.show { transform: translateX(0); }
.toast-success { border-left: 3px solid var(--green); }
.toast-error { border-left: 3px solid var(--red); }
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.7);
  display: none; align-items: center; justify-content: center;
  z-index: 1000; backdrop-filter: blur(4px);
}
.modal-overlay.open { display: flex; }
.modal-card {
  background: var(--surface); border: 1px solid var(--border2);
  border-radius: 12px; padding: 24px; width: 90%; max-width: 480px;
  animation: modal-in 0.15s ease;
}
@keyframes modal-in { from { opacity:0; transform:scale(0.95); } to { opacity:1; transform:scale(1); } }
.modal-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }
#alert-banner {
  transform: translateY(-100%); transition: transform 0.3s ease;
  background: rgba(255,255,255,0.03); border-left: 3px solid var(--red);
  padding: 10px 16px; display: flex; align-items: center; gap: 10px;
  font-size: 13px;
}
#alert-banner.visible { transform: translateY(0); }
@media (max-width: 767px) {
  .sidebar { transform: translateX(-100%); position: fixed; z-index: 100; height: 100vh; transition: transform 0.2s ease; }
  .sidebar.open { transform: translateX(0); }
  .admin-layout { flex-direction: column; }
  .main-content { padding: 12px; }
  .modal-card { width: 95%; }
  .hide-mobile { display: none; }
  .fab { bottom: 20px; right: 20px; }
}
"""

SHARED_JS = """
function showToast(message, type) {
  type = type || 'success';
  var container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  var t = document.createElement('div');
  t.className = 'toast toast-' + type;
  var icon = type === 'success'
    ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
    : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
  t.innerHTML = icon + '<span>' + message + '</span>';
  container.appendChild(t);
  requestAnimationFrame(function(){ t.classList.add('show'); });
  var delay = type === 'error' ? 5000 : 3000;
  setTimeout(function(){
    t.classList.remove('show');
    setTimeout(function(){ t.remove(); }, 300);
  }, delay);
  t.addEventListener('click', function(){ t.remove(); });
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(function(){
    var orig = btn.innerHTML;
    btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Da copy';
    setTimeout(function(){ btn.innerHTML = orig; }, 1200);
  });
}

function openModal(title, bodyHTML, onConfirm, confirmLabel, isDanger) {
  var overlay = document.getElementById('modal-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'modal-overlay';
    overlay.innerHTML = '<div class="modal-card"><div class="modal-title" id="modal-title"></div><div id="modal-body"></div><div class="modal-actions" id="modal-actions"></div></div>';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function(e){ if(e.target===overlay) closeModal(); });
    document.addEventListener('keydown', function(e){ if(e.key==='Escape') closeModal(); });
  }
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = bodyHTML;
  var actions = document.getElementById('modal-actions');
  actions.innerHTML = '';
  var cancelBtn = document.createElement('button');
  cancelBtn.textContent = 'Dong'; cancelBtn.onclick = closeModal;
  actions.appendChild(cancelBtn);
  if (onConfirm) {
    var confirmBtn = document.createElement('button');
    confirmBtn.textContent = confirmLabel || 'Xac nhan';
    confirmBtn.className = isDanger ? 'btn btn-danger' : 'btn btn-primary';
    confirmBtn.onclick = function(){ onConfirm(); closeModal(); };
    actions.appendChild(confirmBtn);
  }
  overlay.classList.add('open');
}

function closeModal() {
  var overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.classList.remove('open');
}

function openTypeConfirmModal(title, bodyHTML, confirmText, onConfirm, confirmLabel) {
  var body = bodyHTML + '<div class="mt-3"><label>Nhap "' + confirmText + '" de xac nhan</label><input type="text" id="confirm-input" class="mt-1" placeholder="' + confirmText + '"  /></div>';
  openModal(title, body, null, null, true);
  var actions = document.getElementById('modal-actions');
  var confirmBtn = document.createElement('button');
  confirmBtn.textContent = confirmLabel || 'Xac nhan';
  confirmBtn.className = 'btn btn-danger';
  confirmBtn.disabled = true;
  confirmBtn.onclick = function(){ if(!confirmBtn.disabled){ onConfirm(); closeModal(); } };
  actions.appendChild(confirmBtn);
  setTimeout(function(){
    var inp = document.getElementById('confirm-input');
    if (inp) inp.addEventListener('input', function(){
      confirmBtn.disabled = inp.value !== confirmText;
    });
  }, 50);
}

function animateCount(el, from, to, duration) {
  var start = null;
  function step(ts) {
    if (!start) start = ts;
    var progress = Math.min((ts - start) / duration, 1);
    var ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * ease);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
"""

# ─── HTML TEMPLATES ───────────────────────────────────────────────────────────

def render_error_page(title, message):
    return f"""<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Loi - {BRANDING_NAME}</title>
<style>{SHARED_CSS}</style></head>
<body style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px">
<div class="card text-center" style="max-width:420px;width:100%">
<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5" style="margin:0 auto 16px">
<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
</svg>
<h2 style="margin-bottom:8px">{title}</h2>
<p class="text-muted">{message}</p>
<a href="/" class="btn mt-4" style="display:inline-flex">Trang chu</a>
</div></body></html>"""

def render_makey_predict_html(data):
    table_name = data.get("table_name", "")
    phien = data.get("phien", "")
    dudoan = data.get("dudoan", "")
    trangthai = data.get("trangthai", "")
    ketqua = data.get("ketqua", "")
    key_info = data.get("key_info", {})
    expires_at = key_info.get("expires_at", "")
    days_left_val = key_info.get("days_left", "")
    scope = key_info.get("scope", "")
    color = "#22c55e" if dudoan == "TAI" else "#ef4444"

    return f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Du doan - {BRANDING_NAME}</title>
<style>{SHARED_CSS}
.predict-card {{ max-width:420px;margin:0 auto;text-align:center; }}
.side-big {{ font-size:56px;font-weight:900;letter-spacing:0.05em;color:{color}; }}
.conf-bar {{ height:6px;background:var(--surface2);border-radius:3px;overflow:hidden;margin:12px 0; }}
.conf-fill {{ height:100%;background:{color};border-radius:3px; }}
</style></head>
<body style="min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;">
<div id="toast-container"></div>
<div class="predict-card w-full">
  <p class="text-muted mb-2" style="font-size:12px">{BRANDING_NAME} &middot; {BRANDING_TELEGRAM}</p>
  <div class="card mb-4">
    <label>{table_name}</label>
    <div class="side-big mt-2">{dudoan}</div>
    <p class="text-muted mt-1">Phien #{phien}</p>
    <div class="conf-bar mt-3">
      <div class="conf-fill" style="width:{data.get('confidence',65)}%"></div>
    </div>
    <p style="font-size:12px;color:var(--text2)">Do tin cay: {data.get('confidence',65)}%</p>
    {'<div class="mt-3"><span class="badge badge-green">Dang doi ket qua</span></div>' if ketqua == 'chuacoketqua' else f'<div class="mt-3"><span class="badge {"badge-green" if "win" in trangthai else "badge-red"}">{ketqua}</span></div>'}
  </div>
  <div class="card card-sm mb-4" style="text-align:left">
    <div class="flex justify-between" style="font-size:12px">
      <span class="text-muted">Scope</span><span>{scope}</span>
    </div>
    <div class="flex justify-between mt-2" style="font-size:12px">
      <span class="text-muted">Het han</span><span>{expires_at[:10] if expires_at else 'Chua kich hoat'}</span>
    </div>
    <div class="flex justify-between mt-2" style="font-size:12px">
      <span class="text-muted">Con lai</span><span>{f'{days_left_val} ngay' if days_left_val is not None else '--'}</span>
    </div>
  </div>
  <p class="text-muted" style="font-size:11px">Tu dong lam moi sau 60 giay</p>
</div>
<button class="fab" id="fab-refresh" title="Lam moi" onclick="refreshPage()">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
</svg></button>
<script>{SHARED_JS}
var refreshTimer = setTimeout(function(){{ window.location.reload(); }}, 60000);
function refreshPage() {{
  var btn = document.getElementById('fab-refresh');
  var svg = btn.querySelector('svg');
  svg.style.animation = 'fab-spin 0.6s linear';
  clearTimeout(refreshTimer);
  setTimeout(function(){{ window.location.reload(); }}, 300);
}}
</script></body></html>"""

def render_makey_history_html(data):
    table_name = data.get("table_name", "")
    items = data.get("items", [])
    rows = ""
    for item in items:
        phien = item.get("phien", "")
        dudoan = item.get("dudoan", "")
        ketqua = item.get("ketqua", "")
        trangthai = item.get("trangthai", "")
        is_win = "win" in trangthai
        badge_class = "badge-green" if is_win else "badge-red"
        win_svg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>'
        lose_svg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        icon = win_svg if is_win else lose_svg
        rows += f"""<tr>
<td class="mono" style="font-size:12px">{phien}</td>
<td><span style="font-weight:600;color:{'#22c55e' if dudoan=='TAI' else '#ef4444'}">{dudoan}</span></td>
<td>{ketqua}</td>
<td><span class="badge {badge_class}" style="display:inline-flex;align-items:center;gap:4px">{icon} {'Thang' if is_win else 'Thua'}</span></td>
</tr>"""

    return f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Lich su - {BRANDING_NAME}</title>
<style>{SHARED_CSS}</style></head>
<body style="padding:20px;max-width:600px;margin:0 auto">
<div id="toast-container"></div>
<div class="flex justify-between items-center mb-4">
  <div>
    <h2>{table_name}</h2>
    <p class="text-muted" style="font-size:12px">{BRANDING_NAME} &middot; {BRANDING_TELEGRAM}</p>
  </div>
  <span class="badge badge-gray">{data.get('count',0)} phien</span>
</div>
<div class="card" style="padding:0;overflow:hidden">
<div class="overflow-x-auto">
<table>
<thead><tr>
<th>Phien</th><th>Du doan</th><th>Ket qua</th><th>Trang thai</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</div></div>
<script>{SHARED_JS}</script></body></html>"""

def render_activate_html(key, expires_at, days, table, action="activated"):
    makey_url = f"/makey?key={key}&table={table}" if table != "ALL" else f"/makey?key={key}"
    msg = f"Da kich hoat thanh cong. Key co hieu luc {days} ngay ke tu lan truy cap dau tien." if action == "activated" else f"Da gia han them {days} ngay. Het han moi: {expires_at}"
    return f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Kich hoat - {BRANDING_NAME}</title>
<style>{SHARED_CSS}</style></head>
<body style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px">
<div id="toast-container"></div>
<div class="card" style="max-width:480px;width:100%;text-align:center">
<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="1.5" style="margin:0 auto 16px">
<circle cx="12" cy="12" r="10"/><polyline points="20 6 9 17 4 12"/>
</svg>
<h2 style="margin-bottom:8px">{'Kich hoat thanh cong' if action=='activated' else 'Gia han thanh cong'}</h2>
<p class="text-muted mb-4" style="font-size:13px">{msg}</p>
<div class="card card-sm mb-3" style="text-align:left;background:var(--surface2)">
  <label>Key cua ban</label>
  <div class="flex items-center gap-2 mt-1">
    <code class="mono" style="font-size:13px;flex:1;word-break:break-all">{key}</code>
    <button class="btn btn-sm" onclick="copyText('{key}',this)">Copy</button>
  </div>
</div>
<div class="card card-sm mb-3" style="text-align:left;background:var(--surface2)">
  <label>Makey URL</label>
  <div class="flex items-center gap-2 mt-1">
    <code class="mono" style="font-size:12px;flex:1;word-break:break-all">{makey_url}</code>
    <button class="btn btn-sm" onclick="copyText('{makey_url}',this)">Copy</button>
  </div>
</div>
<p class="text-muted mt-3" style="font-size:12px">
  Het han: {expires_at if expires_at else 'Tinh tu lan truy cap dau tien'}
</p>
<a href="{makey_url}" class="btn btn-primary mt-4">Mo makey</a>
</div>
<script>{SHARED_JS}</script></body></html>"""

def render_admin_layout(title, content, active_menu=""):
    menu_items = [
        ("dashboard", "/admin", "Tong quan", '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>'),
        ("keys", "/admin/keys", "API Keys", '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>'),
        ("codes", "/admin/codes", "Ma kich hoat", '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>'),
        ("monitor", "/admin/monitor", "Monitor", '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'),
        ("logs", "/admin/logs", "Nhat ky", '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>'),
    ]
    menu_html = ""
    for key, href, label, icon in menu_items:
        active_class = "style='background:var(--surface2);color:var(--text)'" if active_menu == key else "style='color:var(--text2)'"
        menu_html += f"""<a href="{href}" {active_class} style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;font-size:13px;text-decoration:none;transition:color 0.15s ease,background 0.15s ease">{icon}{label}</a>"""

    return f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{title} - Admin {BRANDING_NAME}</title>
<style>{SHARED_CSS}
.admin-layout {{ display:flex;min-height:100vh; }}
.sidebar {{ width:200px;background:var(--surface);border-right:1px solid var(--border);padding:20px 12px;flex-shrink:0;display:flex;flex-direction:column;gap:4px; }}
.sidebar-logo {{ font-size:16px;font-weight:700;padding:8px 12px;margin-bottom:12px; }}
.main-content {{ flex:1;padding:24px;overflow-x:auto; }}
.page-header {{ display:flex;justify-content:space-between;align-items:center;margin-bottom:24px; }}
</style></head>
<body>
<div id="toast-container"></div>
<div id="modal-overlay" class="modal-overlay">
  <div class="modal-card">
    <div class="modal-title" id="modal-title"></div>
    <div id="modal-body"></div>
    <div class="modal-actions" id="modal-actions"></div>
  </div>
</div>
<div class="admin-layout">
  <div class="sidebar" id="sidebar">
    <div class="sidebar-logo">{BRANDING_NAME}</div>
    {menu_html}
    <div style="flex:1"></div>
    <a href="/admin/logout" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:6px;font-size:13px;color:var(--text2);text-decoration:none">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
    Dang xuat</a>
  </div>
  <div class="main-content">
    {content}
  </div>
</div>
<script>{SHARED_JS}</script>
</body></html>"""

# ─── PUBLIC ROUTES ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    tg_link = f"https://t.me/{BRANDING_TELEGRAM.lstrip('@')}"
    html = f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{BRANDING_NAME} - Du doan Tai Xiu LC79</title>
<style>{SHARED_CSS}
.hero {{ text-align:center;padding:60px 20px 40px; }}
.hero h1 {{ font-size:32px;font-weight:900;margin-bottom:12px; }}
.cards-grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;max-width:800px;margin:0 auto 40px; }}
.table-card {{ background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px; }}
</style></head>
<body>
<div id="toast-container"></div>
<div style="max-width:900px;margin:0 auto;padding:0 20px">
  <div class="hero">
    <div class="dot dot-green" style="display:inline-block;margin-right:8px"></div>
    <span class="text-muted" style="font-size:12px">He thong dang hoat dong</span>
    <h1 style="margin-top:16px">{BRANDING_NAME}</h1>
    <p class="text-muted" style="max-width:400px;margin:12px auto">Du doan Tai Xiu LC79 chinh xac. Ho tro 2 ban: Ban Hu va Ban MD5.</p>
    <div class="flex gap-3 mt-4" style="justify-content:center">
      <a href="/pricing" class="btn btn-primary">Xem bang gia</a>
      <a href="{tg_link}" target="_blank" class="btn">Lien he {BRANDING_TELEGRAM}</a>
    </div>
  </div>
  <div class="cards-grid">
    <div class="table-card">
      <div class="flex items-center gap-2 mb-3">
        <div class="dot dot-green"></div>
        <h3>Ban Hu</h3>
      </div>
      <p class="text-muted" style="font-size:13px">Du doan Tai Xiu cho ban lc79_tx. Cap nhat moi 60 giay.</p>
      <div class="mt-3 flex gap-2">
        <span class="badge badge-gray">lc79_tx</span>
        <span class="badge badge-green">Dang chay</span>
      </div>
    </div>
    <div class="table-card">
      <div class="flex items-center gap-2 mb-3">
        <div class="dot dot-green"></div>
        <h3>Ban MD5</h3>
      </div>
      <p class="text-muted" style="font-size:13px">Du doan Tai Xiu cho ban lc79_md5. Cap nhat moi 60 giay.</p>
      <div class="mt-3 flex gap-2">
        <span class="badge badge-gray">lc79_md5</span>
        <span class="badge badge-green">Dang chay</span>
      </div>
    </div>
  </div>
  <div class="card text-center" style="max-width:600px;margin:0 auto 40px">
    <h3 class="mb-2">Ban chua co key?</h3>
    <p class="text-muted mb-4" style="font-size:13px">Lien he admin de duoc cap key su dung dich vu.</p>
    <a href="{tg_link}" target="_blank" class="btn btn-primary">Lien he {BRANDING_TELEGRAM}</a>
  </div>
  <div class="text-center text-muted mb-4" style="font-size:12px">
    &copy; 2026 {BRANDING_NAME} &middot; <a href="/pricing">Bang gia</a> &middot; <a href="/support">Ho tro</a>
  </div>
</div>
<script>{SHARED_JS}</script>
</body></html>"""
    return html

@app.route("/pricing")
def pricing():
    tg_link = f"https://t.me/{BRANDING_TELEGRAM.lstrip('@')}"
    html = f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Bang gia - {BRANDING_NAME}</title>
<style>{SHARED_CSS}
.pricing-grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;max-width:800px;margin:0 auto; }}
.pricing-card {{ background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center; }}
.pricing-card.featured {{ border-color:var(--border2); }}
.price {{ font-size:28px;font-weight:900;font-family:monospace; }}
</style></head>
<body style="max-width:900px;margin:0 auto;padding:40px 20px">
<div id="toast-container"></div>
<a href="/" class="btn btn-sm mb-4">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
Trang chu</a>
<div class="text-center mb-6">
  <h1>Bang gia</h1>
  <p class="text-muted mt-2">Chon goi phu hop voi nhu cau cua ban</p>
</div>
<div class="pricing-grid">
  <div class="pricing-card">
    <label>Ban Hu</label>
    <div class="price mt-2">50.000d</div>
    <div class="text-muted" style="font-size:12px">/tuan</div>
    <div class="mt-4" style="font-size:13px;text-align:left">
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Truy cap Ban Hu (lc79_tx)</span>
      </div>
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Cap nhat moi 60 giay</span>
      </div>
      <div class="flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Lich su 50 phien</span>
      </div>
    </div>
  </div>
  <div class="pricing-card">
    <label>Ban MD5</label>
    <div class="price mt-2">50.000d</div>
    <div class="text-muted" style="font-size:12px">/tuan</div>
    <div class="mt-4" style="font-size:13px;text-align:left">
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Truy cap Ban MD5 (lc79_md5)</span>
      </div>
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Cap nhat moi 60 giay</span>
      </div>
      <div class="flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Lich su 50 phien</span>
      </div>
    </div>
  </div>
  <div class="pricing-card featured">
    <label>Combo ca 2 ban</label>
    <div class="price mt-2">80.000d</div>
    <div class="text-muted" style="font-size:12px">/tuan</div>
    <div class="mt-4" style="font-size:13px;text-align:left">
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Truy cap ca 2 ban</span>
      </div>
      <div class="mb-2 flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Tiet kiem 20.000d/tuan</span>
      </div>
      <div class="flex gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" style="flex-shrink:0;margin-top:1px"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Uu tien ho tro</span>
      </div>
    </div>
  </div>
</div>
<div class="text-center mt-6">
  <a href="{tg_link}" target="_blank" class="btn btn-primary">Lien he {BRANDING_TELEGRAM}</a>
</div>
</body></html>"""
    return html

@app.route("/support")
def support():
    tg_link = f"https://t.me/{BRANDING_TELEGRAM.lstrip('@')}"
    html = f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Ho tro - {BRANDING_NAME}</title>
<style>{SHARED_CSS}
.faq-item {{ border-bottom:1px solid var(--border);padding:16px 0; }}
.faq-q {{ font-weight:600;margin-bottom:6px; }}
.faq-a {{ color:var(--text2);font-size:13px; }}
</style></head>
<body style="max-width:700px;margin:0 auto;padding:40px 20px">
<a href="/" class="btn btn-sm mb-4">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
Trang chu</a>
<h1 class="mb-4">Ho tro</h1>
<div class="card mb-4">
  <div class="faq-item" style="padding-top:0">
    <div class="faq-q">Key cua toi khong hoat dong?</div>
    <div class="faq-a">Kiem tra xem key da duoc kich hoat chua. Key chi tinh han tu lan truy cap dau tien. Neu van loi, lien he admin.</div>
  </div>
  <div class="faq-item">
    <div class="faq-q">Lam the nao de gia han key?</div>
    <div class="faq-a">Lien he admin qua Telegram de duoc cap ma gia han, sau do dung /makey/activate?code=MA_GIA_HAN&extend=KEY.</div>
  </div>
  <div class="faq-item">
    <div class="faq-q">Du lieu cap nhat bao lau mot lan?</div>
    <div class="faq-a">He thong cap nhat moi 60 giay. Du doan moi se co sau moi phien ket thuc.</div>
  </div>
  <div class="faq-item">
    <div class="faq-q">Toi co the dung key tren may khac khong?</div>
    <div class="faq-a">Tuy vao goi cua ban. Mac dinh 1 thiet bi. Neu thiet bi cu khong su dung qua 10 phut, thiet bi moi co the dang nhap tu dong.</div>
  </div>
  <div class="faq-item" style="border-bottom:none">
    <div class="faq-q">Lien he admin o dau?</div>
    <div class="faq-a">Telegram: <a href="{tg_link}" target="_blank">{BRANDING_TELEGRAM}</a></div>
  </div>
</div>
<div class="text-center">
  <a href="{tg_link}" target="_blank" class="btn btn-primary">Nhan ho tro qua Telegram</a>
</div>
</body></html>"""
    return html

# ─── MAKEY ROUTES ─────────────────────────────────────────────────────────────

@app.route("/makey/activate", methods=["GET", "POST"])
def makey_activate():
    code_str = request.args.get("code", "").strip().upper()
    extend_key = request.args.get("extend", "").strip()

    if not code_str:
        if wants_html():
            return html_error("Thieu ma", "Can cung cap ?code=MA_KICH_HOAT")
        return json_error(400, "missing_code", "Can cung cap ?code=MA_KICH_HOAT")

    conn = db()
    code_row = conn.execute("SELECT * FROM activation_codes WHERE code=?", (code_str,)).fetchone()
    conn.close()

    ip = request.remote_addr or ""
    ua = request.headers.get("User-Agent", "")

    def log_activation(key, success, reason=None):
        conn2 = db()
        conn2.execute("""
INSERT INTO activation_log (key, code, success, ip, user_agent, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
""", (key, code_str, 1 if success else 0, ip, ua[:300], reason, now_iso()))
        conn2.commit()
        conn2.close()

    if not code_row:
        log_activation(extend_key, False, "code_not_found")
        if wants_html():
            return html_error("Ma khong ton tai", "Ma kich hoat khong hop le.")
        return json_error(404, "code_not_found", "Ma kich hoat khong ton tai")

    if code_row["revoked"]:
        log_activation(extend_key, False, "code_revoked")
        if wants_html():
            return html_error("Ma da bi thu hoi", "Ma nay da bi vo hieu hoa.")
        return json_error(400, "code_revoked", "Ma da bi thu hoi")

    if code_row["expires_at"]:
        dt = iso_to_dt(code_row["expires_at"])
        if dt and dt < now_dt():
            log_activation(extend_key, False, "code_expired")
            if wants_html():
                return html_error("Ma da het han", "Ma kich hoat nay da het han.")
            return json_error(400, "code_expired", "Ma kich hoat da het han")

    max_uses = code_row["max_uses"]
    if max_uses != -1 and code_row["used_count"] >= max_uses:
        log_activation(extend_key, False, "code_exhausted")
        if wants_html():
            return html_error("Ma da het luot", "Ma nay da duoc su dung het so luot.")
        return json_error(400, "code_exhausted", "Ma da het luot su dung")

    days = code_row["days"]
    scope = code_row["scope"]

    # Gia han key hien co
    if extend_key:
        conn = db()
        key_row = conn.execute("SELECT * FROM api_keys WHERE key=?", (extend_key,)).fetchone()
        conn.close()
        if not key_row:
            log_activation(extend_key, False, "key_not_found")
            if wants_html():
                return html_error("Key khong ton tai", "Key can gia han khong ton tai.")
            return json_error(404, "key_not_found", "Key khong ton tai")
        if key_row["scope"] != scope and scope != "ALL":
            log_activation(extend_key, False, "scope_mismatch")
            if wants_html():
                return html_error("Scope khong khop", "Ma nay khong ap dung cho key nay.")
            return json_error(400, "scope_mismatch", "Ma kich hoat scope khong khop voi key")

        # Gia han
        if key_row["expires_at"]:
            current_exp = iso_to_dt(key_row["expires_at"])
            if current_exp and current_exp > now_dt():
                new_exp = current_exp + timedelta(days=days)
            else:
                new_exp = now_dt() + timedelta(days=days)
        else:
            new_exp = now_dt() + timedelta(days=days)

        new_exp_str = new_exp.strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = db()
        conn.execute("UPDATE api_keys SET expires_at=?, activated=1 WHERE key=?", (new_exp_str, extend_key))
        conn.execute("UPDATE activation_codes SET used_count=used_count+1 WHERE code=?", (code_str,))
        conn.commit()
        conn.close()

        log_activation(extend_key, True, "extended")
        table_for_url = scope if scope not in ("ALL", "ADMIN_BYPASS") else "lc79_tx"

        if wants_html():
            return render_activate_html(extend_key, new_exp_str, days, table_for_url, action="extended")
        return jsonify({"ok": True, "action": "extended", "key": extend_key, "expires_at": new_exp_str, "days_added": days})

    # Tao key moi
    new_key = gen_key(prefix=scope[:2] if scope not in ("ALL", "ADMIN_BYPASS") else "AK")
    conn = db()
    conn.execute("""
INSERT INTO api_keys (key, scope, note, is_active, expires_at, days, max_devices, created_at, activated)
VALUES (?, ?, ?, 1, NULL, ?, 1, ?, 0)
""", (new_key, scope, f"Activated via code {code_str}", days, now_iso()))
    conn.execute("UPDATE activation_codes SET used_count=used_count+1 WHERE code=?", (code_str,))
    conn.commit()
    conn.close()

    log_activation(new_key, True, "created")
    table_for_url = scope if scope not in ("ALL", "ADMIN_BYPASS") else "lc79_tx"

    if wants_html():
        return render_activate_html(new_key, None, days, table_for_url, action="activated")
    return jsonify({"ok": True, "action": "activated", "key": new_key, "scope": scope, "days": days, "expires_at": None, "note": "Het han tinh tu lan truy cap dau tien"})

@app.route("/makey/check")
def makey_check():
    key_str = request.args.get("key", "").strip()
    if not key_str:
        return json_error(400, "missing_key", "Can cung cap ?key=...")

    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    conn.close()

    if not row:
        return json_error(404, "not_found", "Key khong ton tai")

    activated = bool(row["activated"])
    exp = row["expires_at"]
    dl = days_left(exp) if activated else None
    is_expired = False
    if activated and exp:
        dt = iso_to_dt(exp)
        is_expired = dt is not None and dt < now_dt()

    return jsonify({
        "ok": True,
        "key": key_str,
        "scope": row["scope"],
        "is_active": bool(row["is_active"]),
        "activated": activated,
        "expires_at": exp,
        "days_left": dl,
        "is_expired": is_expired,
        "max_devices": row["max_devices"],
        "note": row["note"],
    })

@app.route("/makey")
def makey():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        return add_cors(resp)

    key_str = request.args.get("key", "").strip()
    table_param = request.args.get("table", "").strip()
    req_type = request.args.get("type", "predict").strip()
    limit = min(int(request.args.get("limit", 50)), 50)

    if not key_str:
        if wants_html():
            return html_error("Thieu key", "Can cung cap ?key=KEY_CUA_BAN")
        return json_error(400, "missing_key", "Can cung cap ?key=KEY_CUA_BAN")

    # Validate key
    key_row, err = validate_key(key_str, table_param if table_param else None)
    if err:
        if wants_html():
            return html_error("Loi xac thuc", err)
        return json_error(401, "auth_error", err)

    scope = key_row["scope"]

    # Xac dinh table
    if not table_param:
        if scope == "ALL":
            if wants_html():
                return html_error("Thieu table", "Vui long chi dinh ?table=lc79_tx hoac lc79_md5")
            return json_error(400, "missing_table", "Can chi dinh ?table=lc79_tx hoac lc79_md5")
        elif scope == "ADMIN_BYPASS":
            table_param = "lc79_tx"
        else:
            table_param = scope

    # Kiem tra table ton tai
    conn = db()
    table_row = conn.execute("SELECT * FROM tables_ WHERE code=?", (table_param,)).fetchone()
    conn.close()
    if not table_row:
        if wants_html():
            return html_error("Ban khong ton tai", f"Ban {table_param} khong ton tai")
        return json_error(404, "table_not_found", f"Ban {table_param} khong ton tai")

    if not table_row["is_active"]:
        if wants_html():
            return html_error("Ban tam dung", f"Ban {table_param} dang tam dung")
        return json_error(503, "table_paused", f"Ban {table_param} dang tam dung")

    # Rate limit (skip ADMIN_BYPASS)
    if scope != "ADMIN_BYPASS":
        if not check_rate_limit(key_str):
            if wants_html():
                return html_error("Qua gioi han", "Qua nhieu yeu cau. Vui long cho 1 phut.")
            return json_error(429, "rate_limited", "Qua nhieu yeu cau, vui long cho 1 phut", 429)

    # Device lock (skip ADMIN_BYPASS)
    if scope != "ADMIN_BYPASS":
        ok, dev_err = handle_device_lock(dict(key_row))
        if not ok:
            if wants_html():
                return html_error("Loi thiet bi", dev_err)
            return json_error(403, "device_locked", dev_err)

    # Kiem tra worker da bootstrap chua
    conn = db()
    state_row = conn.execute("SELECT * FROM table_states WHERE table_code=?", (table_param,)).fetchone()
    conn.close()

    if not state_row or not state_row["last_seen_id"] or state_row["last_seen_id"] == 0:
        if wants_html():
            return html_error("Dang khoi dong", "Worker dang khoi dong, vui long thu lai sau 60 giay")
        resp = make_response(jsonify({"ok": False, "error": "bootstrapping", "message": "Worker dang khoi dong, thu lai sau 60s", "retry_after": 60}), 503)
        return add_cors(resp)

    table_name = table_row["name"]

    if req_type == "history":
        conn = db()
        rows = conn.execute("""
SELECT session_id, prediction, actual, result FROM predictions
WHERE table_code=? AND actual IS NOT NULL
ORDER BY session_id DESC LIMIT ?
""", (table_param, limit)).fetchall()
        conn.close()

        items = []
        for r in rows:
            trangthai = ""
            if r["result"] == "win":
                trangthai = "win\u2705"
            elif r["result"] == "lose":
                trangthai = "lose\u274c"
            items.append({
                "phien": r["session_id"],
                "dudoan": r["prediction"],
                "ketqua": r["actual"] or "",
                "trangthai": trangthai,
            })

        data = {
            "ok": True,
            "table": table_param,
            "table_name": table_name,
            "count": len(items),
            "items": items,
        }

        if wants_html():
            html = render_makey_history_html(data)
            resp = make_response(html)
            return add_cors(resp)
        resp = make_response(jsonify(data))
        return add_cors(resp)

    # predict (default)
    conn = db()
    pred_row = conn.execute("""
SELECT session_id, prediction, actual, result FROM predictions
WHERE table_code=? ORDER BY session_id DESC LIMIT 1
""", (table_param,)).fetchone()
    conn.close()

    if not pred_row:
        if wants_html():
            return html_error("Chua co du doan", "He thong chua co du doan. Vui long thu lai sau 60 giay.")
        resp = make_response(jsonify({"ok": False, "error": "no_prediction", "message": "Chua co du doan, thu lai sau 60s", "retry_after": 60}), 503)
        return add_cors(resp)

    phien = pred_row["session_id"]
    dudoan = pred_row["prediction"]
    actual = pred_row["actual"]
    result = pred_row["result"]

    if actual:
        ketqua = actual
        trangthai = "win\u2705" if result == "win" else "lose\u274c"
    else:
        ketqua = "chuacoketqua"
        trangthai = ""

    # Re-read key sau khi activate de co expires_at moi
    conn = db()
    key_row2 = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    conn.close()
    exp = key_row2["expires_at"] if key_row2 else None
    dl = days_left(exp)

    # Lay confidence
    conn = db()
    conf_row = conn.execute(
        "SELECT confidence FROM predictions WHERE table_code=? AND session_id=?",
        (table_param, phien)
    ).fetchone()
    conn.close()
    confidence = conf_row["confidence"] if conf_row else 65

    data = {
        "ok": True,
        "admin": BRANDING_NAME,
        "telegram": BRANDING_TELEGRAM,
        "table": table_param,
        "table_name": table_name,
        "phien": phien,
        "dudoan": dudoan,
        "ketqua": ketqua,
        "trangthai": trangthai,
        "confidence": confidence,
        "key_info": {
            "scope": scope,
            "expires_at": exp,
            "days_left": dl,
        }
    }

    if wants_html():
        html = render_makey_predict_html(data)
        resp = make_response(html)
        return add_cors(resp)
    resp = make_response(jsonify(data))
    return add_cors(resp)

@app.route("/makey", methods=["OPTIONS"])
def makey_options():
    resp = make_response("", 204)
    return add_cors(resp)

# ─── ADMIN AUTH ROUTES ────────────────────────────────────────────────────────

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["admin_logged_in"] = True
            session["admin_user"] = u
            return redirect(url_for("admin_dashboard"))
        error = "Sai ten dang nhap hoac mat khau"

    html = f"""<!DOCTYPE html><html lang="vi"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Dang nhap Admin - {BRANDING_NAME}</title>
<style>{SHARED_CSS}</style></head>
<body style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px">
<div class="card" style="max-width:360px;width:100%">
  <h2 class="mb-4">{BRANDING_NAME} Admin</h2>
  {'<div class="badge badge-red mb-3" style="display:block">' + error + '</div>' if error else ''}
  <form method="POST">
    <div class="mb-3">
      <label>Ten dang nhap</label>
      <input type="text" name="username" class="mt-1" required autofocus>
    </div>
    <div class="mb-4">
      <label>Mat khau</label>
      <input type="password" name="password" class="mt-1" required>
    </div>
    <button type="submit" class="btn btn-primary w-full">Dang nhap</button>
  </form>
</div>
</body></html>"""
    return html

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

# ─── ADMIN DASHBOARD ──────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = db()
    total_keys = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    active_keys = conn.execute("""
SELECT COUNT(*) FROM api_keys WHERE is_active=1
AND (expires_at IS NULL OR expires_at > ?)
""", (now_iso(),)).fetchone()[0]
    active_codes = conn.execute("SELECT COUNT(*) FROM activation_codes WHERE revoked=0").fetchone()[0]
    total_preds = conn.execute("SELECT COUNT(*) FROM predictions WHERE actual IS NOT NULL").fetchone()[0]
    recent_actions = conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    action_rows = ""
    for a in recent_actions:
        action_rows += f"""<tr>
<td class="mono" style="font-size:11px">{a['created_at'][:19]}</td>
<td>{a['admin_user'] or ''}</td>
<td><span class="badge badge-gray">{a['action'] or ''}</span></td>
<td>{a['target'] or ''}</td>
<td class="text-muted" style="font-size:11px">{a['ip'] or ''}</td>
</tr>"""

    content = f"""
<div class="page-header">
  <h1>Tong quan</h1>
  <a href="/admin/keys/create" class="btn btn-primary" onclick="event.preventDefault();createKeyModal()">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
  Tao key moi</a>
</div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px">
  <div class="card card-sm">
    <label>Tong so key</label>
    <div class="big-num mt-2" id="stat-total-keys">{total_keys}</div>
  </div>
  <div class="card card-sm">
    <label>Key dang hoat dong</label>
    <div class="big-num mt-2 text-green" id="stat-active-keys">{active_keys}</div>
  </div>
  <div class="card card-sm">
    <label>Ma kich hoat</label>
    <div class="big-num mt-2" id="stat-codes">{active_codes}</div>
  </div>
  <div class="card card-sm">
    <label>Du doan da giai</label>
    <div class="big-num mt-2" id="stat-preds">{total_preds}</div>
  </div>
</div>
<div class="card">
  <h3 class="mb-3">Hoat dong gan day</h3>
  <div class="overflow-x-auto">
  <table>
  <thead><tr><th>Thoi gian</th><th>Admin</th><th>Hanh dong</th><th>Muc tieu</th><th>IP</th></tr></thead>
  <tbody>{action_rows if action_rows else '<tr><td colspan="5" class="text-center text-muted">Chua co hoat dong</td></tr>'}</tbody>
  </table>
  </div>
</div>
<div id="modal-create-key" class="modal-overlay">
  <div class="modal-card">
    <div class="modal-title">Tao API key moi</div>
    <div>
      <div class="mb-3">
        <label>Scope</label>
        <select id="ck-scope" class="mt-1">
          <option value="lc79_tx">lc79_tx - Ban Hu</option>
          <option value="lc79_md5">lc79_md5 - Ban MD5</option>
          <option value="ALL">ALL - Ca 2 ban</option>
          <option value="ADMIN_BYPASS">ADMIN_BYPASS</option>
        </select>
      </div>
      <div class="mb-3">
        <label>Ghi chu</label>
        <input type="text" id="ck-note" class="mt-1" placeholder="VD: khach hang A">
      </div>
      <div class="mb-3">
        <label>So ngay (tinh tu lan dung dau tien)</label>
        <input type="number" id="ck-days" class="mt-1" value="7" min="1">
      </div>
      <div class="mb-3">
        <label>So thiet bi toi da</label>
        <input type="number" id="ck-devices" class="mt-1" value="1" min="1">
      </div>
    </div>
    <div class="modal-actions">
      <button onclick="closeCkModal()">Huy</button>
      <button class="btn btn-primary" onclick="submitCreateKey()">Tao key</button>
    </div>
    <div id="ck-result" class="mt-3" style="display:none">
      <div class="card card-sm" style="background:var(--surface2)">
        <label>Key moi</label>
        <div class="flex items-center gap-2 mt-1">
          <code class="mono" id="ck-key-val" style="font-size:12px;flex:1;word-break:break-all"></code>
          <button class="btn btn-sm" onclick="copyText(document.getElementById('ck-key-val').textContent,this)">Copy</button>
        </div>
        <div class="mt-2">
          <label>Makey URL</label>
          <div class="flex items-center gap-2 mt-1">
            <code class="mono" id="ck-url-val" style="font-size:11px;flex:1;word-break:break-all"></code>
            <button class="btn btn-sm" onclick="copyText(document.getElementById('ck-url-val').textContent,this)">Copy</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
function createKeyModal() {{
  document.getElementById('modal-create-key').classList.add('open');
}}
function closeCkModal() {{
  document.getElementById('modal-create-key').classList.remove('open');
  document.getElementById('ck-result').style.display='none';
}}
async function submitCreateKey() {{
  var scope = document.getElementById('ck-scope').value;
  var note = document.getElementById('ck-note').value;
  var days = document.getElementById('ck-days').value;
  var devices = document.getElementById('ck-devices').value;
  var resp = await fetch('/admin/keys/create', {{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{scope,note,days:parseInt(days),max_devices:parseInt(devices)}})
  }});
  var d = await resp.json();
  if (d.ok) {{
    document.getElementById('ck-key-val').textContent = d.key;
    document.getElementById('ck-url-val').textContent = window.location.origin + d.makey_url;
    document.getElementById('ck-result').style.display='block';
    showToast('Tao key thanh cong','success');
  }} else {{
    showToast(d.message || 'Loi','error');
  }}
}}
document.getElementById('modal-create-key').addEventListener('click',function(e){{
  if(e.target===this) closeCkModal();
}});
</script>"""
    return render_admin_layout("Tong quan", content, "dashboard")

# ─── ADMIN KEYS ───────────────────────────────────────────────────────────────

@app.route("/admin/keys")
@admin_required
def admin_keys():
    filter_val = request.args.get("filter", "all")
    q = request.args.get("q", "").strip()

    conn = db()
    rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close()

    rows_html = ""
    for r in rows:
        is_expired = False
        if r["activated"] and r["expires_at"]:
            dt = iso_to_dt(r["expires_at"])
            is_expired = dt is not None and dt < now_dt()

        status = "revoked" if not r["is_active"] else ("expired" if is_expired else "active")
        badge = {"active": "badge-green", "expired": "badge-yellow", "revoked": "badge-red"}.get(status, "badge-gray")
        label = {"active": "Hoat dong", "expired": "Het han", "revoked": "Thu hoi"}.get(status, status)

        rows_html += f"""<tr class="key-row"
  data-status="{status}"
  data-key="{r['key'].lower()}"
  data-note="{(r['note'] or '').lower()}">
<td><a href="/admin/keys/{r['key']}" class="mono" style="font-size:12px">{r['key']}</a></td>
<td><span class="badge badge-gray">{r['scope']}</span></td>
<td>{r['note'] or '<span class="text-muted">-</span>'}</td>
<td><span class="badge {badge}">{label}</span></td>
<td class="text-muted" style="font-size:12px">{"Chua kich hoat" if not r["activated"] else (r['expires_at'][:10] if r['expires_at'] else "-")}</td>
<td class="text-muted" style="font-size:12px">{r['created_at'][:10]}</td>
<td style="text-align:right;opacity:0;transition:opacity 0.15s ease" class="key-actions">
  <a href="/admin/keys/{r['key']}" class="btn btn-sm">Chi tiet</a>
</td>
</tr>"""

    content = f"""
<div class="page-header">
  <h1>API Keys</h1>
  <button class="btn btn-primary" onclick="createKeyModal()">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
  Tao key moi</button>
</div>
<div class="flex gap-3 mb-4">
  <input type="text" id="search-input" placeholder="Tim kiem key hoac ghi chu..." style="max-width:300px" oninput="filterTable()">
  <select id="filter-select" onchange="filterTable()">
    <option value="all">Tat ca</option>
    <option value="active">Hoat dong</option>
    <option value="expired">Het han</option>
    <option value="revoked">Thu hoi</option>
  </select>
</div>
<div class="card" style="padding:0;overflow:hidden">
<div class="overflow-x-auto">
<table>
<thead><tr><th>Key</th><th>Scope</th><th>Ghi chu</th><th>Trang thai</th><th>Het han</th><th>Ngay tao</th><th></th></tr></thead>
<tbody id="keys-table">{rows_html}</tbody>
</table>
</div></div>

<div id="modal-create-key" class="modal-overlay">
  <div class="modal-card">
    <div class="modal-title">Tao API key moi</div>
    <div>
      <div class="mb-3"><label>Scope</label>
        <select id="ck-scope" class="mt-1">
          <option value="lc79_tx">lc79_tx - Ban Hu</option>
          <option value="lc79_md5">lc79_md5 - Ban MD5</option>
          <option value="ALL">ALL - Ca 2 ban</option>
          <option value="ADMIN_BYPASS">ADMIN_BYPASS</option>
        </select></div>
      <div class="mb-3"><label>Ghi chu</label><input type="text" id="ck-note" class="mt-1" placeholder="VD: khach hang A"></div>
      <div class="mb-3"><label>So ngay (tinh tu lan dung dau tien)</label><input type="number" id="ck-days" class="mt-1" value="7" min="1"></div>
      <div class="mb-3"><label>So thiet bi toi da</label><input type="number" id="ck-devices" class="mt-1" value="1" min="1"></div>
    </div>
    <div class="modal-actions">
      <button onclick="closeCkModal()">Huy</button>
      <button class="btn btn-primary" onclick="submitCreateKey()">Tao key</button>
    </div>
    <div id="ck-result" class="mt-3" style="display:none">
      <div class="card card-sm" style="background:var(--surface2)">
        <label>Key moi</label>
        <div class="flex items-center gap-2 mt-1">
          <code class="mono" id="ck-key-val" style="font-size:12px;flex:1;word-break:break-all"></code>
          <button class="btn btn-sm" onclick="copyText(document.getElementById('ck-key-val').textContent,this)">Copy</button>
        </div>
        <div class="mt-2"><label>Makey URL</label>
          <div class="flex items-center gap-2 mt-1">
            <code class="mono" id="ck-url-val" style="font-size:11px;flex:1;word-break:break-all"></code>
            <button class="btn btn-sm" onclick="copyText(document.getElementById('ck-url-val').textContent,this)">Copy</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
function filterTable() {{
  var q = document.getElementById('search-input').value.toLowerCase();
  var f = document.getElementById('filter-select').value;
  document.querySelectorAll('.key-row').forEach(function(tr) {{
    var matchQ = !q || tr.dataset.key.includes(q) || tr.dataset.note.includes(q);
    var matchF = f==='all' || tr.dataset.status===f;
    tr.style.display = (matchQ && matchF) ? '' : 'none';
  }});
}}
document.querySelectorAll('tr.key-row').forEach(function(tr) {{
  tr.addEventListener('mouseenter',function(){{
    var acts = tr.querySelector('.key-actions');
    if(acts) acts.style.opacity='1';
  }});
  tr.addEventListener('mouseleave',function(){{
    var acts = tr.querySelector('.key-actions');
    if(acts) acts.style.opacity='0';
  }});
}});
function createKeyModal() {{
  document.getElementById('modal-create-key').classList.add('open');
}}
function closeCkModal() {{
  document.getElementById('modal-create-key').classList.remove('open');
  document.getElementById('ck-result').style.display='none';
}}
async function submitCreateKey() {{
  var scope=document.getElementById('ck-scope').value;
  var note=document.getElementById('ck-note').value;
  var days=document.getElementById('ck-days').value;
  var devices=document.getElementById('ck-devices').value;
  var resp=await fetch('/admin/keys/create',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{scope,note,days:parseInt(days),max_devices:parseInt(devices)}})}});
  var d=await resp.json();
  if(d.ok){{
    document.getElementById('ck-key-val').textContent=d.key;
    document.getElementById('ck-url-val').textContent=window.location.origin+d.makey_url;
    document.getElementById('ck-result').style.display='block';
    showToast('Tao key thanh cong','success');
  }}else{{showToast(d.message||'Loi','error');}}
}}
document.getElementById('modal-create-key').addEventListener('click',function(e){{if(e.target===this)closeCkModal();}});
</script>"""
    return render_admin_layout("API Keys", content, "keys")

@app.route("/admin/keys/<key_str>")
@admin_required
def admin_key_detail(key_str):
    conn = db()
    key_row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    if not key_row:
        conn.close()
        return html_error("Khong tim thay", "Key khong ton tai"), 404

    devices = conn.execute("""
SELECT * FROM api_key_devices WHERE key=? ORDER BY first_seen DESC LIMIT 10
""", (key_str,)).fetchall()
    conn.close()

    is_expired = False
    if key_row["activated"] and key_row["expires_at"]:
        dt = iso_to_dt(key_row["expires_at"])
        is_expired = dt is not None and dt < now_dt()

    status = "Thu hoi" if not key_row["is_active"] else ("Het han" if is_expired else "Hoat dong")
    status_badge = "badge-red" if not key_row["is_active"] else ("badge-yellow" if is_expired else "badge-green")

    device_rows = ""
    for d in devices:
        is_active = not d["released_at"]
        border = "border:1px solid var(--border2)" if is_active else "border:1px solid var(--border)"
        idle_info = ""
        if is_active and d["last_seen"]:
            ls = iso_to_dt(d["last_seen"])
            if ls:
                idle_secs = (now_dt() - ls).total_seconds()
                idle_info = f"{int(idle_secs//60)} phut truoc"
        device_rows += f"""<div class="card card-sm mb-2" style="{border}">
  <div class="flex justify-between items-center">
    <div>
      <div style="font-size:12px;font-family:monospace">{d['device_id'][:16]}...</div>
      <div class="text-muted" style="font-size:11px">{d['browser'] or ''} / {d['os'] or ''} &middot; {d['ip'] or ''}</div>
      <div class="text-muted" style="font-size:11px">Lan dau: {d['first_seen'][:19] if d['first_seen'] else ''} &middot; {idle_info}</div>
    </div>
    <div>
      {'<span class="badge badge-green">Active</span>' if is_active else f'<span class="badge badge-gray">Released</span>'}
      {('<button class="btn btn-sm mt-1" onclick="unlockDevice(' + str(d["id"]) + ')">Unlock</button>') if is_active else ''}
    </div>
  </div>
</div>"""

    content = f"""
<div class="page-header">
  <div>
    <a href="/admin/keys" class="text-muted" style="font-size:12px">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Keys</a>
    <h1 class="mt-1 mono" style="font-size:16px">{key_str}</h1>
  </div>
  <div class="flex gap-2">
    <button class="btn" onclick="extendModal()">Gia han</button>
    {'<button class="btn btn-danger" onclick="revokeKey()">Thu hoi</button>' if key_row['is_active'] else ''}
    <button class="btn btn-danger" onclick="deleteKey()">Xoa</button>
  </div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
  <div class="card">
    <label>Thong tin key</label>
    <table class="mt-2" style="font-size:13px">
      <tr><td class="text-muted" style="width:120px">Scope</td><td><span class="badge badge-gray">{key_row['scope']}</span></td></tr>
      <tr><td class="text-muted">Trang thai</td><td><span class="badge {status_badge}">{status}</span></td></tr>
      <tr><td class="text-muted">Ghi chu</td><td>{key_row['note'] or '-'}</td></tr>
      <tr><td class="text-muted">Kich hoat</td><td>{'Da kich hoat' if key_row['activated'] else 'Chua kich hoat (tinh han tu lan dau)'}</td></tr>
      <tr><td class="text-muted">Het han</td><td>{key_row['expires_at'][:10] if key_row['expires_at'] else 'Chua tinh'}</td></tr>
      <tr><td class="text-muted">So ngay</td><td>{key_row['days'] or 7} ngay</td></tr>
      <tr><td class="text-muted">Thiet bi</td><td>{key_row['max_devices']}</td></tr>
      <tr><td class="text-muted">Ngay tao</td><td>{key_row['created_at'][:10]}</td></tr>
      <tr><td class="text-muted">Lan dung cuoi</td><td>{key_row['last_used_at'][:19] if key_row['last_used_at'] else '-'}</td></tr>
    </table>
  </div>
  <div class="card">
    <label>Makey URL</label>
    <div class="flex items-center gap-2 mt-2">
      <code class="mono" style="font-size:11px;flex:1;word-break:break-all">/makey?key={key_str}&table={key_row['scope'] if key_row['scope'] not in ('ALL','ADMIN_BYPASS') else 'lc79_tx'}</code>
      <button class="btn btn-sm" onclick="copyText('/makey?key={key_str}&table={key_row['scope'] if key_row['scope'] not in ('ALL','ADMIN_BYPASS') else 'lc79_tx'}',this)">Copy</button>
    </div>
  </div>
</div>
<div class="card mb-4">
  <label>Thiet bi ({len(devices)})</label>
  <div class="mt-3">{device_rows if device_rows else '<p class="text-muted" style="font-size:13px">Chua co thiet bi</p>'}</div>
</div>

<script>
async function revokeKey() {{
  openTypeConfirmModal('Thu hoi key','Thu hoi key nay se khong the su dung duoc nua.','REVOKE',async function(){{
    var r=await fetch('/admin/keys/{key_str}/revoke',{{method:'POST'}});
    var d=await r.json();
    if(d.ok){{showToast('Da thu hoi','success');setTimeout(()=>location.reload(),1000);}}
    else showToast(d.message||'Loi','error');
  }},'Thu hoi');
}}
async function deleteKey() {{
  openTypeConfirmModal('Xoa key','Hanh dong nay khong the hoan tac.','DELETE',async function(){{
    var r=await fetch('/admin/keys/{key_str}/delete',{{method:'POST'}});
    var d=await r.json();
    if(d.ok){{showToast('Da xoa','success');setTimeout(()=>location.href='/admin/keys',1000);}}
    else showToast(d.message||'Loi','error');
  }},'Xoa vinh vien');
}}
function extendModal() {{
  openModal('Gia han key','<div><label>So ngay gia han</label><input type="number" id="ext-days" class="mt-1" value="7" min="1"></div>',async function(){{
    var days=parseInt(document.getElementById('ext-days').value)||7;
    var r=await fetch('/admin/keys/{key_str}/extend',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{days}})}});
    var d=await r.json();
    if(d.ok){{showToast('Da gia han '+days+' ngay','success');setTimeout(()=>location.reload(),1000);}}
    else showToast(d.message||'Loi','error');
  }},'Gia han');
}}
async function unlockDevice(id) {{
  if(!confirm('Unlock thiet bi nay?')) return;
  var r=await fetch('/admin/keys/{key_str}/unlock-device',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{device_id:id}})}});
  var d=await r.json();
  if(d.ok){{showToast('Da unlock','success');setTimeout(()=>location.reload(),800);}}
  else showToast(d.message||'Loi','error');
}}
</script>"""
    return render_admin_layout(f"Key {key_str[:8]}...", content, "keys")

# ─── ADMIN KEY ACTIONS ────────────────────────────────────────────────────────

@app.route("/admin/keys/create", methods=["POST"])
@admin_required
def admin_key_create():
    data = request.get_json() or {}
    scope = data.get("scope", "lc79_tx")
    note = data.get("note", "")
    days = int(data.get("days", 7))
    max_devices = int(data.get("max_devices", 1))

    prefix_map = {"lc79_tx": "TX", "lc79_md5": "MD", "ALL": "AL", "ADMIN_BYPASS": "AB"}
    prefix = prefix_map.get(scope, "KY")
    new_key = gen_key(prefix=prefix, length=24)

    conn = db()
    conn.execute("""
INSERT INTO api_keys (key, scope, note, is_active, expires_at, days, max_devices, created_at, activated)
VALUES (?, ?, ?, 1, NULL, ?, ?, ?, 0)
""", (new_key, scope, note, days, max_devices, now_iso()))
    conn.commit()
    conn.close()

    log_admin_action("create_key", new_key, {"scope": scope, "days": days})

    table_for_url = scope if scope not in ("ALL", "ADMIN_BYPASS") else "lc79_tx"
    makey_url = f"/makey?key={new_key}&table={table_for_url}"

    return jsonify({
        "ok": True,
        "key": new_key,
        "scope": scope,
        "expires_at": None,
        "days": days,
        "max_devices": max_devices,
        "makey_url": makey_url,
    })

@app.route("/admin/keys/<key_str>/extend", methods=["POST"])
@admin_required
def admin_key_extend(key_str):
    data = request.get_json() or {}
    days = int(data.get("days", 7))
    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key_str,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "message": "Key khong ton tai"})

    if row["expires_at"]:
        current = iso_to_dt(row["expires_at"])
        if current and current > now_dt():
            new_exp = current + timedelta(days=days)
        else:
            new_exp = now_dt() + timedelta(days=days)
    else:
        new_exp = now_dt() + timedelta(days=days)

    new_exp_str = new_exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE api_keys SET expires_at=?, activated=1 WHERE key=?", (new_exp_str, key_str))
    conn.commit()
    conn.close()
    log_admin_action("extend_key", key_str, {"days": days, "new_expires": new_exp_str})
    return jsonify({"ok": True, "expires_at": new_exp_str})

@app.route("/admin/keys/<key_str>/revoke", methods=["POST"])
@admin_required
def admin_key_revoke(key_str):
    conn = db()
    conn.execute("UPDATE api_keys SET is_active=0 WHERE key=?", (key_str,))
    conn.commit()
    conn.close()
    log_admin_action("revoke_key", key_str)
    return jsonify({"ok": True})

@app.route("/admin/keys/<key_str>/unlock-device", methods=["POST"])
@admin_required
def admin_unlock_device(key_str):
    data = request.get_json() or {}
    device_id = data.get("device_id")
    conn = db()
    conn.execute("""
UPDATE api_key_devices SET released_at=?, released_reason='admin_unlock'
WHERE key=? AND id=?
""", (now_iso(), key_str, device_id))
    conn.commit()
    conn.close()
    log_admin_action("unlock_device", key_str, {"device_id": device_id})
    return jsonify({"ok": True})

@app.route("/admin/keys/<key_str>/delete", methods=["POST"])
@admin_required
def admin_key_delete(key_str):
    conn = db()
    conn.execute("DELETE FROM api_key_devices WHERE key=?", (key_str,))
    conn.execute("DELETE FROM api_keys WHERE key=?", (key_str,))
    conn.commit()
    conn.close()
    log_admin_action("delete_key", key_str)
    return jsonify({"ok": True})

# ─── ADMIN CODES ──────────────────────────────────────────────────────────────

@app.route("/admin/codes")
@admin_required
def admin_codes():
    conn = db()
    codes = conn.execute("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close()

    rows_html = ""
    for c in codes:
        is_expired = False
        if c["expires_at"]:
            dt = iso_to_dt(c["expires_at"])
            is_expired = dt is not None and dt < now_dt()
        status = "revoked" if c["revoked"] else ("expired" if is_expired else "active")
        badge = {"active": "badge-green", "expired": "badge-yellow", "revoked": "badge-red"}.get(status)
        label = {"active": "Dung duoc", "expired": "Het han", "revoked": "Thu hoi"}.get(status)
        max_use_txt = str(c["max_uses"]) if c["max_uses"] != -1 else "Khong gioi han"
        rows_html += f"""<tr>
<td class="mono" style="font-size:12px">{c['code']}</td>
<td><span class="badge badge-gray">{c['scope']}</span></td>
<td>{c['days']} ngay</td>
<td>{c['used_count']} / {max_use_txt}</td>
<td><span class="badge {badge}">{label}</span></td>
<td class="text-muted" style="font-size:12px">{c['created_at'][:10]}</td>
<td>
  {'<button class="btn btn-sm btn-danger" onclick="revokeCode(\'' + c['code'] + '\')">Thu hoi</button>' if not c['revoked'] else ''}
</td>
</tr>"""

    content = f"""
<div class="page-header">
  <h1>Ma kich hoat</h1>
  <div class="flex gap-2">
    <button class="btn" onclick="openCreateCode()">Tao ma</button>
    <button class="btn btn-primary" onclick="openBulkCode()">Tao hang loat</button>
  </div>
</div>
<div class="card" style="padding:0;overflow:hidden">
<div class="overflow-x-auto">
<table>
<thead><tr><th>Ma</th><th>Scope</th><th>So ngay</th><th>Luot dung</th><th>Trang thai</th><th>Ngay tao</th><th></th></tr></thead>
<tbody>{rows_html if rows_html else '<tr><td colspan="7" class="text-center text-muted">Chua co ma</td></tr>'}</tbody>
</table>
</div></div>

<div id="modal-create-code" class="modal-overlay">
  <div class="modal-card">
    <div class="modal-title">Tao ma kich hoat</div>
    <div>
      <div class="mb-3"><label>Scope</label>
        <select id="cc-scope" class="mt-1">
          <option value="lc79_tx">lc79_tx</option>
          <option value="lc79_md5">lc79_md5</option>
          <option value="ALL">ALL</option>
        </select></div>
      <div class="mb-3"><label>So ngay</label><input type="number" id="cc-days" class="mt-1" value="7" min="1"></div>
      <div class="mb-3"><label>So luot dung (-1 = khong gioi han)</label><input type="number" id="cc-maxuses" class="mt-1" value="-1"></div>
    </div>
    <div class="modal-actions">
      <button onclick="closeCcModal()">Huy</button>
      <button class="btn btn-primary" onclick="submitCreateCode()">Tao</button>
    </div>
    <div id="cc-result" class="mt-3" style="display:none">
      <div class="card card-sm" style="background:var(--surface2)">
        <label>Ma kich hoat</label>
        <div class="flex items-center gap-2 mt-1">
          <code class="mono" id="cc-code-val" style="font-size:14px;flex:1"></code>
          <button class="btn btn-sm" onclick="copyText(document.getElementById('cc-code-val').textContent,this)">Copy</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="modal-bulk-code" class="modal-overlay">
  <div class="modal-card">
    <div class="modal-title">Tao ma hang loat</div>
    <div>
      <div class="mb-3"><label>Scope</label>
        <select id="bc-scope" class="mt-1">
          <option value="lc79_tx">lc79_tx</option>
          <option value="lc79_md5">lc79_md5</option>
          <option value="ALL">ALL</option>
        </select></div>
      <div class="mb-3"><label>So luong</label><input type="number" id="bc-count" class="mt-1" value="10" min="1" max="200"></div>
      <div class="mb-3"><label>So ngay</label><input type="number" id="bc-days" class="mt-1" value="7" min="1"></div>
      <div class="mb-3"><label>So luot dung moi ma</label><input type="number" id="bc-maxuses" class="mt-1" value="1"></div>
    </div>
    <div class="modal-actions">
      <button onclick="closeBcModal()">Huy</button>
      <button class="btn btn-primary" onclick="submitBulkCode()">Tao</button>
    </div>
    <div id="bc-result" class="mt-3" style="display:none">
      <div class="flex justify-between items-center mb-2">
        <label id="bc-count-label"></label>
        <div class="flex gap-2">
          <button class="btn btn-sm" onclick="copyText(document.getElementById('bc-textarea').value,this)">Copy tat ca</button>
          <button class="btn btn-sm" onclick="downloadCodes()">Tai .txt</button>
        </div>
      </div>
      <textarea id="bc-textarea" readonly rows="12" style="font-family:monospace;font-size:12px;width:100%;background:var(--surface2);border:1px solid var(--border2);color:var(--text);border-radius:6px;padding:10px;resize:vertical"></textarea>
    </div>
  </div>
</div>

<script>
function openCreateCode(){{ document.getElementById('modal-create-code').classList.add('open'); }}
function closeCcModal(){{ document.getElementById('modal-create-code').classList.remove('open'); document.getElementById('cc-result').style.display='none'; }}
async function submitCreateCode(){{
  var r=await fetch('/admin/codes/create',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{scope:document.getElementById('cc-scope').value,days:parseInt(document.getElementById('cc-days').value),max_uses:parseInt(document.getElementById('cc-maxuses').value)}})}});
  var d=await r.json();
  if(d.ok){{document.getElementById('cc-code-val').textContent=d.code;document.getElementById('cc-result').style.display='block';showToast('Da tao ma','success');}}
  else showToast(d.message||'Loi','error');
}}
function openBulkCode(){{ document.getElementById('modal-bulk-code').classList.add('open'); }}
function closeBcModal(){{ document.getElementById('modal-bulk-code').classList.remove('open'); document.getElementById('bc-result').style.display='none'; }}
async function submitBulkCode(){{
  var r=await fetch('/admin/codes/bulk',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{scope:document.getElementById('bc-scope').value,count:parseInt(document.getElementById('bc-count').value),days:parseInt(document.getElementById('bc-days').value),max_uses:parseInt(document.getElementById('bc-maxuses').value)}})}});
  var d=await r.json();
  if(d.ok){{
    document.getElementById('bc-count-label').textContent=d.count+' ma';
    document.getElementById('bc-textarea').value=d.codes.join('\\n');
    document.getElementById('bc-result').style.display='block';
    showToast('Da tao '+d.count+' ma','success');
  }}else showToast(d.message||'Loi','error');
}}
function downloadCodes(){{
  var text=document.getElementById('bc-textarea').value;
  var a=document.createElement('a');
  a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(text);
  a.download='activation_codes.txt';
  a.click();
}}
async function revokeCode(code){{
  if(!confirm('Thu hoi ma '+code+'?')) return;
  var r=await fetch('/admin/codes/'+code+'/revoke',{{method:'POST'}});
  var d=await r.json();
  if(d.ok){{showToast('Da thu hoi','success');setTimeout(()=>location.reload(),800);}}
  else showToast(d.message||'Loi','error');
}}
document.getElementById('modal-create-code').addEventListener('click',function(e){{if(e.target===this)closeCcModal();}});
document.getElementById('modal-bulk-code').addEventListener('click',function(e){{if(e.target===this)closeBcModal();}});
</script>"""
    return render_admin_layout("Ma kich hoat", content, "codes")

@app.route("/admin/codes/create", methods=["POST"])
@admin_required
def admin_code_create():
    data = request.get_json() or {}
    scope = data.get("scope", "lc79_tx")
    days = int(data.get("days", 7))
    max_uses = int(data.get("max_uses", -1))
    expires_at = data.get("expires_at")

    prefix_map = {"lc79_tx": "TX", "lc79_md5": "MD", "ALL": "AL"}
    prefix = prefix_map.get(scope, "KY")
    code = gen_code(prefix=prefix)

    conn = db()
    conn.execute("""
INSERT INTO activation_codes (code, scope, days, max_uses, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
""", (code, scope, days, max_uses, expires_at, session.get("admin_user"), now_iso()))
    conn.commit()
    conn.close()
    log_admin_action("create_code", code, {"scope": scope, "days": days})
    return jsonify({"ok": True, "code": code, "scope": scope, "days": days})

@app.route("/admin/codes/bulk", methods=["POST"])
@admin_required
def admin_code_bulk():
    data = request.get_json() or {}
    scope = data.get("scope", "lc79_tx")
    count = min(int(data.get("count", 10)), 200)
    days = int(data.get("days", 7))
    max_uses = int(data.get("max_uses", 1))

    prefix_map = {"lc79_tx": "TX", "lc79_md5": "MD", "ALL": "AL"}
    prefix = prefix_map.get(scope, "KY")

    codes = []
    conn = db()
    for _ in range(count):
        code = gen_code(prefix=prefix)
        conn.execute("""
INSERT OR IGNORE INTO activation_codes (code, scope, days, max_uses, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?)
""", (code, scope, days, max_uses, session.get("admin_user"), now_iso()))
        codes.append(code)
    conn.commit()
    conn.close()
    log_admin_action("bulk_create_code", f"{count} codes", {"scope": scope, "days": days})
    return jsonify({"ok": True, "count": len(codes), "scope": scope, "days": days, "codes": codes})

@app.route("/admin/codes/<code_str>/revoke", methods=["POST"])
@admin_required
def admin_code_revoke(code_str):
    conn = db()
    conn.execute("UPDATE activation_codes SET revoked=1 WHERE code=?", (code_str,))
    conn.commit()
    conn.close()
    log_admin_action("revoke_code", code_str)
    return jsonify({"ok": True})

# ─── ADMIN MONITOR ────────────────────────────────────────────────────────────

def build_monitor_data():
    conn = db()
    tables = conn.execute("SELECT * FROM tables_ ORDER BY sort_order").fetchall()
    result = []
    for t in tables:
        code = t["code"]
        state = conn.execute("SELECT * FROM table_states WHERE table_code=?", (code,)).fetchone()
        total_preds = conn.execute("SELECT COUNT(*) FROM predictions WHERE table_code=? AND actual IS NOT NULL", (code,)).fetchone()[0]
        wins = conn.execute("SELECT COUNT(*) FROM predictions WHERE table_code=? AND result='win'", (code,)).fetchone()[0]
        losses = conn.execute("SELECT COUNT(*) FROM predictions WHERE table_code=? AND result='lose'", (code,)).fetchone()[0]

        # accuracy_100
        recent_100 = conn.execute("""
SELECT result FROM predictions WHERE table_code=? AND actual IS NOT NULL
ORDER BY session_id DESC LIMIT 100
""", (code,)).fetchall()
        wins_100 = sum(1 for r in recent_100 if r["result"] == "win")
        acc_100 = round(wins_100 / len(recent_100), 3) if recent_100 else 0.0
        acc_all = round(wins / total_preds, 3) if total_preds else 0.0

        # streak
        streak_rows = conn.execute("""
SELECT result FROM predictions WHERE table_code=? AND actual IS NOT NULL
ORDER BY session_id DESC LIMIT 200
""", (code,)).fetchall()
        current_streak = {"type": None, "count": 0}
        best_win = 0
        best_lose = 0
        worst_lose = 0
        if streak_rows:
            first = streak_rows[0]["result"]
            cnt = 1
            for i in range(1, len(streak_rows)):
                if streak_rows[i]["result"] == first:
                    cnt += 1
                else:
                    break
            current_streak = {"type": first, "count": cnt}
            # best/worst
            cur_type = streak_rows[0]["result"]
            cur_cnt = 1
            for i in range(1, len(streak_rows)):
                if streak_rows[i]["result"] == cur_type:
                    cur_cnt += 1
                else:
                    if cur_type == "win":
                        best_win = max(best_win, cur_cnt)
                    else:
                        worst_lose = max(worst_lose, cur_cnt)
                    cur_type = streak_rows[i]["result"]
                    cur_cnt = 1
            if cur_type == "win":
                best_win = max(best_win, cur_cnt)
            else:
                worst_lose = max(worst_lose, cur_cnt)

        # health
        last_poll_at = state["last_poll_at"] if state else None
        last_poll_error = state["last_poll_error"] if state else None
        is_active = bool(t["is_active"])

        health = "green"
        health_reason = None
        if not is_active:
            health = "paused"
        elif last_poll_error:
            health = "red"
            health_reason = last_poll_error[:100]
        elif last_poll_at:
            lp = iso_to_dt(last_poll_at)
            if lp:
                age_min = (now_dt() - lp).total_seconds() / 60
                if age_min > 15:
                    health = "red"
                    health_reason = f"Khong poll {int(age_min)} phut"
                elif age_min > 5:
                    health = "yellow"
                    health_reason = f"Cham {int(age_min)} phut"
        if health == "green" and acc_100 < 0.45:
            health = "red"
            health_reason = f"Accuracy thap: {acc_100:.1%}"
        elif health == "green" and acc_100 < 0.50:
            health = "yellow"
            health_reason = f"Accuracy trung binh: {acc_100:.1%}"

        # sessions_learned
        history_json = state["history_json"] if state else None
        sessions_learned = 0
        if history_json:
            try:
                d = json.loads(history_json)
                sessions_learned = len(d.get("history", []))
            except Exception:
                pass

        result.append({
            "code": code,
            "name": t["name"],
            "health": health,
            "health_reason": health_reason,
            "is_active": is_active,
            "sessions_learned": sessions_learned,
            "predictions_total": total_preds,
            "wins": wins,
            "losses": losses,
            "accuracy_all": acc_all,
            "accuracy_100": acc_100,
            "current_streak": current_streak,
            "best_streak": {"type": "win", "count": best_win},
            "worst_streak": {"type": "lose", "count": worst_lose},
            "last_poll_at": last_poll_at,
            "last_poll_error": last_poll_error,
            "regime_change": False,
        })
    conn.close()
    alerts = [t for t in result if t["health"] in ("red", "yellow")]
    return {"updated_at": now_iso(), "tables": result, "alerts": alerts}

@app.route("/admin/api/monitor")
@admin_required
def admin_api_monitor():
    return jsonify(build_monitor_data())

@app.route("/admin/api/monitor/<table_code>/history")
@admin_required
def admin_api_monitor_history(table_code):
    conn = db()
    rows = conn.execute("""
SELECT session_id, prediction, actual, result, created_at FROM predictions
WHERE table_code=? ORDER BY session_id DESC LIMIT 100
""", (table_code,)).fetchall()
    conn.close()
    items = [dict(r) for r in rows]
    return jsonify({"ok": True, "table": table_code, "items": items})

@app.route("/admin/monitor")
@admin_required
def admin_monitor():
    data = build_monitor_data()
    tables_html = ""
    for t in data["tables"]:
        health = t["health"]
        dot_class = {"green": "dot-green", "yellow": "dot-yellow", "red": "dot-red", "paused": "dot-gray"}.get(health, "dot-gray")
        badge_class = {"green": "badge-green", "yellow": "badge-yellow", "red": "badge-red", "paused": "badge-gray"}.get(health, "badge-gray")
        health_label = {"green": "Tot", "yellow": "Canh bao", "red": "Loi", "paused": "Tam dung"}.get(health)

        tables_html += f"""<div class="card mb-3">
  <div class="flex justify-between items-center mb-3">
    <div class="flex items-center gap-3">
      <div class="dot {dot_class}"></div>
      <div>
        <h3>{t['name']}</h3>
        <span class="text-muted" style="font-size:12px">{t['code']}</span>
      </div>
    </div>
    <div class="flex gap-2 items-center">
      <span class="badge {badge_class}">{health_label}</span>
      {'<span class="text-muted" style="font-size:11px">' + t['health_reason'] + '</span>' if t['health_reason'] else ''}
      <a href="/admin/monitor/{t['code']}" class="btn btn-sm">Chi tiet</a>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
    <div><label>Phien hoc</label><div class="big-num mt-1" style="font-size:24px">{t['sessions_learned']}</div></div>
    <div><label>Tong du doan</label><div class="big-num mt-1" style="font-size:24px">{t['predictions_total']}</div></div>
    <div><label>Acc 100 phien</label><div class="big-num mt-1 {'text-green' if t['accuracy_100']>=0.55 else 'text-yellow' if t['accuracy_100']>=0.5 else 'text-red'}" style="font-size:24px">{t['accuracy_100']:.1%}</div></div>
    <div><label>Streak hien tai</label><div class="big-num mt-1" style="font-size:24px">{t['current_streak']['count']} {'W' if t['current_streak']['type']=='win' else 'L' if t['current_streak']['type']=='lose' else '-'}</div></div>
  </div>
  <div class="mt-3 flex gap-4" style="font-size:12px;color:var(--text2)">
    <span>Poll cuoi: {t['last_poll_at'][:19] if t['last_poll_at'] else 'Chua poll'}</span>
    <span>W/L: {t['wins']}/{t['losses']}</span>
    <span>Acc tong: {t['accuracy_all']:.1%}</span>
  </div>
</div>"""

    content = f"""
<div class="page-header">
  <h1>Monitor</h1>
  <div class="flex gap-2 items-center">
    <span id="auto-refresh-label" class="text-muted" style="font-size:12px">Tu dong: Bat</span>
    <button class="btn btn-sm" id="toggle-refresh" onclick="toggleAutoRefresh()">Tat tu dong</button>
  </div>
</div>
<div id="alert-banner" style="display:none"></div>
<div id="tables-container">{tables_html}</div>
<button class="fab" id="fab-refresh" onclick="manualRefresh()">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
</svg></button>
<script>
var autoRefresh = localStorage.getItem('monitor_autorefresh') !== 'false';
var refreshInterval = null;
function updateToggleBtn() {{
  var label = document.getElementById('auto-refresh-label');
  var btn = document.getElementById('toggle-refresh');
  label.textContent = 'Tu dong: ' + (autoRefresh ? 'Bat' : 'Tat');
  btn.textContent = autoRefresh ? 'Tat tu dong' : 'Bat tu dong';
}}
function toggleAutoRefresh() {{
  autoRefresh = !autoRefresh;
  localStorage.setItem('monitor_autorefresh', autoRefresh);
  updateToggleBtn();
  if (autoRefresh) startRefresh(); else stopRefresh();
}}
function startRefresh() {{
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(doRefresh, 10000);
}}
function stopRefresh() {{
  if (refreshInterval) clearInterval(refreshInterval);
}}
async function doRefresh() {{
  try {{
    var r = await fetch('/admin/api/monitor', {{credentials:'same-origin'}});
    var d = await r.json();
    // Simple reload for now
    location.reload();
  }} catch(e) {{}}
}}
async function manualRefresh() {{
  var fab = document.getElementById('fab-refresh');
  var svg = fab.querySelector('svg');
  svg.style.animation = 'fab-spin 0.6s linear';
  await doRefresh();
}}
updateToggleBtn();
if (autoRefresh) startRefresh();
</script>"""
    return render_admin_layout("Monitor", content, "monitor")

@app.route("/admin/monitor/<table_code>")
@admin_required
def admin_monitor_detail(table_code):
    conn = db()
    t_row = conn.execute("SELECT * FROM tables_ WHERE code=?", (table_code,)).fetchone()
    if not t_row:
        conn.close()
        return html_error("Khong tim thay", "Ban khong ton tai"), 404

    recent = conn.execute("""
SELECT session_id, prediction, actual, result, confidence, created_at FROM predictions
WHERE table_code=? ORDER BY session_id DESC LIMIT 100
""", (table_code,)).fetchall()
    resets = conn.execute("""
SELECT * FROM engine_resets WHERE table_code=? ORDER BY id DESC LIMIT 10
""", (table_code,)).fetchall()
    state = conn.execute("SELECT * FROM table_states WHERE table_code=?", (table_code,)).fetchone()
    conn.close()

    rows_html = ""
    for r in recent:
        result_badge = ""
        if r["result"] == "win":
            result_badge = '<span class="badge badge-green">Thang</span>'
        elif r["result"] == "lose":
            result_badge = '<span class="badge badge-red">Thua</span>'
        else:
            result_badge = '<span class="badge badge-gray">Chua co</span>'
        rows_html += f"""<tr>
<td class="mono" style="font-size:12px">{r['session_id']}</td>
<td style="font-weight:600;color:{'#22c55e' if r['prediction']=='TAI' else '#ef4444'}">{r['prediction']}</td>
<td>{r['actual'] or '-'}</td>
<td>{result_badge}</td>
<td>{r['confidence'] or '-'}%</td>
<td class="text-muted" style="font-size:11px">{r['created_at'][:19] if r['created_at'] else ''}</td>
</tr>"""

    reset_rows = ""
    for r in resets:
        reset_rows += f"""<tr>
<td class="text-muted" style="font-size:12px">{r['created_at'][:19]}</td>
<td>{r['reason']}</td>
<td>{r['accuracy_before']:.1%} if r['accuracy_before'] else '-'</td>
<td>{r['sessions_at_reset']}</td>
</tr>"""

    last_poll = state["last_poll_at"] if state else None
    last_error = state["last_poll_error"] if state else None

    table_actions_html = f"""
<div class="flex gap-2 mt-3">
  <button class="btn {'btn-danger' if t_row['is_active'] else 'btn-primary'}" onclick="toggleTable()">
    {'Tam dung ban' if t_row['is_active'] else 'Bat lai ban'}
  </button>
  <button class="btn btn-danger" onclick="restartEngine()">Restart engine</button>
</div>"""

    content = f"""
<div class="page-header">
  <div>
    <a href="/admin/monitor" class="text-muted" style="font-size:12px">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Monitor</a>
    <h1 class="mt-1">{t_row['name']} <span class="text-muted" style="font-size:14px">({table_code})</span></h1>
  </div>
</div>
<div class="card mb-4">
  <div class="flex gap-4" style="font-size:13px;flex-wrap:wrap">
    <div><label>Trang thai</label><div class="mt-1">{'<span class="badge badge-green">Dang chay</span>' if t_row['is_active'] else '<span class="badge badge-gray">Tam dung</span>'}</div></div>
    <div><label>Poll cuoi</label><div class="mt-1 text-muted">{last_poll[:19] if last_poll else 'Chua poll'}</div></div>
    <div><label>Loi gan nhat</label><div class="mt-1 text-muted">{last_error[:60] if last_error else 'Khong co'}</div></div>
  </div>
  {table_actions_html}
</div>
<div class="card mb-4">
  <h3 class="mb-3">100 phien gan nhat</h3>
  <div class="overflow-x-auto">
  <table>
  <thead><tr><th>Phien</th><th>Du doan</th><th>Ket qua</th><th>Trang thai</th><th>Do tin cay</th><th>Thoi gian</th></tr></thead>
  <tbody>{rows_html if rows_html else '<tr><td colspan="6" class="text-center text-muted">Chua co du lieu</td></tr>'}</tbody>
  </table>
  </div>
</div>
{'<div class="card mb-4"><h3 class="mb-3">Lich su reset engine</h3><div class="overflow-x-auto"><table><thead><tr><th>Thoi gian</th><th>Ly do</th><th>Acc truoc</th><th>Phien</th></tr></thead><tbody>' + reset_rows + '</tbody></table></div></div>' if resets else ''}
<button class="fab" id="fab" onclick="location.reload()">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
</svg></button>
<script>
async function toggleTable() {{
  var is_active = {'1' if t_row['is_active'] else '0'};
  var r = await fetch('/admin/tables/{table_code}/toggle', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{is_active:is_active?0:1}})}});
  var d = await r.json();
  if(d.ok){{showToast('Da cap nhat','success');setTimeout(()=>location.reload(),800);}}
  else showToast(d.message||'Loi','error');
}}
function restartEngine() {{
  openTypeConfirmModal('Restart engine','Viec nay se xoa lich su hoc cua engine va bat dau lai tu dau.','RESTART',async function(){{
    var r=await fetch('/admin/tables/{table_code}/restart',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{confirm:'RESTART'}})}});
    var d=await r.json();
    if(d.ok){{showToast('Da restart','success');setTimeout(()=>location.reload(),1000);}}
    else showToast(d.message||'Loi','error');
  }},'Restart');
}}
</script>"""
    return render_admin_layout(f"Monitor - {t_row['name']}", content, "monitor")

@app.route("/admin/tables/<table_code>/toggle", methods=["POST"])
@admin_required
def admin_table_toggle(table_code):
    data = request.get_json() or {}
    is_active = int(data.get("is_active", 1))
    conn = db()
    conn.execute("UPDATE tables_ SET is_active=? WHERE code=?", (is_active, table_code))
    conn.commit()
    conn.close()
    log_admin_action("toggle_table", table_code, {"is_active": is_active})
    return jsonify({"ok": True})

@app.route("/admin/tables/<table_code>/restart", methods=["POST"])
@admin_required
def admin_table_restart(table_code):
    data = request.get_json() or {}
    if data.get("confirm") != "RESTART":
        return jsonify({"ok": False, "message": "Can xac nhan RESTART"})
    conn = db()
    conn.execute("UPDATE table_states SET history_json=NULL, last_seen_id=0 WHERE table_code=?", (table_code,))
    conn.commit()
    conn.close()
    log_admin_action("restart_engine", table_code)
    return jsonify({"ok": True})

# ─── ADMIN LOGS ───────────────────────────────────────────────────────────────

@app.route("/admin/logs")
@admin_required
def admin_logs():
    conn = db()
    logs = conn.execute("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()

    icon_map = {
        "create_key": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
        "create_code": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/></svg>',
        "revoke_key": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        "revoke_code": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        "restart_engine": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
        "toggle_table": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="5" width="22" height="14" rx="7" ry="7"/><circle cx="8" cy="12" r="3"/></svg>',
        "extend_key": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
        "delete_key": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
        "unlock_device": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
    }
    default_icon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>'

    entries_html = ""
    for log in logs:
        icon = icon_map.get(log["action"], default_icon)
        entries_html += f"""<div style="display:flex;gap:16px;padding:12px 0;border-bottom:1px solid var(--border)">
  <div style="width:32px;height:32px;border-radius:50%;background:var(--surface2);border:1px solid var(--border2);display:flex;align-items:center;justify-content:center;flex-shrink:0">
    {icon}
  </div>
  <div style="flex:1">
    <div style="font-size:13px"><span class="badge badge-gray">{log['action'] or ''}</span> <span style="color:var(--text2)">tren</span> <strong>{log['target'] or ''}</strong></div>
    <div class="text-muted" style="font-size:11px;margin-top:2px">{log['admin_user'] or ''} &middot; {log['ip'] or ''} &middot; {log['created_at'][:19] if log['created_at'] else ''}</div>
    {f'<div class="text-muted" style="font-size:11px;margin-top:2px;font-family:monospace">{log["detail_json"][:100]}</div>' if log["detail_json"] else ''}
  </div>
</div>"""

    content = f"""
<div class="page-header">
  <h1>Nhat ky hoat dong</h1>
</div>
<div class="card">
  {entries_html if entries_html else '<p class="text-muted text-center">Chua co hoat dong</p>'}
</div>"""
    return render_admin_layout("Nhat ky", content, "logs")

# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if wants_html():
        return html_error("404", "Trang khong ton tai"), 404
    return jsonify({"error": "not_found", "message": "Trang khong ton tai"}), 404

@app.errorhandler(500)
def server_error(e):
    if wants_html():
        return html_error("500", "Loi may chu"), 500
    return jsonify({"error": "server_error", "message": "Loi may chu"}), 500

# ─── RENDER.YAML (comment) ────────────────────────────────────────────────────
# services:
#   - type: web
#     name: lc79-api
#     env: python
#     plan: starter
#     buildCommand: pip install -r requirements.txt
#     startCommand: gunicorn app:app --workers 2 --bind 0.0.0.0:$PORT
#     envVars:
#       - key: SECRET_KEY
#         generateValue: true
#       - key: DATABASE_PATH
#         value: /var/data/app.db
#       - key: ADMIN_USER
#         value: admin
#       - key: ADMIN_PASS
#         sync: false
#       - key: BRANDING_NAME
#         value: P A W
#       - key: BRANDING_TELEGRAM
#         value: "@K0ZT1"
#     disk:
#       name: data
#       mountPath: /var/data
#       sizeGB: 1
#   - type: worker
#     name: lc79-worker
#     env: python
#     plan: starter
#     buildCommand: pip install -r requirements.txt
#     startCommand: python worker.py
#     envVars:
#       - key: DATABASE_PATH
#         value: /var/data/app.db
#     disk:
#       name: data
#       mountPath: /var/data
#       sizeGB: 1

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
