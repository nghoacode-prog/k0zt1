import time
import requests
import sqlite3
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from engine import (
    db, now_iso, init_db, seed_tables,
    parse_upstream, load_engine, save_engine,
    load_last_seen, save_last_seen,
    mark_poll_ok, mark_poll_error
)

LOG_PREFIX = "[worker]"

def log_info(table_code, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"{ts} [{table_code}] {msg}", flush=True)

def log_warning(table_code, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"{ts} [{table_code}] WARN: {msg}", flush=True)

def log_error(table_code, msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"{ts} [{table_code}] ERROR: {msg}", flush=True)

# ─── DB ACCURACY ──────────────────────────────────────────────────────────────

def db_accuracy(table_code, n=100):
    conn = db()
    rows = conn.execute("""
SELECT result FROM predictions
WHERE table_code=? AND actual IS NOT NULL
ORDER BY session_id DESC LIMIT ?
""", (table_code, n)).fetchall()
    conn.close()
    if not rows:
        return 0.5
    wins = sum(1 for r in rows if r["result"] == "win")
    return wins / len(rows)

# ─── RESOLVE + INSERT ─────────────────────────────────────────────────────────

def resolve_pending(table_code, session_id, actual_int):
    actual_str = "TAI" if actual_int == 1 else "XIU"
    conn = db()
    row = conn.execute("""
SELECT id, prediction FROM predictions
WHERE table_code=? AND session_id=? AND actual IS NULL
""", (table_code, session_id)).fetchone()
    if row:
        result = "win" if row["prediction"] == actual_str else "lose"
        conn.execute("""
UPDATE predictions SET actual=?, result=?, resolved_at=? WHERE id=?
""", (actual_str, result, now_iso(), row["id"]))
        conn.commit()
    conn.close()

def insert_pending(table_code, session_id, prediction, confidence):
    conn = db()
    conn.execute("""
INSERT OR IGNORE INTO predictions (table_code, session_id, prediction, confidence)
VALUES (?, ?, ?, ?)
""", (table_code, session_id, prediction, confidence))
    conn.commit()
    conn.close()

def log_engine_reset(table_code, reason, accuracy_before, sessions_at_reset):
    conn = db()
    conn.execute("""
INSERT INTO engine_resets (table_code, reason, accuracy_before, sessions_at_reset, created_at)
VALUES (?, ?, ?, ?, ?)
""", (table_code, reason, accuracy_before, sessions_at_reset, now_iso()))
    conn.commit()
    conn.close()

# ─── PROCESS TABLE ────────────────────────────────────────────────────────────

def process_table(table):
    code = table["code"]
    try:
        r = requests.get(table["upstream_url"], timeout=10)
        r.raise_for_status()
        raw = r.json()
    except Exception as e:
        err = f"fetch: {str(e)[:200]}"
        log_error(code, err)
        mark_poll_error(code, err)
        return

    parsed = parse_upstream(raw)
    if not parsed:
        err = "parse_fail"
        log_error(code, err)
        mark_poll_error(code, err)
        return

    sessions = parsed["sessions"]
    latest_id = parsed["latest_id"]

    engine = load_engine(code)
    last_seen = load_last_seen(code)

    new = [s for s in sessions if s["session_id"] > last_seen]
    if not new:
        mark_poll_ok(code)
        return

    # Gap detection
    if last_seen > 0 and new[0]["session_id"] > last_seen + 1:
        gap = new[0]["session_id"] - last_seen - 1
        log_warning(code, f"gap: miss {gap} phien")

    bootstrap = (last_seen == 0)

    # Patch engine với accuracy từ DB
    engine._cached_accuracy = db_accuracy(code, 100)

    for i, s in enumerate(new):
        sid = s["session_id"]
        resolve_pending(code, sid, s["result"])
        engine.observe(s["result"])

        if bootstrap:
            # Chỉ insert 1 prediction duy nhất sau khi học xong tất cả
            if i == len(new) - 1:
                pred = engine.predict()
                if pred["side"]:
                    insert_pending(code, sid + 1, pred["side"], pred["confidence"])
                log_info(code, f"bootstrapped {len(new)} sessions -> {latest_id}, hoc {len(engine.history)} phien")
        else:
            pred = engine.predict()
            if pred["side"]:
                insert_pending(code, sid + 1, pred["side"], pred["confidence"])

    # Watchdog check sau mỗi batch
    acc = db_accuracy(code, 100)
    engine._cached_accuracy = acc
    if len(engine.history) > 0 and len(engine.history) % 50 == 0:
        if acc < 0.45:
            log_warning(code, f"watchdog reset: acc={acc:.3f}")
            log_engine_reset(code, "watchdog_low_acc", acc, len(engine.history))

    save_engine(code, engine)
    save_last_seen(code, latest_id)
    mark_poll_ok(code)

    if not bootstrap:
        log_info(code, f"+{len(new)} phien -> {latest_id} (hoc {len(engine.history)})")

# ─── MAIN LOOP ────────────────────────────────────────────────────────────────

def main():
    init_db()
    seed_tables()
    log_info("main", "Worker khoi dong")

    stagger = False
    last_healthcheck = time.time()
    start_time = time.time()

    while True:
        try:
            conn = db()
            tables = conn.execute(
                "SELECT * FROM tables_ WHERE is_active=1 ORDER BY sort_order"
            ).fetchall()
            conn.close()

            for i, t in enumerate(tables):
                if stagger and i > 0:
                    time.sleep(30)
                process_table(dict(t))

            # Clean old rate_limits moi gio
            conn = db()
            conn.execute(
                "DELETE FROM rate_limits WHERE window < ?",
                (str(int(time.time() // 60) - 120),)
            )
            conn.commit()
            conn.close()

            # A9 — Healthcheck log moi 5 phut
            now = time.time()
            if now - last_healthcheck > 300:
                uptime_min = int((now - start_time) / 60)
                log_info("worker_alive", f"tables={len(tables)}, uptime={uptime_min}min")
                last_healthcheck = now

            stagger = True

        except Exception as e:
            log_error("main", f"loop error: {str(e)[:300]}")

        time.sleep(60)


if __name__ == "__main__":
    main()
