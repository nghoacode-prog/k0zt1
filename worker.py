# -*- coding: utf-8 -*-
"""LC79 upstream polling worker. Chỉ xử lý hai bàn LC79."""
import logging
import os
import time
import requests
from engine import (TABLES, PredictionEngine, db, init_db, parse_upstream, load_engine,
                    load_last_seen, save_worker_state, mark_poll_ok,
                    mark_poll_error, accuracy, now_iso, resolve_actual, get_worker_control, set_worker_control)

POLL_SECONDS = 8
BOOTSTRAP_SESSIONS = 105
REQUEST_TIMEOUT = 10
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("lc79-worker")


def get_tables():
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM tables_ WHERE is_active=1 ORDER BY sort_order").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def fetch_sessions(url):
    response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json", "User-Agent": "LC79-Worker/1.0"})
    response.raise_for_status()
    parsed = parse_upstream(response.json())
    if not parsed:
        raise ValueError("Dữ liệu upstream không đúng định dạng hoặc không có phiên hợp lệ")
    return parsed["sessions"]


def insert_pending(table_code, session_id, prediction):
    if prediction.get("side") == "SKIP":
        return
    conn = db()
    try:
        conn.execute("""INSERT OR IGNORE INTO predictions
            (table_code,session_id,prediction,confidence,created_at,detail_json)
            VALUES(?,?,?,?,?,?)""", (table_code, int(session_id), prediction["side"],
                                    int(prediction["confidence"]), now_iso(), __import__("json").dumps(prediction.get("full", {}), ensure_ascii=False)))
        conn.commit()
    except Exception as e:
        log.error(f"Lỗi insert_pending: {e}")
    finally:
        conn.close()


def resolve_pending(table_code, session_id, actual_int):
    actual = "TAI" if int(actual_int) == 1 else "XIU"
    conn = db()
    try:
        row = conn.execute("""SELECT id,prediction FROM predictions
            WHERE table_code=? AND session_id=? AND actual IS NULL""", (table_code, int(session_id))).fetchone()
        if row:
            result = "win" if row["prediction"] == actual else "lose"
            conn.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?",
                         (actual, result, now_iso(), row["id"]))
            conn.commit()
    except Exception as e:
        log.error(f"Lỗi resolve_pending: {e}")
    finally:
        conn.close()
    
    # Gọi resolve_actual để lưu log phân định (module votes)
    try:
        resolve_actual(table_code, [{"session_id": int(session_id), "result": int(actual_int)}])
    except Exception as e:
        log.error(f"Lỗi resolve_actual: {e}")


def process_table(table):
    code = table["code"]
    try:
        sessions = fetch_sessions(table["upstream_url"])
        last_seen = load_last_seen(code)
        engine = load_engine(code)
        
        if get_worker_control("force_restart:" + code) == "1":
            engine = PredictionEngine(history=engine.history, table_code=code)
            set_worker_control("force_restart:" + code, "0")
            log.warning("%s: reset adaptive weights theo yêu cầu quản trị", code)
            
        if last_seen == 0:
            if len(sessions) < BOOTSTRAP_SESSIONS:
                mark_poll_ok(code)
                log.info("%s: đang bootstrap (%d/%d phiên)", code, len(sessions), BOOTSTRAP_SESSIONS)
                return
            seed = sessions[-BOOTSTRAP_SESSIONS:]
            engine = PredictionEngine(table_code=code)
            for session in seed:
                engine.predict(accuracy(code, 100), accuracy(code, 500))
                engine.observe(session["result"])
            latest_id = seed[-1]["session_id"]
            prediction = engine.predict(accuracy(code, 100), accuracy(code, 500))
            insert_pending(code, latest_id + 1, prediction)
            save_worker_state(code, engine, latest_id)
            mark_poll_ok(code)
            log.info("%s: bootstrap hoàn tất %d phiên, tạo 1 pending cho phiên %d", code, len(seed), latest_id + 1)
            return

        new_sessions = [s for s in sessions if s["session_id"] > last_seen]
        if not new_sessions:
            mark_poll_ok(code)
            return
            
        if new_sessions[0]["session_id"] > last_seen + 1:
            log.warning("%s: phát hiện thiếu %d phiên upstream", code, new_sessions[0]["session_id"] - last_seen - 1)
            
        for session in new_sessions:
            sid = session["session_id"]
            prior_prediction = engine.predict(accuracy(code, 100), accuracy(code, 500))
            actual_side = "TAI" if int(session["result"]) == 1 else "XIU"
            
            for module_name, vote in prior_prediction.get("modules", {}).items():
                probability = float(vote.get("p", 0.5))
                vote_side = "TAI" if probability >= 0.5 else "XIU"
                if vote_side != actual_side and (probability > 0.7 or probability < 0.3):
                    log.warning("%s phiên %s: module %s vote sai tự tin p=%.3f actual=%s", code, sid, module_name, probability, actual_side)
                    
            resolve_pending(code, sid, session["result"])
            engine.observe(session["result"])
            prediction = engine.predict(accuracy(code, 100), accuracy(code, 500))
            insert_pending(code, sid + 1, prediction)
            last_seen = sid
            
        save_worker_state(code, engine, last_seen)
        mark_poll_ok(code)
        log.info("%s: cập nhật %d phiên, mới nhất %d", code, len(new_sessions), last_seen)
    except Exception as exc:
        mark_poll_error(code, str(exc))
        log.exception("%s: lỗi xử lý: %s", code, exc)


def main():
    init_db()
    log.info("Worker LC79 khởi động; poll tuần tự từng bàn để tránh lock SQLite")
    # CHẠY TUẦN TỰ THAY VÌ THREADPOOLEXECUTOR ĐỂ TRÁNH DATABASE IS LOCKED
    while True:
        started = time.monotonic()
        try:
            tables = get_tables()
            by_code = {t["code"]: t for t in tables}
            if get_worker_control("force_restart") == "1":
                for table_code in by_code:
                    set_worker_control("force_restart:" + table_code, "1")
                set_worker_control("force_restart", "0")
                
            # Poll tuần tự
            for code in ("lc79_tx", "lc79_md5"):
                if code in by_code:
                    process_table(by_code[code])
                    
            # Dọn rate limits
            conn = db()
            try:
                conn.execute("DELETE FROM rate_limits WHERE CAST(window AS INTEGER) < ?", (int(time.time()//60)-120,))
                conn.commit()
            finally:
                conn.close()
                
        except Exception:
            log.exception("Lỗi vòng lặp worker")
        elapsed = time.monotonic() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


if __name__ == "__main__":
    main()

# === END worker.py ===
