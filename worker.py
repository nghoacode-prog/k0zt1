# -*- coding: utf-8 -*-
"""LC79 upstream polling worker. Chỉ xử lý hai bàn LC79."""
import logging
import os
import time
import requests
from engine import (TABLES, PredictionEngine, db, init_db, parse_upstream, load_engine,
                    load_last_seen, save_worker_state, mark_poll_ok,
                    mark_poll_error, accuracy, now_iso)

POLL_SECONDS = 60
BOOTSTRAP_SESSIONS = 105
REQUEST_TIMEOUT = 15
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("lc79-worker")


def get_tables():
    conn = db()
    rows = conn.execute("SELECT * FROM tables_ WHERE is_active=1 ORDER BY sort_order").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_sessions(url):
    response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json", "User-Agent": "LC79-Worker/1.0"})
    response.raise_for_status()
    parsed = parse_upstream(response.json())
    if not parsed:
        raise ValueError("Dữ liệu upstream không đúng định dạng hoặc không có phiên hợp lệ")
    return parsed["sessions"]


def insert_pending(table_code, session_id, prediction):
    conn = db()
    conn.execute("""INSERT OR IGNORE INTO predictions
        (table_code,session_id,prediction,confidence,created_at)
        VALUES(?,?,?,?,?)""", (table_code, int(session_id), prediction["side"],
                                int(prediction["confidence"]), now_iso()))
    conn.commit()
    conn.close()


def resolve_pending(table_code, session_id, actual_int):
    actual = "TAI" if int(actual_int) == 1 else "XIU"
    conn = db()
    row = conn.execute("""SELECT id,prediction FROM predictions
        WHERE table_code=? AND session_id=? AND actual IS NULL""", (table_code, int(session_id))).fetchone()
    if row:
        result = "win" if row["prediction"] == actual else "lose"
        conn.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?",
                     (actual, result, now_iso(), row["id"]))
    conn.commit()
    conn.close()


def process_table(table):
    code = table["code"]
    try:
        sessions = fetch_sessions(table["upstream_url"])
        last_seen = load_last_seen(code)
        engine = load_engine(code)
        if last_seen == 0:
            # Bootstrap chỉ học 105 phiên gần nhất; tuyệt đối không ghi chúng vào predictions.
            if len(sessions) < BOOTSTRAP_SESSIONS:
                mark_poll_ok(code)
                log.info("%s: đang bootstrap (%d/%d phiên)", code, len(sessions), BOOTSTRAP_SESSIONS)
                return
            seed = sessions[-BOOTSTRAP_SESSIONS:]
            engine = PredictionEngine()
            for session in seed:
                engine.predict(accuracy(code, 100), accuracy(code, 500))
                engine.observe(session["result"])
            latest_id = seed[-1]["session_id"]
            acc100 = accuracy(code, 100)
            acc500 = accuracy(code, 500)
            prediction = engine.predict(acc100, acc500)
            insert_pending(code, latest_id + 1, prediction)
            save_worker_state(code, engine, latest_id)
            mark_poll_ok(code)
            log.info("%s: bootstrap hoàn tất %d phiên, tạo 1 pending cho phiên %d",
                     code, len(seed), latest_id + 1)
            return

        new_sessions = [s for s in sessions if s["session_id"] > last_seen]
        if not new_sessions:
            mark_poll_ok(code)
            return
        if new_sessions[0]["session_id"] > last_seen + 1:
            log.warning("%s: phát hiện thiếu %d phiên upstream", code,
                        new_sessions[0]["session_id"] - last_seen - 1)
        for session in new_sessions:
            sid = session["session_id"]
            # Tái tạo dự báo pending trong bộ nhớ trước khi cập nhật kết quả.
            engine.predict(accuracy(code, 100), accuracy(code, 500))
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
    log.info("Worker LC79 khởi động; chu kỳ 60 giây, lệch nhịp 0/30 giây")
    while True:
        started = time.monotonic()
        try:
            tables = get_tables()
            # Bảo đảm thứ tự cố định: Hũ trước, MD5 sau 30 giây.
            by_code = {t["code"]: t for t in tables}
            for index, code in enumerate(("lc79_tx", "lc79_md5")):
                table = by_code.get(code)
                if table:
                    process_table(table)
                if index == 0:
                    time.sleep(30)
            # Dọn cửa sổ giới hạn truy cập cũ, giữ lại hai giờ gần nhất.
            conn=db()
            conn.execute("DELETE FROM rate_limits WHERE CAST(window AS INTEGER) < ?", (int(time.time()//60)-120,))
            conn.commit(); conn.close()
        except Exception:
            log.exception("Lỗi vòng lặp worker")
        elapsed = time.monotonic() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


if __name__ == "__main__":
    main()

# === END worker.py ===
