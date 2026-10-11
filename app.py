import os
import hmac
import time
import threading
from collections import deque
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS

import algorithm

app = Flask(__name__)

# Configure CORS_ALLOWED_ORIGINS in Render. Use * only for temporary testing.
allowed = os.getenv("CORS_ALLOWED_ORIGINS", "")
origins = [x.strip() for x in allowed.split(",") if x.strip()] or []
CORS(app, resources={r"/api/*": {"origins": origins or []}})

SERVER_API_KEY = os.getenv("SERVER_API_KEY", "")
API_CALLS = deque()
CALL_LOCK = threading.Lock()
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))

# Cache prediction by source session so repeated 1-second polling does not
# create a different prediction for the same session. The source is still
# checked on each request; a new prediction is accepted only on session change.
PREDICTION_CACHE = {"session": None, "payload": None}
PREDICTION_LOCK = threading.Lock()


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Do not deploy an unprotected public API.
        if not SERVER_API_KEY:
            return jsonify({
                "ok": False,
                "error": "server_not_configured",
                "message": "Set SERVER_API_KEY in the host environment before using protected endpoints."
            }), 503

        auth = request.headers.get("Authorization", "")
        supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(supplied, SERVER_API_KEY):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        now = time.time()
        with CALL_LOCK:
            while API_CALLS and now - API_CALLS[0] > 60:
                API_CALLS.popleft()
            if len(API_CALLS) >= RATE_LIMIT_PER_MINUTE:
                return jsonify({"ok": False, "error": "rate_limit_exceeded"}), 429
            API_CALLS.append(now)
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def index():
    return jsonify({
        "service": "PAW DEV TX AI Private API",
        "status": "online",
        "version": "1.0.0",
        "endpoints": ["/health", "/api/v1/predict", "/api/v1/stats"]
    })


@app.get("/health")
def health():
    return jsonify({"ok": True, "status": "online"})


@app.get("/api/v1/predict")
@require_api_key
def predict():
    # Check the source on every request. Clients can poll this endpoint every
    # second; the cached prediction is retained while the source session is unchanged.
    result, error = algorithm.predict_next()
    if error or not result:
        return jsonify({"ok": False, "error": error or "prediction_unavailable"}), 502

    source_session = result.get("top_id")
    with PREDICTION_LOCK:
        if PREDICTION_CACHE["session"] != source_session:
            payload = {
                "session": source_session,
                "prediction": result.get("predict"),
                "rate": result.get("confidence"),
                "result": None,
                "admin": "@K0ZT1"
            }
            PREDICTION_CACHE["session"] = source_session
            PREDICTION_CACHE["payload"] = payload
        payload = dict(PREDICTION_CACHE["payload"])

    # Minimal public JSON: no internal patterns, reasons, or algorithm details.
    return jsonify(payload)


@app.get("/api/v1/stats")
@require_api_key
def stats():
    return jsonify({"ok": True, "stats": algorithm.get_stats()})


@app.errorhandler(404)
def not_found(_):
    return jsonify({"ok": False, "error": "not_found"}), 404


@app.errorhandler(500)
def internal_error(_):
    app.logger.exception("Unhandled server error")
    return jsonify({"ok": False, "error": "internal_server_error"}), 500
