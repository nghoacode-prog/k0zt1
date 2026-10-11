# PAW DEV TX AI Private API

This wraps the supplied `thuattoanpawdev.py` prediction logic in a private Flask API.
The supplied source had an indentation issue around `mod_cycle` and `_BOT_HISTORY`;
those syntax/initialization issues were repaired in `algorithm.py` so it can import.

## Endpoints
- `GET /health` — public health check
- `GET /api/v1/predict` — protected prediction endpoint
- `GET /api/v1/stats` — protected in-memory win/loss stats

Protected endpoints require:
`Authorization: Bearer YOUR_SERVER_API_KEY`

## Deploy on Render
1. Upload all four files to a private GitHub repository.
2. Create a Render Web Service from that repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 30`
5. In Render Environment, set `SERVER_API_KEY` to a long random secret. Never put it in public HTML or a distributed APK.
6. `CORS_ALLOWED_ORIGINS` should contain only trusted browser origins, comma-separated. For Telegram bot server-to-server calls, CORS is not relevant.

## Call example
```bash
curl -H "Authorization: Bearer YOUR_SERVER_API_KEY" \
  https://YOUR-SERVICE.onrender.com/api/v1/predict
```

## Security architecture
- Keep the repository private.
- Keep the master API key only in server-side environment variables or a trusted bot backend.
- For a public HTML client, do NOT embed the master key. Use a small backend/bot that authenticates users and calls this API server-to-server, or implement short-lived per-user credentials.
- Do not expose raw algorithm source or full internal traces in API responses.

## Important
This wrapper hides source code from normal API clients, but it does not make the algorithm impossible to copy if the server/repository/hosting account is compromised. Use private repository access, strong account security, secret rotation, and persistent storage for production.
The prediction logic is heuristic; confidence values in the supplied algorithm are not demonstrated probabilities of winning. Backtest against unseen future results before making performance claims.
The original bot result history is in-memory and resets on restart; persistent result grading/database should be added before production use.


## Minimal prediction response
The `/api/v1/predict` endpoint exposes only `session`, `prediction`, `result`, and `admin`. `result` is `null` until a separate grading flow records the actual outcome. Algorithm internals stay on the server. Admin contact: `@K0ZT1`.


## Auto refresh and session guard
- Client should request `/api/v1/predict` every 1 second.
- Each request checks the source API; the response is cached for the same source session.
- A new prediction is published only when `top_id` changes.
- The `result` field remains `null` until actual-result grading is implemented; do not treat it as an actual result.
- If the upstream source is delayed or returns stale session IDs, the server cannot guarantee that the source itself is correct. Verify whether the upstream `top_id` represents the current session or the next target session before using it in a live tool.
