from flask import Flask, jsonify, request
import os, math, json, requests
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

URLS = {
    "md5": os.getenv("UPSTREAM_MD5_URL", "https://wtxmd52.tele68.com/v1/txmd5/sessions"),
    "hu": os.getenv("UPSTREAM_HU_URL", "https://wtx.tele68.com/v1/tx/sessions"),
}
MAX_HISTORY = 105

@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return r

def conn():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is missing")
    return psycopg2.connect(url, connect_timeout=8)

def init_db():
    c = conn()
    try:
        with c.cursor() as x:
            x.execute("""CREATE TABLE IF NOT EXISTS sessions(
                table_name TEXT NOT NULL, session_id BIGINT NOT NULL,
                total INTEGER, result TEXT NOT NULL, dices JSONB,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY(table_name,session_id))""")
            x.execute("""CREATE TABLE IF NOT EXISTS predictions(
                table_name TEXT NOT NULL, session_id BIGINT NOT NULL,
                prediction TEXT NOT NULL, probability DOUBLE PRECISION NOT NULL,
                status TEXT NOT NULL DEFAULT 'WAITING', actual_result TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                settled_at TIMESTAMPTZ,
                PRIMARY KEY(table_name,session_id))""")
        c.commit()
    finally:
        c.close()

def norm(v):
    v = str(v or "").upper().strip()
    return "TAI" if v in ("TAI","TÀI") else "XIU" if v in ("XIU","XỈU") else None

def fetch(table):
    r = requests.get(URLS[table], timeout=8, headers={"User-Agent":"PAWDEV/1.0"})
    r.raise_for_status()
    p = r.json()
    raw = p.get("list") if isinstance(p,dict) else p
    if raw is None and isinstance(p,dict):
        raw = p.get("data") or p.get("sessions")
    out, seen = [], set()
    for s in raw or []:
        try: sid = int(s.get("id",s.get("_id")))
        except: continue
        if sid in seen: continue
        result = norm(s.get("resultTruyenThong",s.get("result")))
        if not result: continue
        dice = s.get("dices",[])
        try: total = int(s.get("point",sum(int(z) for z in dice)))
        except: total = 0
        out.append({"id":sid,"total":total,"result":result,"dices":dice})
        seen.add(sid)
    return sorted(out,key=lambda z:z["id"])

def sync(table):
    rows=fetch(table); c=conn()
    try:
        with c.cursor() as x:
            for r in rows:
                x.execute("""INSERT INTO sessions(table_name,session_id,total,result,dices)
                    VALUES(%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT(table_name,session_id) DO UPDATE SET
                    total=EXCLUDED.total,result=EXCLUDED.result,dices=EXCLUDED.dices,
                    updated_at=NOW()""",
                    (table,r["id"],r["total"],r["result"],json.dumps(r["dices"])))
        c.commit()
    finally: c.close()

def history(table):
    c=conn()
    try:
        with c.cursor(cursor_factory=RealDictCursor) as x:
            x.execute("""SELECT session_id AS id,total,result,dices FROM sessions
                         WHERE table_name=%s ORDER BY session_id DESC LIMIT %s""",
                      (table,MAX_HISTORY))
            a=[dict(r) for r in x.fetchall()]
        return list(reversed(a))
    finally: c.close()

def sigmoid(z):
    return 1/(1+math.exp(-max(-40,min(40,z))))

def feat(a,i):
    q=a[i]; p=a[max(0,i-1)]; pp=a[max(0,i-2)]
    return [(q["total"]+p["total"]+pp["total"])/3,q["total"]-p["total"],
            float(q["result"]=="TAI")+float(p["result"]=="TAI")+float(pp["result"]=="TAI")]

def model(a):
    if len(a)<30: return None
    a=a[-30:]; X=[feat(a,i) for i in range(len(a)-1)]
    y=[float(a[i+1]["result"]=="TAI") for i in range(len(a)-1)]
    m=[sum(r[j] for r in X)/len(X) for j in range(3)]
    sd=[math.sqrt(sum((r[j]-m[j])**2 for r in X)/len(X)) or 1 for j in range(3)]
    w=[0,0,0]; b=0
    for _ in range(500):
        g=[0,0,0]; gb=0
        for r,yy in zip(X,y):
            z=sum(((r[j]-m[j])/sd[j])*w[j] for j in range(3))+b
            e=sigmoid(z)-yy
            for j in range(3): g[j]+=((r[j]-m[j])/sd[j])*e
            gb+=e
        for j in range(3): w[j]-=.1*g[j]/len(X)
        b-=.1*gb/len(X)
    f=feat(a,len(a)-1)
    z=sum(((f[j]-m[j])/sd[j])*w[j] for j in range(3))+b
    prob=sigmoid(z)
    # Exact repeated suffix signal, lengths 2..10.
    rs=[r["result"] for r in a]; votes=[]
    for n in range(2,min(10,len(rs)//2)+1):
        pat=rs[-n:]; nxt=[]
        for i in range(len(rs)-n):
            if rs[i:i+n]==pat and i+n<len(rs): nxt.append(rs[i+n])
        if nxt:
            t=nxt.count("TAI"); x=nxt.count("XIU")
            cons=abs(t-x)/len(nxt)
            if cons>=.25: votes.append((1 if t>x else -1,cons))
    if votes:
        s=sum(v*c for v,c in votes)/sum(c for _,c in votes)
        prob=max(.05,min(.95,prob+.10*s))
    confidence=min(.80,max(.50,abs(prob-.5)*2))
    return ("TAI" if prob>=.5 else "XIU"),prob,confidence

def settle(table,a):
    ids={r["id"]:r["result"] for r in a}; c=conn()
    try:
        with c.cursor() as x:
            for sid,res in ids.items():
                x.execute("""UPDATE predictions SET actual_result=%s,
                    status=CASE WHEN prediction=%s THEN 'WIN' ELSE 'LOSE' END,
                    settled_at=NOW()
                    WHERE table_name=%s AND session_id=%s AND status='WAITING'""",
                    (res,res,table,sid))
        c.commit()
    finally: c.close()

def ensure_prediction(table,a):
    if len(a)<30:return None
    target=a[-1]["id"]+1
    c=conn()
    try:
        with c.cursor(cursor_factory=RealDictCursor) as x:
            x.execute("SELECT * FROM predictions WHERE table_name=%s AND session_id=%s",(table,target))
            old=x.fetchone()
            if old:return dict(old)
        m=model(a)
        if not m:return None
        pred,prob,conf=m
        with c.cursor(cursor_factory=RealDictCursor) as x:
            x.execute("""INSERT INTO predictions(table_name,session_id,prediction,probability)
                         VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING *""",
                      (table,target,pred,conf))
            row=x.fetchone()
        c.commit()
        return dict(row) if row else None
    finally:c.close()

def process(table):
    init_db(); sync(table); a=history(table); settle(table,a); return a,ensure_prediction(table,a)

def fmt(p):
    status=p["status"]
    return {"phien":int(p["session_id"]),"ban":p["table_name"].upper(),
            "du_doan":p["prediction"],"ti_le":round(float(p["probability"])*100,1),
            "ket_qua":p["actual_result"],"trang_thai":status,
            "icon":"⏳" if status=="WAITING" else "✅" if status=="WIN" else "❌"}

@app.get("/")
def root():
    return jsonify({"ok":True,"service":"PAW DEV SERVER",
                    "endpoints":["/health","/predict?table=md5","/history?table=md5",
                                 "/thongke?table=md5","/check?table=md5"]})

@app.get("/health")
def health():
    try:init_db();return jsonify({"ok":True,"database":"connected","time":datetime.now(timezone.utc).isoformat()})
    except Exception as e:return jsonify({"ok":False,"error":str(e)}),500

@app.get("/predict")
def predict():
    table=request.args.get("table","md5").lower()
    if table not in URLS:return jsonify({"error":"table must be md5 or hu"}),400
    try:
        a,p=process(table)
        return jsonify(fmt(p)) if p else jsonify({"error":"Chưa đủ 30 phiên để tạo dự đoán","history":len(a)})
    except Exception as e:return jsonify({"error":str(e)}),500

@app.get("/history")
def hist():
    table=request.args.get("table","md5").lower()
    if table not in URLS:return jsonify({"error":"table must be md5 or hu"}),400
    try:
        a,_=process(table); c=conn()
        try:
            with c.cursor(cursor_factory=RealDictCursor) as x:
                x.execute("""SELECT * FROM predictions WHERE table_name=%s
                             ORDER BY session_id DESC LIMIT 100""",(table,))
                ps={int(r["session_id"]):dict(r) for r in x.fetchall()}
        finally:c.close()
        out=[]
        for r in a:
            p=ps.get(r["id"])
            out.append({"phien":r["id"],"ban":table.upper(),
                        "du_doan":p["prediction"] if p else None,
                        "ti_le":round(float(p["probability"])*100,1) if p else None,
                        "ket_qua":r["result"],
                        "trang_thai":p["status"] if p else None,
                        "icon":("⏳" if p and p["status"]=="WAITING" else
                                "✅" if p and p["status"]=="WIN" else
                                "❌" if p and p["status"]=="LOSE" else "—")})
        return jsonify(list(reversed(out)))
    except Exception as e:return jsonify({"error":str(e)}),500

@app.get("/thongke")
def stats():
    table=request.args.get("table","md5").lower()
    if table not in URLS:return jsonify({"error":"table must be md5 or hu"}),400
    try:
        process(table);c=conn()
        try:
            with c.cursor() as x:
                x.execute("""SELECT COUNT(*) FILTER(WHERE status='WIN'),
                             COUNT(*) FILTER(WHERE status='LOSE'),
                             COUNT(*) FILTER(WHERE status='WAITING')
                             FROM predictions WHERE table_name=%s""",(table,))
                win,lose,wait=x.fetchone()
        finally:c.close()
        total=win+lose
        return jsonify({"ban":table.upper(),"win":win,"lose":lose,"cho":wait,
                        "tong":total+wait,"ti_le_win":round(win/total*100,1) if total else None})
    except Exception as e:return jsonify({"error":str(e)}),500

@app.get("/check")
def check():return stats()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT","3000")))
