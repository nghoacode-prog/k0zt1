# -*- coding: utf-8 -*-
"""LC79 deterministic prediction engine and SQLite persistence."""
from __future__ import annotations
import ast
import json
import math
import os
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/tmp/lc79.db")
TABLES = {
    "lc79_tx": {"name": "Bàn Hũ", "url": "https://wtx.tele68.com/v1/tx/sessions"},
    "lc79_md5": {"name": "Bàn MD5", "url": "https://wtxmd52.tele68.com/v1/txmd5/sessions"},
}

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def db():
    parent = Path(DATABASE_PATH).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
CREATE TABLE IF NOT EXISTS tables_ (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    game_code TEXT NOT NULL,
    game_name TEXT NOT NULL,
    upstream_url TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS table_states (
    table_code TEXT PRIMARY KEY REFERENCES tables_(code),
    history_json TEXT,
    last_seen_id INTEGER DEFAULT 0,
    last_poll_at TEXT,
    last_poll_error TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_code TEXT NOT NULL,
    session_id INTEGER NOT NULL,
    prediction TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    actual TEXT,
    result TEXT,
    resolved_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pred_unique ON predictions(table_code, session_id);
CREATE INDEX IF NOT EXISTS idx_pred_table ON predictions(table_code, session_id DESC);
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    note TEXT,
    is_active INTEGER DEFAULT 1,
    expires_at TEXT,
    days INTEGER DEFAULT 7,
    max_devices INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT,
    activated INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_key_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL REFERENCES api_keys(key),
    device_id TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    browser TEXT,
    os TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    released_at TEXT,
    released_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_key ON api_key_devices(key, released_at);
CREATE TABLE IF NOT EXISTS activation_codes (
    code TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    days INTEGER NOT NULL,
    max_uses INTEGER DEFAULT -1,
    used_count INTEGER DEFAULT 0,
    expires_at TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT, code TEXT, success INTEGER,
    ip TEXT, user_agent TEXT, reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user TEXT, action TEXT, target TEXT,
    detail_json TEXT, ip TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS engine_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_code TEXT NOT NULL,
    reason TEXT NOT NULL,
    accuracy_before REAL,
    sessions_at_reset INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT, window TEXT, count INTEGER,
    PRIMARY KEY (key, window)
);
""")
    # Migration không phá schema cũ.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(predictions)").fetchall()}
    if "detail_json" not in cols:
        conn.execute("ALTER TABLE predictions ADD COLUMN detail_json TEXT")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS prediction_resolutions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, table_code TEXT NOT NULL,
      session_id INTEGER NOT NULL, prediction TEXT, actual TEXT, result TEXT,
      regime TEXT, regime_conf REAL, confidence INTEGER, top_module TEXT,
      top_module_p REAL, module_votes_json TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_resol_unique ON prediction_resolutions(table_code,session_id);
    CREATE INDEX IF NOT EXISTS idx_resol_date ON prediction_resolutions(created_at);
    CREATE TABLE IF NOT EXISTS table_configs(table_code TEXT PRIMARY KEY,config_json TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS broadcasts(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS worker_control(key TEXT PRIMARY KEY,value TEXT,updated_at TEXT);
    """)
    for i, (code, meta) in enumerate(TABLES.items(), 1):
        conn.execute("INSERT OR IGNORE INTO tables_(code,name,game_code,game_name,upstream_url,is_active,sort_order) VALUES(?,?,?,?,?,1,?)",
                     (code, meta["name"], "lc79", "LC79", meta["url"], i))
        conn.execute("INSERT OR IGNORE INTO table_states(table_code) VALUES(?)", (code,))
    conn.commit()
    conn.close()

def parse_upstream(raw):
    if not isinstance(raw, dict): return None
    items = raw.get("list")
    if not isinstance(items, list) or not items: return None
    sessions = []
    for item in items:
        if not isinstance(item, dict): continue
        try: sid = int(item.get("id", 0))
        except (TypeError, ValueError): continue
        if sid <= 0: continue
        rs = str(item.get("resultTruyenThong", "")).strip().upper()
        if rs == "TAI": result = 1
        elif rs == "XIU": result = 0
        else: continue
        dices = item.get("dices")
        if not isinstance(dices, list) or len(dices) != 3: dices = None
        point = item.get("point")
        if not isinstance(point, int) or not (3 <= point <= 18):
            point = sum(dices) if dices else None
        sessions.append({"session_id": sid, "result": result, "dices": dices, "tong": point})
    sessions.sort(key=lambda s: s["session_id"])
    if not sessions: return None
    return {"sessions": sessions, "latest_id": sessions[-1]["session_id"]}

# ---------------------------------------------------------------------------
# Tám module thống kê chuyên biệt
# ---------------------------------------------------------------------------
class TransitionModule:
    name = "transition"
    def __init__(self): self.one = {}; self.two = {}
    @staticmethod
    def bucket(run: int) -> int: return run if run <= 7 else 8
    @staticmethod
    def current(hist):
        if not hist: return None, 0
        v=hist[-1]; n=1
        for x in reversed(hist[:-1]):
            if x != v: break
            n += 1
        return v,n
    def update(self,hist,y):
        prev,run=self.current(hist)
        if prev is None:return
        k=(prev,self.bucket(run)); self.one.setdefault(k,[2.0,2.0])[int(y)] += 1
        if len(hist)>=2:
            k2=(hist[-2],hist[-1]); self.two.setdefault(k2,[2.0,2.0])[int(y)] += 1
    def predict(self,hist):
        prev,run=self.current(hist)
        if prev is None:return .5,0.0,{}
        a=self.one.get((prev,self.bucket(run)),[2.,2.]); b=self.two.get((hist[-2],prev),[2.,2.]) if len(hist)>=2 else [2.,2.]
        p1=a[1]/sum(a); p2=b[1]/sum(b); n1=sum(a)-4; n2=sum(b)-4
        w2=max(0,n2)/(max(0,n1)+max(0,n2)+1e-9); p=p1*(1-w2)+p2*w2
        conf=min(1,abs(p-.5)*2)*(1-min(1,4/(n1+n2+4)))
        return p,conf,{"prev":prev,"run":run,"p_1step":round(p1,4),"p_2step":round(p2,4),"samples_1step":max(0,int(n1)),"samples_2step":max(0,int(n2))}

class StreakLengthModule:
    name="streak_length"
    def __init__(self): self.reaching={}; self.ending={}
    @staticmethod
    def _run(hist): return TransitionModule.current(hist)
    def update(self,hist,y):
        prev,run=self._run(hist)
        if prev is None:return
        for L in range(1,min(run,15)+1): self.reaching[L]=self.reaching.get(L,0)+1
        self.reaching[min(run+1,15)]=self.reaching.get(min(run+1,15),0)+1
        if y!=prev:self.ending[min(run,15)]=self.ending.get(min(run,15),0)+1
    def predict(self,hist):
        prev,run=self._run(hist)
        if prev is None:return .5,0.,{}
        L=min(run,15); reach=self.reaching.get(L,0); end=self.ending.get(L,0)
        hazard=(end+1.5)/(reach+3.0); survival={str(i):round(max(0,1-(self.ending.get(i,0)+1.5)/(self.reaching.get(i,0)+3)),4) for i in range(1,16)}
        remaining=sum(max(0,1-(self.ending.get(i,0)+1.5)/(self.reaching.get(i,0)+3)) for i in range(L,16))
        p_continue=1-hazard; p=p_continue if prev==1 else 1-p_continue
        conf=min(1,abs(p-.5)*2)*min(1,reach/20)
        return p,conf,{"run":run,"hazard_rate":round(hazard,4),"expected_remaining":round(remaining,2),"survival_curve":survival}

class BreakModule:
    name="break"
    def __init__(self): self.counts={}
    @staticmethod
    def _state(hist):
        if len(hist)<3 or hist[-1]==hist[-2]:return None
        before=hist[-2]; run=1
        for x in reversed(hist[:-2]):
            if x!=before:break
            run+=1
        return hist[-1],before,run
    def update(self,hist,y):
        st=self._state(hist)
        if st:
            prev,_,run=st; cell=self.counts.setdefault(min(run,15),[1.,1.]); cell[0 if y==prev else 1]+=1
    def predict(self,hist):
        st=self._state(hist)
        if not st:return .5,0.,{}
        prev,_,run=st; c=self.counts.get(min(run,15),[1.,1.]); keep=c[0]/sum(c); p=keep if prev else 1-keep
        return p,min(1,abs(keep-.5)*2)*min(1,(sum(c)-2)/15),{"run_before":run,"prev":prev,"p_keep":round(keep,4),"samples":int(sum(c)-2)}

class FrequencyModule:
    name="frequency"
    def update(self,hist,y): pass
    def predict(self,hist):
        if not hist:return .5,0.,{}
        decay=0.5**(1/15); a=b=0.
        for v in hist:
            a*=decay;b*=decay
            if v:a+=1
            else:b+=1
        ew=a/(a+b); allp=sum(hist)/len(hist); drift=ew-allp
        p=max(.05,min(.95,.5+drift*min(1,len(hist)/50)))
        return p,min(1,abs(p-.5)*2),{"p_tai_ewma":round(ew,4),"p_tai_all":round(allp,4),"drift":round(drift,4),"samples":len(hist)}

class StreakEndModule:
    name="streak_end"
    def __init__(self):self.attempts={};self.ends={}
    @staticmethod
    def _bucket(run):return 2 if run<=2 else 3 if run==3 else 4 if run==4 else 5
    def update(self,hist,y):
        prev,run=TransitionModule.current(hist)
        if prev is None:return
        b=self._bucket(run);self.attempts[b]=self.attempts.get(b,0)+1
        if y!=prev:self.ends[b]=self.ends.get(b,0)+1
    def predict(self,hist):
        prev,run=TransitionModule.current(hist)
        if prev is None or run<2:return .5,0.,{}
        b=self._bucket(run);n=self.attempts.get(b,0);haz=(self.ends.get(b,0)+1)/(n+2);cont=1-haz;p=cont if prev else 1-cont
        return p,min(1,abs(p-.5)*2)*min(1,n/20),{"run":run,"block_size":b,"hazard_rate":round(haz,4),"samples":n}

class StabilityModule:
    name="stability"
    def update(self,hist,y):pass
    def predict(self,hist):
        if len(hist)<3:return .5,0.,{}
        vals={w:sum(hist[i]==hist[i-1] for i in range(max(1,len(hist)-w+1),len(hist)))/max(1,min(w,len(hist))-1) for w in (10,20,50)}
        weights={w:1/w for w in vals}; same=sum(vals[w]*weights[w] for w in vals)/sum(weights.values());trend=vals[10]-vals[50];prev=hist[-1]
        p=prev*same+(1-prev)*(1-same);state="stable" if same>.55 else "unstable" if same<.45 else "neutral"
        return p,min(1,abs(same-.5)*2),{"p_same_10":round(vals[10],4),"p_same_20":round(vals[20],4),"p_same_50":round(vals[50],4),"trend":round(trend,4),"state":state}

class MomentumModule:
    name="momentum"
    def update(self,hist,y):pass
    def predict(self,hist):
        if len(hist)<5:return .5,0.,{}
        p5=sum(hist[-5:])/len(hist[-5:]);p10=sum(hist[-10:])/len(hist[-10:]);p20=sum(hist[-20:])/len(hist[-20:]);m=((p5-p10)+(p5-p20)+(p10-p20))/3;acc=(p5-p10)-(p10-p20);p=max(.05,min(.95,.5+m*(1+.5*acc)))
        return p,min(1,abs(m)*4),{"p_short":round(p5,4),"p_mid":round(p10,4),"p_long":round(p20,4),"momentum_avg":round(m,4),"acceleration":round(acc,4)}

class BaseRateModule:
    name="base_rate"
    def __init__(self):self.ag=self.bg=self.ar=self.br=1.;self.n=0
    def update(self,hist,y):
        self.ag*=.998;self.bg*=.998;self.ar*=.99;self.br*=.99
        if y:self.ag+=1;self.ar+=1
        else:self.bg+=1;self.br+=1
        self.n+=1
    def predict(self,hist):
        pg=self.ag/(self.ag+self.bg);pr=self.ar/(self.ar+self.br);sur=abs(pr-pg);blend=min(.85,max(.35,sur/.15)) if sur>.15 else .35;p=pg*(1-blend)+pr*blend
        return p,min(1,abs(p-.5)*2),{"p_global":round(pg,4),"p_recent":round(pr,4),"surprise":round(sur,4),"samples_global":self.n,"samples_recent":self.n}

class RegimeClassifier:
    def state(self,hist):
        if len(hist)<10:return "WARMUP",0.,{"block_lengths":[],"dominant_pattern":"WARMUP","pattern_strength":0.,"confidence":0.}
        h=hist[-30:];blocks=[]
        for v in h:
            if not blocks or blocks[-1][0]!=v:blocks.append([v,1])
            else:blocks[-1][1]+=1
        lengths=[b[1] for b in blocks];run=lengths[-1];same=sum(h[i]==h[i-1] for i in range(1,len(h)))/(len(h)-1);bias=sum(h)/len(h)
        # Pattern block 2-2, 3-3 and alternation.
        pair22=len(h)>=8 and all(h[i]==h[i+1] for i in range(0,8,2)) and all(h[i]!=h[i+2] for i in range(0,6,2))
        triple33=len(h)>=12 and all(h[i]==h[i+1]==h[i+2] for i in range(0,12,3)) and all(h[i]!=h[i+3] for i in range(0,9,3))
        cross3=len(h)>=6 and all(h[i]!=h[i-1] for i in range(1,7))
        if run>=8:r="BET_8plus";strength=min(1,run/12)
        elif run>=5:r="BET_5to7";strength=run/7
        elif run>=2 and same>.52:r="BET_2plus";strength=min(1,.5+same/2)
        elif triple33:r="DAO_3_3";strength=.85
        elif pair22:r="DAO_2_2";strength=.8
        elif cross3:r="CROSS_3";strength=.75
        elif len(h)>=6 and all(h[i]!=h[i-1] for i in range(1,6)):r="DAO_1_1";strength=.8
        elif bias>.58:r="BIAS_TAI";strength=min(1,(bias-.5)*3)
        elif bias<.42:r="BIAS_XIU";strength=min(1,(.5-bias)*3)
        else:r="RANDOM";strength=max(0,1-abs(same-.5)*3)
        conf=max(0,min(1,strength));return r,conf,{"block_lengths":lengths,"dominant_pattern":r,"pattern_strength":round(strength,4),"confidence":round(conf,4),"p_same":round(same,4),"bias_tai":round(bias,4),"autocorrelation_lag_1":round(same,4),"autocorrelation_lag_2":round(sum(h[i]==h[i-2] for i in range(2,len(h)))/(len(h)-2),4),"autocorrelation_lag_3":round(sum(h[i]==h[i-3] for i in range(3,len(h)))/(len(h)-3),4)}

class PredictionEngine:
    EXPERTS=("transition","streak_length","break","frequency","streak_end","stability","momentum","base_rate")
    def __init__(self,history=None,table_code=""):
        self.table_code=table_code;self.config=dict(TABLE_CONFIG.get(table_code,{}));self.history=[]
        if table_code:
            try:self.config=get_table_config(table_code)
            except Exception:pass
        self.transition=TransitionModule();self.streak_length=StreakLengthModule();self.break_module=BreakModule();self.frequency=FrequencyModule();self.streak_end=StreakEndModule();self.stability=StabilityModule();self.momentum=MomentumModule();self.base_rate=BaseRateModule();self.classifier=RegimeClassifier()
        self.adaptive_weights={n:1. for n in self.EXPERTS};self.module_stats={n:{"loss":0.,"n":0} for n in self.EXPERTS}
        for v in list(history or []):self._update(1 if int(v)==1 else 0,learn=False)
    def _update(self,y,learn=True):
        hist=self.history[:]
        if learn and len(hist)>=30:
            for name,(p,_,_) in self._modules().items():
                loss=-(y*math.log(max(1e-6,p))+(1-y)*math.log(max(1e-6,1-p)));st=self.module_stats[name];st["loss"]+=loss;st["n"]+=1
                baseline=math.log(2);lr=.05/math.sqrt(1+st["n"]/100);self.adaptive_weights[name]=max(.2,min(3.,self.adaptive_weights[name]*math.exp(-lr*(loss-baseline))))
        self.transition.update(hist,y);self.streak_length.update(hist,y);self.break_module.update(hist,y);self.frequency.update(hist,y);self.streak_end.update(hist,y);self.stability.update(hist,y);self.momentum.update(hist,y);self.base_rate.update(hist,y);self.history.append(y)
    def _modules(self):return {"transition":self.transition.predict(self.history),"streak_length":self.streak_length.predict(self.history),"break":self.break_module.predict(self.history),"frequency":self.frequency.predict(self.history),"streak_end":self.streak_end.predict(self.history),"stability":self.stability.predict(self.history),"momentum":self.momentum.predict(self.history),"base_rate":self.base_rate.predict(self.history)}
    @staticmethod
    def _clamp(v,lo,hi):return max(lo,min(hi,v))
    def _regime_weights(self,regime):
        base={n:1. for n in self.EXPERTS}
        if regime.startswith("BET"):base.update({"transition":1.8,"streak_length":2.,"streak_end":1.8,"stability":1.4,"break":.6})
        elif regime.startswith("DAO") or regime=="CROSS_3":base.update({"transition":1.8,"break":1.8,"streak_length":.5,"streak_end":.5,"momentum":.7})
        elif regime.startswith("BIAS"):base.update({"frequency":2.,"base_rate":2.,"momentum":1.4})
        return base
    def predict(self,accuracy_100=.5,accuracy_500=.5):
        n=len(self.history);regime,rc,rd=self.classifier.state(self.history);mods=self._modules();cfg=self.config
        disabled=set(cfg.get("disabled_modules",[]));regw=self._regime_weights(regime);weights={k:regw[k]*self.adaptive_weights[k] for k in self.EXPERTS}
        active={k:v for k,v in mods.items() if k not in disabled};num=den=0.
        for k,(pm,cm,_) in active.items():w=weights[k]*(.2+.8*cm);num+=pm*w;den+=w
        p=num/den if den else .5;base_shrink=.5 if n<50 else .7 if n<200 else .85 if n<500 else 1.;shrink=base_shrink*(.7+.3*rc)*float(cfg.get("shrink_extra",1.));p=.5+(p-.5)*max(0,min(1,shrink));p=self._clamp(p,.05,.95)
        edge=abs(p-.5)*2;conf=int(round(50+35*edge));conf=max(int(cfg.get("min_confidence",50)),min(85,conf));side="TAI" if p>=.5 else "XIU"
        mv={k:{"p":round(float(pm),4),"conf":round(float(cm),4),"weight":round(weights[k],4),"details":d} for k,(pm,cm,d) in mods.items()}
        top=sorted(mv.items(),key=lambda z:z[1]["weight"],reverse=True)[:3];explanation=self.get_explanation({"regime":regime,"regime_conf":rc,"modules":mv,"side":side})
        full={"regime":regime,"regime_conf":rc,"regime_details":rd,"modules":mv,"weights":regw,"adaptive_weights":self.adaptive_weights.copy(),"p_internal":p,"explanation":explanation}
        return {"side":side if n>=30 else None,"confidence":conf if n>=30 else 50,"p_internal":p if n>=30 else .5,"regime":regime,"regime_conf":rc,"regime_details":rd,"modules":mv,"weights":regw,"adaptive_weights":self.adaptive_weights.copy(),"skip":n<30,"reason":"warmup" if n<30 else None,"is_uncertain":n<30 or regime=="RANDOM" or edge<.04,"full":full}
    def predict_detail(self):return self.predict()
    def get_explanation(self,prediction_dict):
        ms=prediction_dict.get("modules",{});top=sorted(ms.items(),key=lambda x:x[1].get("weight",0),reverse=True)[:3];parts=[f"{n}={v.get('p',.5):.2f}(w={v.get('weight',1):.2f})" for n,v in top]
        return f"Regime {prediction_dict.get('regime','WARMUP')} (conf {prediction_dict.get('regime_conf',0):.2f}), top 3: {', '.join(parts)} → vote {prediction_dict.get('side') or 'chờ'}"
    def observe(self,result):self._update(1 if int(result)==1 else 0,learn=True)
    def to_dict(self):return {"history":list(self.history),"adaptive_weights":self.adaptive_weights,"module_stats":self.module_stats,"table_code":self.table_code}
    @classmethod
    def from_history(cls,history):return cls(history=history)
    @classmethod
    def from_dict(cls,data):
        if not isinstance(data,dict):return cls()
        obj=cls(history=data.get("history",[]),table_code=data.get("table_code",""));obj.adaptive_weights.update({k:float(v) for k,v in data.get("adaptive_weights",{}).items() if k in obj.EXPERTS});obj.module_stats.update(data.get("module_stats",{}));return obj

class Backtest:
    @staticmethod
    def run(history,warmup=30):
        eng=PredictionEngine();rows=[];correct=0;by_regime={};by_conf={};by_side={};by_module={n:[0,0] for n in PredictionEngine.EXPERTS};wins=losses=0;bestw=bestl=0
        for y in history:
            pred=eng.predict();
            if len(eng.history)>=warmup:
                ok=pred.get("side")==("TAI" if y else "XIU");correct+=int(ok);wins=wins+1 if ok else 0;losses=losses+1 if not ok else 0;bestw=max(bestw,wins);bestl=max(bestl,losses)
                for mn,mv in pred.get("modules",{}).items():
                    mok=(float(mv.get("p",.5))>=.5)==bool(y);by_module[mn][0]+=1;by_module[mn][1]+=int(mok)
                r=pred["regime"];bucket=str((pred["confidence"]//5)*5);by_regime.setdefault(r,[0,0]);by_regime[r][0]+=1;by_regime[r][1]+=int(ok);by_conf.setdefault(bucket,[0,0]);by_conf[bucket][0]+=1;by_conf[bucket][1]+=int(ok);side=pred.get("side") or "NAI";by_side.setdefault(side,[0,0]);by_side[side][0]+=1;by_side[side][1]+=int(ok);rows.append({"actual":y,"prediction":side,"correct":ok,"regime":r,"confidence":pred["confidence"]})
            eng.observe(y)
        total=len(rows);return {"total_predictions":total,"correct":correct,"accuracy":correct/total if total else 0.,"by_regime":by_regime,"by_confidence_bucket":by_conf,"by_side":by_side,"by_module":{k:{"votes":v[0],"correct":v[1],"accuracy":v[1]/v[0] if v[0] else 0.} for k,v in by_module.items()},"streak_wins":bestw,"streak_losses":bestl,"timeline":rows}

TABLE_CONFIG={"lc79_tx":{"disabled_modules":[],"shrink_extra":1.0,"min_confidence":50},"lc79_md5":{"disabled_modules":[],"shrink_extra":1.0,"min_confidence":50}}

def get_table_config(table_code):
    c=db();r=c.execute("SELECT config_json FROM table_configs WHERE table_code=?",(table_code,)).fetchone();c.close();cfg=dict(TABLE_CONFIG.get(table_code,{}));
    if r:
        try:cfg.update(json.loads(r[0] or "{}"))
        except Exception:pass
    return cfg

def save_table_config(table_code,config):
    c=db();c.execute("INSERT INTO table_configs(table_code,config_json,updated_at) VALUES(?,?,?) ON CONFLICT(table_code) DO UPDATE SET config_json=excluded.config_json,updated_at=excluded.updated_at",(table_code,json.dumps(config),now_iso()));c.commit();c.close()

def resolve_actual(table_code,sessions):
    c=db();count=0
    for x in sessions:
        sid=int(x.get("session_id",0));actual="TAI" if int(x.get("result",0))==1 else "XIU";r=c.execute("SELECT * FROM predictions WHERE table_code=? AND session_id=? AND actual IS NOT NULL",(table_code,sid)).fetchone()
        if not r:continue
        result="win" if r["prediction"]==actual else "lose";detail={}
        try:detail=json.loads(r["detail_json"] or "{}")
        except Exception:pass
        modules=detail.get("modules",{});top=max(modules.items(),key=lambda z:z[1].get("weight",0)) if modules else (None,{})
        c.execute("UPDATE predictions SET actual=?,result=?,resolved_at=? WHERE id=?",(actual,result,now_iso(),r["id"]))
        c.execute("INSERT OR IGNORE INTO prediction_resolutions(table_code,session_id,prediction,actual,result,regime,regime_conf,confidence,top_module,top_module_p,module_votes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(table_code,sid,r["prediction"],actual,result,detail.get("regime"),detail.get("regime_conf"),r["confidence"],top[0],top[1].get("p"),json.dumps(modules)))
        count+=1
    c.commit();c.close();return count

def accuracy_detail(table_code,days=7):
    c=db();r=c.execute("SELECT COUNT(*) total,SUM(result='win') wins,SUM(result='lose') losses FROM predictions WHERE table_code=? AND result IS NOT NULL AND resolved_at>=datetime('now',?)",(table_code,f"-{int(days)} days")).fetchone();c.close();total=r["total"] or 0;wins=r["wins"] or 0;return {"total":total,"wins":wins,"losses":r["losses"] or 0,"accuracy":wins/total if total else 0.}

def get_broadcast():
    c=db();r=c.execute("SELECT message FROM broadcasts WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone();c.close();return r[0] if r else ""
def set_worker_control(key,value):
    c=db();c.execute("INSERT INTO worker_control(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(key,str(value),now_iso()));c.commit();c.close()
def get_worker_control(key,default=None):
    c=db();r=c.execute("SELECT value FROM worker_control WHERE key=?",(key,)).fetchone();c.close();return r[0] if r else default

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def load_engine(table_code):
    conn=db(); row=conn.execute("SELECT history_json FROM table_states WHERE table_code=?",(table_code,)).fetchone(); conn.close()
    try: state=json.loads(row["history_json"] or '{"history":[]}') if row else {"history":[]}
    except (ValueError,TypeError): state={"history":[]}
    obj=PredictionEngine.from_dict(state)
    obj.table_code=table_code
    obj.config=get_table_config(table_code)
    return obj

def save_engine(table_code, engine):
    conn=db(); conn.execute("UPDATE table_states SET history_json=?,updated_at=? WHERE table_code=?",
        (json.dumps(engine.to_dict(),separators=(",",":")),now_iso(),table_code)); conn.commit(); conn.close()

def load_last_seen(table_code):
    conn=db(); row=conn.execute("SELECT last_seen_id FROM table_states WHERE table_code=?",(table_code,)).fetchone(); conn.close()
    return int(row[0]) if row else 0

def save_last_seen(table_code, session_id):
    conn=db(); conn.execute("UPDATE table_states SET last_seen_id=?,updated_at=? WHERE table_code=?",(int(session_id),now_iso(),table_code)); conn.commit(); conn.close()

def save_worker_state(table_code, engine, session_id):
    """Ghi model và last_seen trong cùng transaction để tránh học lặp sau crash."""
    conn=db()
    conn.execute("UPDATE table_states SET history_json=?,last_seen_id=?,updated_at=? WHERE table_code=?",
        (json.dumps(engine.to_dict(),separators=(",",":")),int(session_id),now_iso(),table_code))
    conn.commit(); conn.close()

def mark_poll_ok(table_code):
    conn=db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=NULL,updated_at=? WHERE table_code=?",(now_iso(),now_iso(),table_code)); conn.commit(); conn.close()

def mark_poll_error(table_code,error):
    conn=db(); conn.execute("UPDATE table_states SET last_poll_at=?,last_poll_error=?,updated_at=? WHERE table_code=?",(now_iso(),str(error)[:500],now_iso(),table_code)); conn.commit(); conn.close()

def accuracy(table_code, limit=100):
    conn=db(); rows=conn.execute("SELECT result FROM predictions WHERE table_code=? AND result IS NOT NULL ORDER BY session_id DESC LIMIT ?",(table_code,int(limit))).fetchall(); conn.close()
    return (sum(r[0]=="win" for r in rows)/len(rows)) if rows else .5

# === END engine.py ===
