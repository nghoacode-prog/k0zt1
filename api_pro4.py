from flask import Flask, jsonify
import requests, time, threading, numpy as np

app = Flask(__name__)

@app.after_request
def cors(res):
    res.headers['Access-Control-Allow-Origin'] = '*'
    return res

API = "https://wtxmd52.tele68.com/v1/txmd5/sessions"
history = []
model_w = None
model_b = 0.0
scaler_mean = None
scaler_std = None
trained = False

# Luu du doan da dua ra: { so_phien: {"du_doan": "TAI", "prob": 0.57} }
# de sau khi co ket qua that thi doi chieu Win/Lose.
du_doan_da_luu = {}
phien_da_du_doan = None

# ===== GIAM NHIEU (cach 3 + 4) =====
# Cach 3: lam muot xac suat bang trung binh truot 5 lan gan nhat
lich_su_prob = []          # cac gia tri prob gan nhat
SO_LAN_LAM_MUOT = 5

# Cach 4: khoa huong toi thieu N van moi cho doi
huong_dang_khoa = None     # 'TAI' / 'XIU'
so_van_da_khoa = 0
SO_VAN_KHOA_TOI_THIEU = 4

# Chong LECH MOT BEN: luu lich su prob dai han de tinh NGUONG DONG.
# Neu model bi lech (VD prob luon quanh 0.56), lay chinh trung binh
# dai han lam moc giua thay vi co dinh 0.5 -> se ra ca 2 huong.
lich_su_prob_dai = []
SO_LUU_DAI = 60


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1.0 / (1.0 + np.exp(-z))


def chuan_hoa_fit(X):
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1.0
    return mean, std


def chuan_hoa(X, mean, std):
    return (X - mean) / std


def huan_luyen_logistic(X, y, so_vong=500, toc_do=0.1):
    n_mau, n_dac_trung = X.shape
    w = np.zeros(n_dac_trung)
    b = 0.0
    for _ in range(so_vong):
        p = sigmoid(X.dot(w) + b)
        w -= toc_do * (X.T.dot(p - y) / n_mau)
        b -= toc_do * (np.sum(p - y) / n_mau)
    return w, b


def fetch():
    global history
    try:
        r = requests.get(API, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data and "list" in data:
                parsed = []
                for s in data["list"]:
                    parsed.append({
                        "Phien": s["id"],
                        "Tong": sum(s["dices"]),
                        "Ket_qua": s["resultTruyenThong"],
                        "Xuc_xac": s["dices"],
                    })
                parsed.sort(key=lambda x: x["Phien"])
                history = parsed
                print(f"[DATA] {len(history)} phiên")
                train()
                luu_du_doan_moi()
    except Exception as e:
        print("[API]", e)


def train():
    global model_w, model_b, scaler_mean, scaler_std, trained
    if len(history) < 30:
        return

    recent = history[-30:]
    X, y = [], []
    for i in range(len(recent) - 1):
        cur = recent[i]
        nxt = recent[i + 1]
        avg = (cur["Tong"] + recent[max(0, i - 1)]["Tong"] + recent[max(0, i - 2)]["Tong"]) / 3
        slope = cur["Tong"] - recent[max(0, i - 1)]["Tong"]
        trend = ((cur["Ket_qua"] == "TAI")
                 + (recent[max(0, i - 1)]["Ket_qua"] == "TAI")
                 + (recent[max(0, i - 2)]["Ket_qua"] == "TAI"))
        X.append([avg, slope, trend])
        y.append(1 if nxt["Ket_qua"] == "TAI" else 0)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=float)

    scaler_mean, scaler_std = chuan_hoa_fit(X)
    X_chuan = chuan_hoa(X, scaler_mean, scaler_std)
    model_w, model_b = huan_luyen_logistic(X_chuan, y, so_vong=500, toc_do=0.1)
    trained = True
    print("[TRAIN] done")


def tinh_du_doan():
    """Tra ve (du_doan, xac_suat) cho phien tiep theo"""
    if not trained or len(history) < 10:
        return None, None

    last = history[-1]
    prev = history[-2] if len(history) > 1 else last
    prev2 = history[-3] if len(history) > 2 else last

    avg = (last["Tong"] + prev["Tong"] + prev2["Tong"]) / 3
    slope = last["Tong"] - prev["Tong"]
    trend = ((last["Ket_qua"] == "TAI")
             + (prev["Ket_qua"] == "TAI")
             + (prev2["Ket_qua"] == "TAI"))

    X_new = np.array([[avg, slope, trend]], dtype=float)
    X_new = chuan_hoa(X_new, scaler_mean, scaler_std)
    prob_tho = float(sigmoid(X_new.dot(model_w) + model_b)[0])

    # ===== CACH 3: LAM MUOT bang trung binh truot =====
    # Thay vi dung thang prob vua tinh, lay trung binh 5 lan gan nhat
    # de huong du doan khong nhay lien tuc theo tung bien dong nho.
    global lich_su_prob
    lich_su_prob.append(prob_tho)
    if len(lich_su_prob) > SO_LAN_LAM_MUOT:
        lich_su_prob = lich_su_prob[-SO_LAN_LAM_MUOT:]
    prob = float(np.mean(lich_su_prob))

    # ===== NGUONG DONG (chong lech mot ben) =====
    # Luu prob dai han, lay TRUNG BINH lam moc giua. Neu model lech
    # sang Tai (prob luon ~0.56) thi moc giua se la 0.56, khi do prob
    # 0.54 se duoc coi la "nghieng Xiu" -> ra ca 2 huong, khong dinh 1.
    global lich_su_prob_dai
    lich_su_prob_dai.append(prob_tho)
    if len(lich_su_prob_dai) > SO_LUU_DAI:
        lich_su_prob_dai = lich_su_prob_dai[-SO_LUU_DAI:]

    # Dung TRUNG VI (median) thay trung binh - chong lech tot hon.
    # Ha nguong xuong 6 mau de nguong dong hoat dong SOM, tranh
    # tinh trang 20 van dau full mot huong khi server vua khoi dong.
    if len(lich_su_prob_dai) >= 6:
        moc_giua = float(np.median(lich_su_prob_dai))
    else:
        # Chua du mau: lay chinh prob dau tien lam moc tam thoi
        moc_giua = float(np.mean(lich_su_prob_dai))

    # AUTO: ben nao xac suat CAO HON thi chon ben do, khong nguong,
    # khong "CHO" - dung nhu yeu cau.
    doan_moi = "TAI" if prob >= moc_giua else "XIU"

    # ===== CACH 4: KHOA HUONG toi thieu N van =====
    # Sau khi chon 1 huong, giu nguyen it nhat SO_VAN_KHOA_TOI_THIEU van
    # truoc khi cho phep doi sang huong nguoc lai.
    global huong_dang_khoa, so_van_da_khoa

    if doan_moi == "CHỜ":
        # Vung can bang: neu dang khoa huong nao thi giu tiep huong do
        if huong_dang_khoa and so_van_da_khoa < SO_VAN_KHOA_TOI_THIEU:
            so_van_da_khoa += 1
            return huong_dang_khoa, prob
        return "CHỜ", prob

    if huong_dang_khoa is None:
        huong_dang_khoa = doan_moi
        so_van_da_khoa = 1
        return doan_moi, prob

    if doan_moi == huong_dang_khoa:
        so_van_da_khoa += 1
        return doan_moi, prob

    # Muon doi huong -> chi cho doi khi da giu du so van toi thieu
    if so_van_da_khoa >= SO_VAN_KHOA_TOI_THIEU:
        huong_dang_khoa = doan_moi
        so_van_da_khoa = 1
        return doan_moi, prob

    # Chua du -> giu huong cu
    so_van_da_khoa += 1
    return huong_dang_khoa, prob


def luu_du_doan_moi():
    """Luu du doan cho phien TIEP THEO (chi luu 1 lan / phien)"""
    global phien_da_du_doan
    if not trained or not history:
        return
    phien_tiep = history[-1]["Phien"] + 1
    if phien_da_du_doan == phien_tiep:
        return  # da luu roi, khong ghi de
    doan, prob = tinh_du_doan()
    if doan is None:
        return
    du_doan_da_luu[phien_tiep] = {"du_doan": doan, "prob": prob}
    phien_da_du_doan = phien_tiep
    # Gioi han bo nho: chi giu 200 du doan gan nhat
    if len(du_doan_da_luu) > 200:
        for k in sorted(du_doan_da_luu.keys())[:-200]:
            del du_doan_da_luu[k]


@app.route("/predict")
def pred():
    if not trained or len(history) < 10:
        return jsonify({"error": "chua train"})
    doan, prob = tinh_du_doan()
    return jsonify({
        "Phien_tiep_theo": history[-1]["Phien"] + 1,
        "Tai": f"{prob*100:.1f}%",
        "Xiu": f"{(1-prob)*100:.1f}%",
        "Du_doan": doan,
        "Tin_cay": f"{abs(prob-0.5)*2*100:.1f}%",
        "Khoa_huong": huong_dang_khoa,
        "So_van_khoa": f"{so_van_da_khoa}/{SO_VAN_KHOA_TOI_THIEU}",
        "Lam_muot": f"{len(lich_su_prob)}/{SO_LAN_LAM_MUOT}",
    })


@app.route("/history")
def hist():
    """Lich su 40 phien gan nhat, KEM ket qua doi chieu Win/Lose"""
    ket_qua = []
    for h in history[-40:]:
        dd = du_doan_da_luu.get(h["Phien"])
        trang_thai = None  # None = khong co du doan cho phien nay
        if dd:
            trang_thai = "WIN" if dd["du_doan"] == h["Ket_qua"] else "LOSE"
            if dd["du_doan"] == "CHỜ":
                trang_thai = "SKIP"
        ket_qua.append({
            "Phien": h["Phien"],
            "Tong": h["Tong"],
            "Ket_qua": h["Ket_qua"],
            "Xuc_xac": h.get("Xuc_xac", []),
            "Du_doan": dd["du_doan"] if dd else None,
            "Trang_thai": trang_thai,
        })
    return jsonify(ket_qua)


@app.route("/thongke")
def thongke():
    """Tong ket Win/Lose tren cac phien da co du doan"""
    win = lose = skip = 0
    for h in history:
        dd = du_doan_da_luu.get(h["Phien"])
        if not dd:
            continue
        if dd["du_doan"] == "CHỜ":
            skip += 1
        elif dd["du_doan"] == h["Ket_qua"]:
            win += 1
        else:
            lose += 1
    tong = win + lose
    return jsonify({
        "Win": win, "Lose": lose, "Skip": skip,
        "Ty_le": f"{(win/tong*100):.1f}%" if tong > 0 else "--",
        "Tong_da_danh": tong,
    })


# Trang theo doi - mo http://127.0.0.1:3005
TRANG_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZETNOT AI · THEO DÕI</title>
<style>
    *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    body{
        font-family:'Segoe UI',system-ui,sans-serif;
        background:#07090f;color:#e6e9ef;min-height:100vh;padding:10px;
        background-image:radial-gradient(120% 80% at 50% 0%,rgba(240,192,64,.07),transparent 60%);
    }
    .wrap{max-width:580px;margin:0 auto}

    @keyframes nhay{0%,100%{opacity:.5}50%{opacity:1}}
    @keyframes truotLen{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
    @keyframes chayNgang{0%{transform:translateX(-100%)}100%{transform:translateX(300%)}}
    @keyframes xoay{to{transform:rotate(360deg)}}

    /* ===== HEADER ===== */
    .header{
        background:linear-gradient(135deg,#12161f,#1a2130);
        border:1px solid #232c3d;border-radius:14px;
        padding:13px;margin-bottom:10px;position:relative;overflow:hidden;
    }
    .header::after{
        content:'';position:absolute;top:0;left:0;width:30%;height:100%;
        background:linear-gradient(90deg,transparent,rgba(240,192,64,.08),transparent);
        animation:chayNgang 4s linear infinite;
    }
    .h-top{display:flex;justify-content:space-between;align-items:center}
    .header h1{
        font-size:15px;font-weight:900;letter-spacing:1.5px;
        background:linear-gradient(90deg,#f0c040,#ffe9a8,#f0c040);
        background-size:200% auto;-webkit-background-clip:text;
        -webkit-text-fill-color:transparent;animation:sang 3s linear infinite;
    }
    @keyframes sang{to{background-position:200% center}}
    .live{
        display:flex;align-items:center;gap:5px;font-size:9px;
        color:#4ade80;font-weight:800;letter-spacing:.5px;
    }
    .live i{width:6px;height:6px;border-radius:50%;background:#4ade80;animation:nhay 1.2s infinite}
    .h-time{font-size:9px;color:#5a6478;margin-top:5px}

    /* ===== NEXT ===== */
    .next{
        background:linear-gradient(135deg,#12161f,#1c2438);
        border:1.5px solid #f0c040;border-radius:14px;
        padding:14px;margin-bottom:10px;text-align:center;position:relative;
    }
    .next-lb{font-size:9px;font-weight:900;letter-spacing:2px;color:#f0c040}
    .next-ph{font-size:11px;color:#8892a4;margin:4px 0 8px;font-weight:700}
    .next-pd{font-size:30px;font-weight:900;letter-spacing:3px;line-height:1.1}
    .next-pd.tai{color:#ff4d6d;text-shadow:0 0 20px rgba(255,77,109,.45);animation:nhay 1.1s infinite}
    .next-pd.xiu{color:#38bdf8;text-shadow:0 0 20px rgba(56,189,248,.45);animation:nhay 1.1s infinite}
    .next-pd.cho{color:#5a6478;font-size:20px}
    .next-cf{font-size:10px;color:#8892a4;margin-top:5px}

    /* Thanh ty le */
    .ratio{display:flex;height:24px;border-radius:7px;overflow:hidden;margin-top:10px}
    .ratio div{
        display:flex;align-items:center;justify-content:center;
        font-size:10px;font-weight:900;transition:width .6s cubic-bezier(.22,1,.36,1);
    }
    .r-t{background:linear-gradient(90deg,#8f1229,#ff4d6d)}
    .r-x{background:linear-gradient(90deg,#38bdf8,#0e4f7d)}

    /* ===== THONG KE ===== */
    .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:10px}
    .st{
        background:#12161f;border:1px solid #232c3d;border-radius:11px;
        padding:9px 3px;text-align:center;
    }
    .st b{display:block;font-size:17px;font-weight:900;line-height:1.2}
    .st span{font-size:8px;color:#5a6478;font-weight:800;letter-spacing:.3px}
    .st.w b{color:#4ade80}.st.l b{color:#f87171}
    .st.r b{color:#f0c040}.st.s b{color:#c084fc}

    /* ===== CHUOI GAN NHAT ===== */
    .streak-card{
        background:#12161f;border:1px solid #232c3d;border-radius:12px;
        padding:10px;margin-bottom:10px;
    }
    .sc-title{font-size:9px;font-weight:900;color:#f0c040;letter-spacing:.8px;margin-bottom:7px}
    .streak{display:flex;gap:3px;flex-wrap:wrap}
    .sq{
        width:22px;height:22px;border-radius:5px;font-size:10px;
        display:flex;align-items:center;justify-content:center;font-weight:900;
        animation:truotLen .3s ease backwards;
    }
    .sq.w{background:rgba(74,222,128,.15);color:#4ade80;border:1px solid rgba(74,222,128,.35)}
    .sq.l{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.35)}
    .sq.n{background:rgba(255,255,255,.04);color:#5a6478;border:1px solid #232c3d}

    /* ===== BANG ===== */
    .tbl-card{background:#12161f;border:1px solid #232c3d;border-radius:14px;overflow:hidden}
    table{width:100%;border-collapse:collapse;table-layout:fixed}
    thead th{
        background:#1a2130;color:#f0c040;font-size:9px;font-weight:900;
        letter-spacing:.6px;padding:10px 2px;text-align:center;
        border-bottom:1px solid #232c3d;
    }
    tbody td{
        padding:9px 2px;text-align:center;font-size:11px;
        border-bottom:1px solid #161c28;
    }
    tbody tr{animation:truotLen .35s ease backwards}
    tbody tr:last-child td{border-bottom:none}
    tbody tr.win{background:linear-gradient(90deg,rgba(74,222,128,.09),transparent)}
    tbody tr.lose{background:linear-gradient(90deg,rgba(248,113,113,.09),transparent)}
    tbody tr.win td:first-child{box-shadow:inset 3px 0 0 #4ade80}
    tbody tr.lose td:first-child{box-shadow:inset 3px 0 0 #f87171}

    th:nth-child(1),td:nth-child(1){width:24%}
    th:nth-child(2),td:nth-child(2){width:14%}
    th:nth-child(3),td:nth-child(3){width:22%}
    th:nth-child(4),td:nth-child(4){width:22%}
    th:nth-child(5),td:nth-child(5){width:18%}

    .c-ph{color:#5a6478;font-weight:700;font-size:10px}
    .c-tg{color:#f0c040;font-weight:900;font-size:12px}
    .bdg{
        display:inline-block;padding:3px 0;border-radius:6px;
        font-size:10px;font-weight:900;width:46px;
    }
    .bdg.tai{background:rgba(255,77,109,.16);color:#ff6b85;border:1px solid rgba(255,77,109,.38)}
    .bdg.xiu{background:rgba(56,189,248,.16);color:#5ecdff;border:1px solid rgba(56,189,248,.38)}
    .bdg.cho{background:rgba(255,255,255,.05);color:#5a6478;border:1px solid #232c3d}
    .c-wl{font-size:13px}

    .loading{
        text-align:center;color:#5a6478;padding:26px;font-size:11px;
    }
    .loading i{
        display:inline-block;width:14px;height:14px;border-radius:50%;
        border:2px solid #232c3d;border-top-color:#f0c040;
        animation:xoay .8s linear infinite;vertical-align:-3px;margin-right:6px;
    }

    .credit{
        text-align:center;margin-top:12px;padding:11px;
        background:linear-gradient(120deg,rgba(240,192,64,.14),rgba(192,132,252,.14));
        border:1.5px solid rgba(240,192,64,.4);border-radius:11px;
        font-size:13px;font-weight:900;letter-spacing:1.6px;color:#f0c040;
        animation:nhay 1.9s ease-in-out infinite;
    }
</style>
</head>
<body>
<div class="wrap">
    <div class="header">
        <div class="h-top">
            <h1>ZETNOT AI</h1>
            <span class="live"><i></i>LIVE</span>
        </div>
        <div class="h-time">Cập nhật: <span id="tg">--:--:--</span> · <span id="tongVan">0</span> ván</div>
    </div>

    <div class="next">
        <div class="next-lb">▶ DỰ ĐOÁN PHIÊN TỚI</div>
        <div class="next-ph" id="nextPh">#------</div>
        <div class="next-pd cho" id="nextPd">CHỜ</div>
        <div class="next-cf" id="nextCf">Độ tin cậy: --</div>
        <div class="ratio">
            <div class="r-t" id="rT" style="width:50%">50%</div>
            <div class="r-x" id="rX" style="width:50%">50%</div>
        </div>
    </div>

    <div class="stats">
        <div class="st w"><b id="sW">0</b><span>THẮNG</span></div>
        <div class="st l"><b id="sL">0</b><span>THUA</span></div>
        <div class="st r"><b id="sR">--</b><span>TỶ LỆ</span></div>
        <div class="st s"><b id="sS">0</b><span>CHUỖI</span></div>
    </div>

    <div class="streak-card">
        <div class="sc-title">20 PHIÊN GẦN NHẤT</div>
        <div class="streak" id="streak"></div>
    </div>

    <div class="tbl-card">
        <table>
            <thead>
                <tr>
                    <th>PHIÊN</th><th>TỔNG</th><th>DỰ ĐOÁN</th><th>KẾT QUẢ</th><th>W/L</th>
                </tr>
            </thead>
            <tbody id="tb">
                <tr><td colspan="5" class="loading"><i></i>Đang tải...</td></tr>
            </tbody>
        </table>
    </div>

    <div class="credit">TELE @ZETNOT1</div>
</div>

<script>
    async function capNhat(){
        try{
            const [p,h,t] = await Promise.all([
                fetch('/predict').then(r=>r.json()),
                fetch('/history').then(r=>r.json()),
                fetch('/thongke').then(r=>r.json()),
            ]);

            document.getElementById('tg').textContent = new Date().toLocaleTimeString('vi-VN');
            document.getElementById('tongVan').textContent = h.length;

            // NEXT
            if(!p.error){
                document.getElementById('nextPh').textContent = '#'+p.Phien_tiep_theo;
                document.getElementById('nextCf').textContent = 'Độ tin cậy: '+p.Tin_cay;
                const el = document.getElementById('nextPd');
                const d = p.Du_doan;
                el.textContent = d==='TAI'?'TÀI':(d==='XIU'?'XỈU':'CHỜ');
                el.className = 'next-pd '+(d==='TAI'?'tai':(d==='XIU'?'xiu':'cho'));

                const tai = parseFloat(p.Tai)||50;
                document.getElementById('rT').style.width = tai+'%';
                document.getElementById('rT').textContent = p.Tai;
                document.getElementById('rX').style.width = (100-tai)+'%';
                document.getElementById('rX').textContent = p.Xiu;
            }

            // THONG KE
            document.getElementById('sW').textContent = t.Win||0;
            document.getElementById('sL').textContent = t.Lose||0;
            document.getElementById('sR').textContent = t.Ty_le||'--';

            // CHUOI + dem chuoi hien tai
            const coKQ = h.filter(v=>v.Trang_thai);
            let chuoi = 0, loai = null;
            for(let i=coKQ.length-1;i>=0;i--){
                const s = coKQ[i].Trang_thai;
                if(s!=='WIN'&&s!=='LOSE') break;
                if(loai===null){loai=s;chuoi=1}
                else if(s===loai) chuoi++;
                else break;
            }
            const elS = document.getElementById('sS');
            elS.textContent = (loai==='WIN'?'+':'-')+chuoi;
            elS.style.color = loai==='WIN'?'#4ade80':'#f87171';

            document.getElementById('streak').innerHTML = h.slice(-20).map((v,i)=>{
                const c = v.Trang_thai==='WIN'?'w':(v.Trang_thai==='LOSE'?'l':'n');
                const ic = v.Trang_thai==='WIN'?'✓':(v.Trang_thai==='LOSE'?'✕':'·');
                return `<span class="sq ${c}" style="animation-delay:${i*15}ms">${ic}</span>`;
            }).join('');

            // BANG
            document.getElementById('tb').innerHTML = h.slice(-20).reverse().map((v,i)=>{
                const cls = v.Trang_thai==='WIN'?'win':(v.Trang_thai==='LOSE'?'lose':'');
                const ic = v.Trang_thai==='WIN'?'✅':(v.Trang_thai==='LOSE'?'❌':'—');
                const dd = v.Du_doan==='TAI'?'TÀI':(v.Du_doan==='XIU'?'XỈU':'CHỜ');
                const cD = v.Du_doan==='TAI'?'tai':(v.Du_doan==='XIU'?'xiu':'cho');
                const kq = v.Ket_qua==='TAI'?'TÀI':'XỈU';
                const cK = v.Ket_qua==='TAI'?'tai':'xiu';
                return `<tr class="${cls}" style="animation-delay:${i*20}ms">
                    <td class="c-ph">#${v.Phien}</td>
                    <td class="c-tg">${v.Tong}</td>
                    <td><span class="bdg ${cD}">${dd}</span></td>
                    <td><span class="bdg ${cK}">${kq}</span></td>
                    <td class="c-wl">${ic}</td>
                </tr>`;
            }).join('');
        }catch(e){
            document.getElementById('tg').textContent = 'Mất kết nối';
        }
    }
    capNhat();
    setInterval(capNhat,3000);
</script>
</body>
</html>
"""


@app.route("/")
def home():
    return TRANG_HTML


if __name__ == "__main__":
    fetch()
    threading.Thread(
        target=lambda: [time.sleep(3) or fetch() for _ in iter(int, 1)],
        daemon=True
    ).start()
    app.run(host="0.0.0.0", port=3005)
