#!/usr/bin/env python3
"""
analisis_harian.py
Ringkasan harian log UFW BLOCK per IP penyerang -> hasil-<tanggal><bulan>-ufw.csv

Hanya sisi penyerang yang disimpan (IP sumber, port, waktu).
Alamat server, MAC, dan nama host TIDAK ikut ke output.

Contoh:
  python analisis_harian.py --input rekap_ufw.csv --tanggal "Oct 25" --ref flagged_ip_summary.csv
  python analisis_harian.py --input /var/log/ufw.log --tanggal "Oct 26" --ref flagged_ip_summary.csv hasil-25oct-ufw.csv
  python analisis_harian.py --input ufw.log --tanggal "Oct 26" --abaikan 203.0.113.7,203.0.113.8

Catatan:
- total_percobaan = jumlah BARIS log yang diblok (bukan koneksi unik). koneksi_unik dan
  rasio_ulang membantu mendeteksi satu koneksi yang diulang (retransmisi).
- Model ML dilatih ulang pada data hari itu saja (k=4, contamination=0.02, random_state=42).
  Nomor klaster sudah diurutkan: 0 = paling ringan ... 3 = paling ekstrem.
- Kalau log terpotong di tengah hari, lihat kolom pertama_terlihat / terakhir_terlihat
  atau ringkasan di layar untuk mengetahui cakupan waktunya.
- Hanya IPv4 publik yang dianalisis (IPv6 dan alamat lokal dibuang).

Kebutuhan: pip install pandas numpy scikit-learn
"""

import argparse
import os
import re
import sys
from datetime import datetime

import numpy as np
import pandas as pd

try:
    from sklearn.cluster import KMeans
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    sys.exit("scikit-learn belum terpasang. Jalankan: pip install scikit-learn")

FITUR = ["total_percobaan", "jumlah_port_berbeda", "max_burst_5menit",
         "durasi_aktif_menit", "port_per_percobaan"]
FITUR_LOG = ["total_percobaan", "jumlah_port_berbeda", "max_burst_5menit", "durasi_aktif_menit"]
MIN_IP_UNTUK_ML = 40

BLOCK_RE = re.compile(
    r"^(?P<bln>[A-Za-z]{3})\s+(?P<hari>\d{1,2})\s+(?P<waktu>\d\d:\d\d:\d\d)\s.*?\[UFW BLOCK\]"
    r".*?SRC=(?P<src>\S+).*?PROTO=(?P<proto>\w+)"
    r"(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)


# ---------- membaca input ----------
def baca_log_mentah(path):
    rows = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "UFW BLOCK" not in line:
                continue
            m = BLOCK_RE.match(line)
            if m:
                rows.append((m["bln"], m["hari"], m["waktu"], m["src"],
                             m["proto"], m["spt"], m["dpt"]))
    return pd.DataFrame(rows, columns=["bulan", "hari", "waktu", "src", "proto", "spt", "dpt"])


def baca_rekap_csv(path):
    cols = ["bulan", "hari", "waktu", "host", "aksi", "iface", "mac",
            "src", "dst", "proto", "spt", "dpt"]
    df = pd.read_csv(path, header=None, names=cols, dtype=str, on_bad_lines="skip")
    df = df[df["bulan"] != "Bulan"]
    if df["proto"].isna().all():
        sys.exit("File ini tidak punya kolom protokol/port. Buat ulang rekap dengan "
                 "perintah awk versi lengkap (12 kolom), atau pakai log mentah.")
    return df[["bulan", "hari", "waktu", "src", "proto", "spt", "dpt"]].copy()


# ---------- pembersihan ----------
def ipv4_publik(ip):
    if not isinstance(ip, str) or ":" in ip:
        return False
    p = ip.split(".")
    if len(p) != 4:
        return False
    try:
        a, b = int(p[0]), int(p[1])
    except ValueError:
        return False
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


def p24(ip):
    return ".".join(ip.split(".")[:3])


# ---------- fitur per IP ----------
def hitung_fitur(d):
    hasil = []
    for ip, g in d.groupby("src", sort=False):
        t = np.sort(g["dt"].values)
        n = len(t)
        kiri, burst = 0, 0
        for k in range(n):
            while (t[k] - t[kiri]) / np.timedelta64(1, "s") > 300:
                kiri += 1
            burst = max(burst, k - kiri + 1)
        port = g["dpt"].dropna().nunique()
        koneksi = g[["spt", "dpt"]].fillna("-").drop_duplicates().shape[0]
        durasi = (t[-1] - t[0]) / np.timedelta64(1, "m")
        hasil.append((ip, n, koneksi, port, burst, durasi,
                      str(pd.Timestamp(t[0])), str(pd.Timestamp(t[-1]))))
    f = pd.DataFrame(hasil, columns=[
        "ip_address", "total_percobaan", "koneksi_unik", "jumlah_port_berbeda",
        "max_burst_5menit", "durasi_aktif_menit", "pertama_terlihat", "terakhir_terlihat"])
    f["port_per_percobaan"] = f["jumlah_port_berbeda"] / f["total_percobaan"]
    f["rasio_ulang"] = 1 - f["koneksi_unik"] / f["total_percobaan"]
    f["retransmisi_dominan"] = (f["rasio_ulang"] >= 0.5) & (f["total_percobaan"] >= 5)
    f["label"] = np.select(
        [(f["jumlah_port_berbeda"] >= 6) & (f["max_burst_5menit"] >= 10),
         f["jumlah_port_berbeda"] >= 6,
         f["max_burst_5menit"] >= 10],
        ["burst+scanner", "port_scanner", "burst"], default="normal")
    return f


# ---------- machine learning ----------
def jalankan_ml(f):
    X = f[FITUR].copy()
    for c in FITUR_LOG:
        X[c] = np.log1p(X[c])
    Xs = StandardScaler().fit_transform(X)

    km = KMeans(n_clusters=4, n_init=10, random_state=42).fit(Xs)
    urut = f.groupby(km.labels_)["total_percobaan"].mean().sort_values().index.tolist()
    peta = {lama: baru for baru, lama in enumerate(urut)}
    f["klaster"] = [peta[x] for x in km.labels_]

    iso = IsolationForest(n_estimators=200, contamination=0.02, random_state=42).fit(Xs)
    f["skor_anomali"] = iso.decision_function(Xs).round(4)
    f["anomali_iso"] = iso.predict(Xs) == -1
    return f


# ---------- perbandingan dengan riwayat ----------
def tandai_dikenal(f, ref_paths, out_path):
    kenal = set()
    for p in ref_paths:
        if os.path.abspath(p) == os.path.abspath(out_path):
            continue
        try:
            r = pd.read_csv(p, dtype=str)
        except FileNotFoundError:
            print(f"  (peringatan) file referensi tidak ditemukan: {p}")
            continue
        if "ip_address" not in r.columns:
            print(f"  (peringatan) {p} tidak punya kolom ip_address, dilewati")
            continue
        kenal |= set(r["ip_address"].dropna())
    kenal24 = {p24(i) for i in kenal}
    f["dikenal"] = f["ip_address"].isin(kenal)
    f["rentang24_dikenal"] = f["ip_address"].map(lambda i: p24(i) in kenal24)
    return f, len(kenal)


def _resolve_path(path, subdirs):
    """Cari path di direktori saat ini, lalu di subdirektori yang diberikan."""
    if os.path.isabs(path) and os.path.exists(path):
        return path
    if os.path.exists(path):
        return path
    for sub in subdirs:
        candidate = os.path.join(sub, os.path.basename(path))
        if os.path.exists(candidate):
            return candidate
    return path  # kembalikan asli agar error handling bawaan


def _auto_input():
    """Ambil file CSV terbaru di ufw/data/."""
    d = "ufw/data"
    if not os.path.isdir(d):
        return None
    files = sorted(
        [f for f in os.listdir(d) if f.lower().endswith(".csv")],
        key=lambda f: os.path.getmtime(os.path.join(d, f)), reverse=True)
    return os.path.join(d, files[0]) if files else None


# ---------- ringkasan ----------
def simpulan_csv(f, d, out, total_baris_tanggal, hari, bln, args):
    """Buat file ringkasan CSV berisi statistik umum."""
    ringkasan = {
        "fecha": f"{hari} {bln} {args.tahun}",
        "total_baris_ufw_block": total_baris_tanggal,
        "total_baris_ipv4_publik": len(d),
        "ip_unik": len(f),
        "normal": int((f["label"] == "normal").sum()),
        "port_scanner": int((f["label"] == "port_scanner").sum()),
        "burst": int((f["label"] == "burst").sum()),
        "burst_plus_scanner": int((f["label"] == "burst+scanner").sum()),
        "anomali_iso": int(f["anomali_iso"].sum()) if "anomali_iso" in f.columns else 0,
        "retransmisi_dominan": int(f["retransmisi_dominan"].sum()),
        "dikenal": int(f["dikenal"].sum()) if "dikenal" in f.columns and f["dikenal"].notna().any() else 0,
        "rentang24_dikenal": int(f["rentang24_dikenal"].sum()) if "rentang24_dikenal" in f.columns and f["rentang24_dikenal"].notna().any() else 0,
        "pertama_terlihat": f["pertama_terlihat"].min() if "pertama_terlihat" in f.columns else "",
        "terakhir_terlihat": f["terakhir_terlihat"].max() if "terakhir_terlihat" in f.columns else "",
        "cakupan_waktu": f"{d['dt'].min().time()} - {d['dt'].max().time()}",
    }
    if f["klaster"].notna().any():
        for k in range(4):
            ringkasan[f"klaster_{k}"] = int((f["klaster"] == k).sum())
    else:
        for k in range(4):
            ringkasan[f"klaster_{k}"] = 0

    base = os.path.splitext(out)[0]
    ringkasan_path = base + "-ringkasan.csv"
    pd.DataFrame([ringkasan]).to_csv(ringkasan_path, index=False)
    return ringkasan_path


def main():
    ap = argparse.ArgumentParser(description="Ringkasan harian log UFW per IP penyerang")
    ap.add_argument("--input", help="log mentah (ufw.log) atau rekap .csv 12 kolom. Kosong = auto ufw/data/")
    ap.add_argument("--fecha", help='contoh: "Oct 25". Kosong = tanggal yang paling banyak muncul')
    ap.add_argument("--tahun", type=int, default=datetime.now().year)
    ap.add_argument("--ref", nargs="*", default=[],
                    help="file hasil/ringkasan sebelumnya (punya kolom ip_address)")
    ap.add_argument("--abaikan", default="", help="IP sendiri yang dibuang, pisahkan dengan koma")
    ap.add_argument("--out", help="nama file output (default: hasil-<tgl><bln>-ufw.csv)")
    args = ap.parse_args()

    input_path = _resolve_path(args.input, ["ufw/data"]) if args.input else _auto_input()
    if not input_path or not os.path.exists(input_path):
        sys.exit("Tidak ditemukan file input. Berikan --input atau letakkan .csv di ufw/data/")
    d = baca_rekap_csv(input_path) if input_path.lower().endswith(".csv") else baca_log_mentah(input_path)
    if d.empty:
        sys.exit("Tidak ada baris UFW BLOCK yang terbaca.")

    d["hari_n"] = pd.to_numeric(d["hari"], errors="coerce")
    d = d.dropna(subset=["hari_n"])
    d["hari_n"] = d["hari_n"].astype(int)

    if args.fecha:
        bln, hari = args.fecha.split()
        hari = int(hari)
    else:
        top = (d["bulan"] + " " + d["hari_n"].astype(str)).value_counts().idxmax().split()
        bln, hari = top[0], int(top[1])
    d = d[(d["bulan"].str.lower() == bln.lower()) & (d["hari_n"] == hari)].copy()
    if d.empty:
        sys.exit(f"Tidak ada data untuk tanggal {bln} {hari}.")

    total_baris_tanggal = len(d)
    d = d[d["src"].map(ipv4_publik)].copy()
    abaikan = {x.strip() for x in args.abaikan.split(",") if x.strip()}
    if abaikan:
        d = d[~d["src"].isin(abaikan)]
    if d.empty:
        sys.exit("Tidak ada baris IPv4 publik pada tanggal itu.")

    d["dt"] = pd.to_datetime(
        f"{args.tahun} " + d["bulan"] + " " + d["hari_n"].astype(str) + " " + d["waktu"],
        format="%Y %b %d %H:%M:%S", errors="coerce")
    d = d.dropna(subset=["dt"])

    out = args.out or os.path.join("ufw", "hasil", f"hasil-{hari}{bln.lower()}-ufw.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    f = hitung_fitur(d)
    f.insert(0, "tanggal", d["dt"].dt.date.iloc[0].isoformat())

    if len(f) >= MIN_IP_UNTUK_ML:
        f = jalankan_ml(f)
    else:
        print(f"IP unik hanya {len(f)} (< {MIN_IP_UNTUK_ML}); ML dilewati.")
        f["klaster"], f["skor_anomali"], f["anomali_iso"] = np.nan, np.nan, False

    if args.ref:
        ref_paths = [_resolve_path(r, ["ufw/hasil"]) for r in args.ref]
        f, n_ref = tandai_dikenal(f, ref_paths, out)
    else:
        f["dikenal"], f["rentang24_dikenal"] = np.nan, np.nan

    f["durasi_aktif_menit"] = f["durasi_aktif_menit"].round(1)
    f["port_per_percobaan"] = f["port_per_percobaan"].round(3)
    f["rasio_ulang"] = f["rasio_ulang"].round(3)
    kolom = ["tanggal", "ip_address", "total_percobaan", "koneksi_unik", "jumlah_port_berbeda",
             "max_burst_5menit", "durasi_aktif_menit", "port_per_percobaan", "rasio_ulang",
             "retransmisi_dominan", "label", "klaster", "skor_anomali", "anomali_iso",
             "dikenal", "rentang24_dikenal", "pertama_terlihat", "terakhir_terlihat"]
    f = f[kolom].sort_values("total_percobaan", ascending=False)
    f.to_csv(out, index=False)

    ringkasan_path = simpulan_csv(f, d, out, total_baris_tanggal, hari, bln, args)

    # ---------- ringkasan di layar ----------
    print(f"\n=== Ringkasan {hari} {bln} {args.tahun} ===")
    print(f"Baris UFW BLOCK tanggal ini : {total_baris_tanggal}")
    print(f"Baris IPv4 publik           : {len(d)}  | IP unik: {len(f)}")
    print(f"Cakupan waktu               : {d['dt'].min().time()} - {d['dt'].max().time()}")
    print(f"Label threshold             : {f['label'].value_counts().to_dict()}")
    if f["klaster"].notna().any():
        print(f"Sebaran klaster (0 ringan..3 ekstrem): {f['klaster'].value_counts().sort_index().to_dict()}")
        print(f"IP anomali                  : {int(f['anomali_iso'].sum())}"
              f"  (berlabel normal: {int((f['anomali_iso'] & (f['label'] == 'normal')).sum())})")
    print(f"Retransmisi dominan         : {int(f['retransmisi_dominan'].sum())} IP")
    if args.ref:
        print(f"IP dikenal dari referensi   : {int(f['dikenal'].sum())} / {len(f)}"
              f"  | rentang /24 dikenal: {int(f['rentang24_dikenal'].sum())} / {len(f)}")
    print(f"\nTersimpan: {out}")
    print(f"Ringkasan   : {ringkasan_path}")


if __name__ == "__main__":
    main()
