"""Uji analisis_harian.py. Hanya library standar (unittest) + dependensi skrip."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from unittest import mock

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analisis_harian as ad  # noqa: E402

BLN = ad.BULAN


def baris(t, src, dpt=22, spt=40000, proto="TCP"):
    """Satu baris UFW BLOCK gaya syslog klasik."""
    s = (f"{BLN[t.month - 1]} {t.day:2d} {t:%H:%M:%S} srv kernel: [1.0] [UFW BLOCK] "
         f"IN=eth0 OUT= MAC=aa:bb SRC={src} DST=10.9.8.7 LEN=44 PROTO={proto}")
    if proto != "ICMP":
        s += f" SPT={spt} DPT={dpt}"
    return s


def log_hari(tgl, n_ip=45, offset=0):
    """Log sintetis satu hari: tiap IP punya pola berbeda (supaya ML punya variasi)."""
    out = []
    dasar = datetime(tgl.year, tgl.month, tgl.day, 1, 0, 0)
    for i in range(n_ip):
        src = f"{50 + (i + offset) % 150}.1.{(i + offset) % 200 + 1}.9"
        mulai = dasar + timedelta(minutes=17 * i)
        for k in range(1 + i % 9):
            out.append(baris(mulai + timedelta(seconds=3 * k), src,
                             dpt=20 + (k * (1 + i % 5)), spt=40000 + (i % 3)))
    return out


def isi(path):
    with open(path) as f:
        return f.read()


def jalankan(argv):
    """Panggil main() di proses ini. Kembalikan (kode_keluar, stdout, stderr)."""
    o, e, kode = io.StringIO(), io.StringIO(), 0
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        try:
            ad.main(argv)
        except SystemExit as x:
            kode = x.code if isinstance(x.code, int) else 1
            if isinstance(x.code, str):
                e.write(x.code)
    return kode, o.getvalue(), e.getvalue()


class TestTanggal(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(ad.parse_tanggal("2026-10-25", date(2026, 11, 4)), date(2026, 10, 25))

    def test_syslog_tidak_melewati_hari_ini(self):
        self.assertEqual(ad.parse_tanggal("Nov 3", date(2026, 11, 4)), date(2026, 11, 3))
        # 31 Des dibaca saat 2 Jan -> tahun lalu, bukan tahun depan
        self.assertEqual(ad.parse_tanggal("Dec 31", date(2027, 1, 2)), date(2026, 12, 31))

    def test_tahun_eksplisit_dan_kabisat(self):
        self.assertEqual(ad.parse_tanggal("Oct 25", date(2026, 11, 4), 2025), date(2025, 10, 25))
        self.assertEqual(ad.parse_tanggal("Feb 29", date(2026, 3, 1)), date(2024, 2, 29))

    def test_format_salah(self):
        with self.assertRaises(ValueError):
            ad.parse_tanggal("kemarin", date(2026, 11, 4))
        with self.assertRaises(ValueError):
            ad.parse_tanggal("Xyz 3", date(2026, 11, 4))


class TestParsingDanFitur(unittest.TestCase):
    def test_ipv4_publik(self):
        for ip in ("8.8.8.8", "172.15.0.1", "172.32.0.1", "193.0.0.1"):
            self.assertTrue(ad.ipv4_publik(ip), ip)
        for ip in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "172.16.5.5", "169.254.1.1",
                   "224.0.0.1", "0.0.0.0", "2001:db8::1", "bukan-ip", None):
            self.assertFalse(ad.ipv4_publik(ip), ip)

    def test_regex_baris_block(self):
        t = datetime(2026, 11, 3, 6, 0, 1)
        m = ad.BLOCK_RE.match(baris(t, "1.2.3.4", dpt=3389, spt=5555))
        self.assertEqual((m["bln"], m["hari"], m["waktu"], m["src"], m["dpt"], m["spt"]),
                         ("Nov", "3", "06:00:01", "1.2.3.4", "3389", "5555"))
        self.assertIsNone(ad.BLOCK_RE.match("Nov  3 06:00:01 srv sshd[1]: Accepted publickey"))

    def test_fitur_burst_dan_scanner(self):
        t0 = datetime(2026, 11, 3, 10, 0, 0)
        rows = [(t0 + timedelta(seconds=i), "5.5.5.5", "40000", "22") for i in range(12)]
        rows += [(t0 + timedelta(minutes=10 * i), "6.6.6.6", str(40000 + i), str(100 + i))
                 for i in range(6)]
        d = pd.DataFrame(rows, columns=["dt", "src", "spt", "dpt"])
        f = ad.hitung_fitur(d).set_index("ip_address")
        a, b = f.loc["5.5.5.5"], f.loc["6.6.6.6"]
        self.assertEqual((a.total_percobaan, a.koneksi_unik, a.max_burst_5menit), (12, 1, 12))
        self.assertEqual(a.label, "burst")
        self.assertTrue(a.retransmisi_dominan)
        self.assertEqual((b.jumlah_port_berbeda, b.max_burst_5menit), (6, 1))
        self.assertEqual(b.label, "port_scanner")


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def tulis(self, nama, baris_log):
        p = os.path.join(self.dir, nama)
        with open(p, "w") as f:
            f.write("\n".join(baris_log) + "\n")
        return p

    def test_pergantian_tahun_dan_default_kemarin(self):
        # 30 Des, 31 Des (target), 1 Jan: tahun harus benar di setiap baris
        log = (log_hari(date(2026, 12, 30), 10, 100) + log_hari(date(2026, 12, 31), 45)
               + log_hari(date(2027, 1, 1), 10, 200))
        p = self.tulis("ufw.log", log)
        out = os.path.join(self.dir, "hasil")

        class PalsuDT(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2027, 1, 1, 6, 0, 0)

        with mock.patch.object(ad, "datetime", PalsuDT):
            kode, _, err = jalankan(["--input", p, "--out-dir", out, "--ketat"])
        self.assertEqual(kode, 0, err)
        f = pd.read_csv(os.path.join(out, "hasil-2026-12-31-ufw.csv"))
        self.assertEqual(set(f["tanggal"]), {"2026-12-31"})
        self.assertTrue(f["pertama_terlihat"].str.startswith("2026-12-31").all())
        r = pd.read_csv(os.path.join(out, "hasil-2026-12-31-ufw-ringkasan.csv"))
        self.assertEqual(r.loc[0, "tanggal"], "2026-12-31")

    def test_ketat_menolak_data_parsial_dan_tidak_menulis(self):
        # log terpotong rotasi: baris sebelum 00:00 hari target tidak ada
        p = self.tulis("ufw.log", log_hari(date(2026, 11, 3), 45) + log_hari(date(2026, 11, 4), 5, 80))
        out = os.path.join(self.dir, "hasil")
        kode, _, err = jalankan(["--input", p, "--tanggal", "2026-11-03", "--out-dir", out, "--ketat"])
        self.assertEqual(kode, 3)
        self.assertIn("cakupan", err)
        self.assertFalse(os.path.exists(os.path.join(out, "hasil-2026-11-03-ufw.csv")))
        # tanpa --ketat: hanya peringatan, hasil tetap ditulis
        kode, _, err = jalankan(["--input", p, "--tanggal", "2026-11-03", "--out-dir", out])
        self.assertEqual(kode, 0)
        self.assertIn("PERINGATAN", err)

    def test_dua_file_rotasi_sama_dengan_satu_file_utuh(self):
        seluruh = (log_hari(date(2026, 11, 2), 8, 100) + log_hari(date(2026, 11, 3), 45)
                   + log_hari(date(2026, 11, 4), 8, 60))
        separ = len(seluruh) // 2
        satu = self.tulis("utuh.log", seluruh)
        a = self.tulis("ufw.log.1", seluruh[:separ])
        b = self.tulis("ufw.log", seluruh[separ:])
        o1, o2 = os.path.join(self.dir, "o1"), os.path.join(self.dir, "o2")
        self.assertEqual(jalankan(["--input", satu, "--tanggal", "2026-11-03", "--out-dir", o1, "--ketat"])[0], 0)
        self.assertEqual(jalankan(["--input", a, b, "--tanggal", "2026-11-03", "--out-dir", o2, "--ketat"])[0], 0)
        n = "hasil-2026-11-03-ufw.csv"
        self.assertEqual(isi(os.path.join(o1, n)), isi(os.path.join(o2, n)))

    def test_deterministik_dan_ml_jalan(self):
        p = self.tulis("ufw.log", log_hari(date(2026, 11, 2), 3, 100) + log_hari(date(2026, 11, 3), 45)
                       + log_hari(date(2026, 11, 4), 3, 100))
        hasil = []
        for i in (1, 2):
            out = os.path.join(self.dir, f"run{i}")
            self.assertEqual(jalankan(["--input", p, "--tanggal", "2026-11-03", "--out-dir", out])[0], 0)
            hasil.append(isi(os.path.join(out, "hasil-2026-11-03-ufw.csv")))
        self.assertEqual(hasil[0], hasil[1])
        f = pd.read_csv(os.path.join(self.dir, "run1", "hasil-2026-11-03-ufw.csv"))
        self.assertTrue(f["klaster"].notna().all())
        self.assertTrue(set(f["klaster"]) <= {0, 1, 2, 3})

    def test_referensi_otomatis_hanya_hari_sebelumnya(self):
        p = self.tulis("ufw.log", log_hari(date(2026, 11, 2), 45) + log_hari(date(2026, 11, 3), 45, 10)
                       + log_hari(date(2026, 11, 4), 5, 80))
        out = os.path.join(self.dir, "hasil")
        for tgl in ("2026-11-02", "2026-11-03"):
            self.assertEqual(jalankan(["--input", p, "--tanggal", tgl, "--out-dir", out])[0], 0)
        h2 = pd.read_csv(os.path.join(out, "hasil-2026-11-02-ufw.csv"))
        h3 = pd.read_csv(os.path.join(out, "hasil-2026-11-03-ufw.csv"))
        self.assertGreater(int(h3["dikenal"].sum()), 0)       # IP tumpang tindih terdeteksi
        # hitung ulang 2 Nov setelah 3 Nov ada: tidak boleh 'melihat masa depan'
        jalankan(["--input", p, "--tanggal", "2026-11-02", "--out-dir", out])
        h2b = pd.read_csv(os.path.join(out, "hasil-2026-11-02-ufw.csv"))
        self.assertEqual(int(h2b["dikenal"].sum()), 0)
        self.assertEqual(len(h2), len(h2b))

    def test_input_hilang(self):
        kode, _, err = jalankan(["--input", os.path.join(self.dir, "tidak-ada.log")])
        self.assertNotEqual(kode, 0)
        self.assertIn("tidak ditemukan", err)


if __name__ == "__main__":
    unittest.main()
