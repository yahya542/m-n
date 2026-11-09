import csv
import json
import os
import shutil
import tempfile
import unittest
from dashboard import DashboardData, MonitoringHandler, make_handler
from http.server import HTTPServer
import threading
import urllib.request


class TestDashboardData(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.helper = DashboardData(self.test_dir)

        # Buat dummy data hari 1
        ringkasan_1 = [{
            "tanggal": "2026-11-01",
            "total_baris_ufw_block": "100",
            "total_baris_ipv4_publik": "90",
            "ip_unik": "2",
            "normal": "1",
            "port_scanner": "1",
            "burst": "0",
            "burst_plus_scanner": "0",
            "anomali_iso": "1",
            "retransmisi_dominan": "0"
        }]
        detail_1 = [
            {"tanggal": "2026-11-01", "ip_address": "1.2.3.4", "total_percobaan": "80",
             "jumlah_port_berbeda": "10", "max_burst_5menit": "15", "durasi_aktif_menit": "5.0",
             "label": "port_scanner", "anomali_iso": "True", "terakhir_terlihat": "2026-11-01 10:00:00"},
            {"tanggal": "2026-11-01", "ip_address": "5.6.7.8", "total_percobaan": "20",
             "jumlah_port_berbeda": "1", "max_burst_5menit": "2", "durasi_aktif_menit": "1.0",
             "label": "normal", "anomali_iso": "False", "terakhir_terlihat": "2026-11-01 08:00:00"}
        ]
        self._write_csv("hasil-2026-11-01-ufw-ringkasan.csv", ringkasan_1)
        self._write_csv("hasil-2026-11-01-ufw.csv", detail_1)

        # Buat dummy data hari 2
        ringkasan_2 = [{
            "tanggal": "2026-11-02",
            "total_baris_ufw_block": "50",
            "total_baris_ipv4_publik": "50",
            "ip_unik": "1",
            "normal": "0",
            "port_scanner": "0",
            "burst": "1",
            "burst_plus_scanner": "0",
            "anomali_iso": "0",
            "retransmisi_dominan": "1"
        }]
        detail_2 = [
            {"tanggal": "2026-11-02", "ip_address": "1.2.3.4", "total_percobaan": "50",
             "jumlah_port_berbeda": "2", "max_burst_5menit": "20", "durasi_aktif_menit": "10.0",
             "label": "burst", "anomali_iso": "False", "terakhir_terlihat": "2026-11-02 12:00:00"}
        ]
        self._write_csv("hasil-2026-11-02-ufw-ringkasan.csv", ringkasan_2)
        self._write_csv("hasil-2026-11-02-ufw.csv", detail_2)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_csv(self, filename, rows):
        path = os.path.join(self.test_dir, filename)
        if not rows:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def test_available_dates_dan_months(self):
        dates = self.helper.get_available_dates()
        self.assertEqual(dates, ["2026-11-02", "2026-11-01"])
        months = self.helper.get_available_months()
        self.assertEqual(months, ["2026-11"])

    def test_fetch_yesterday(self):
        data = self.helper.fetch_data(range_type="yesterday")
        self.assertIn("2026-11-02", data["title"])
        self.assertEqual(data["summary"]["total_baris_ufw_block"], 50)
        self.assertEqual(len(data["top_ips"]), 1)
        self.assertEqual(data["top_ips"][0]["ip_address"], "1.2.3.4")

    def test_fetch_multi_day_aggregation(self):
        data = self.helper.fetch_data(range_type="7d")
        summary = data["summary"]
        self.assertEqual(summary["total_baris_ufw_block"], 150)
        self.assertEqual(summary["ip_unik"], 2)

        # Cek agregasi IP 1.2.3.4: percobaan = 80 + 50 = 130
        ip_1 = next(x for x in data["top_ips"] if x["ip_address"] == "1.2.3.4")
        self.assertEqual(ip_1["total_percobaan"], 130)
        self.assertEqual(ip_1["jumlah_port_berbeda"], 10)  # max(10, 2)
        self.assertEqual(ip_1["label"], "port_scanner")    # prioritas port_scanner > burst
        self.assertTrue(ip_1["anomali_iso"])               # True or False = True
        self.assertEqual(ip_1["terakhir_terlihat"], "2026-11-02 12:00:00")


class TestDashboardHttpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp()
        cls.helper = DashboardData(cls.test_dir)

        # Start HTTP server on dynamic port
        handler = make_handler(cls.helper)
        cls.server = HTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir)

    def test_get_html(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("UFW Security Monitor", body)

    def test_get_api_options(self):
        url = f"http://127.0.0.1:{self.port}/api/options"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("dates", data)
            self.assertIn("months", data)

    def test_get_api_data(self):
        url = f"http://127.0.0.1:{self.port}/api/data?range=yesterday"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("summary", data)
            self.assertIn("time_series", data)
            self.assertIn("top_ips", data)


if __name__ == "__main__":
    unittest.main()
