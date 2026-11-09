#!/usr/bin/env python3
"""
dashboard.py
Server web monitoring UFW mandiri berbasis Python standard library (zero external dependency).
Membaca file ufw/hasil/hasil-*-ufw.csv dan ...-ringkasan.csv, menyajikan dashboard responsif.
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, date, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>UFW Security Monitor</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
      --accent-yellow: #eab308;
      --accent-blue: #3b82f6;
      --accent-purple: #a855f7;
      --accent-green: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 1.5rem;
    }
    .container { max-width: 1300px; margin: 0 auto; }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 2rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--card-border);
    }
    .brand h1 { font-size: 1.5rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
    .brand p { color: var(--text-muted); font-size: 0.875rem; }
    .filters { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; }
    select, input {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      outline: none;
    }
    select:focus, input:focus { border-color: var(--accent-blue); }
    .grid-kpi {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .card-kpi .label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    .card-kpi .value { font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }
    .card-kpi .desc { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    .grid-charts {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 1rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 900px) { .grid-charts { grid-template-columns: 1fr; } }
    .chart-container { position: relative; height: 260px; width: 100%; }
    .table-section h2 { font-size: 1.125rem; font-weight: 600; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center; }
    .table-wrapper { overflow-x: auto; max-height: 520px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }
    th {
      background: #182234;
      color: var(--text-muted);
      padding: 0.75rem 1rem;
      position: sticky;
      top: 0;
      z-index: 1;
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
    }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid rgba(51, 65, 85, 0.5); }
    tr:hover td { background-color: rgba(255, 255, 255, 0.02); }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-burst-scanner { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-port-scanner { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-burst { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .badge-normal { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; }
    .badge-anomali { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
    .empty-msg { text-align: center; color: var(--text-muted); padding: 3rem 1rem; font-style: italic; }
    .loading { opacity: 0.5; pointer-events: none; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>🛡️ UFW Monitor</h1>
        <p id="sub-title">Memuat ringkasan keamanan...</p>
      </div>
      <div class="filters">
        <label for="range-select" style="font-size: 0.85rem; color: var(--text-muted)">Rentang:</label>
        <select id="range-select" onchange="onRangeChange()">
          <option value="yesterday">Kemarin (1 Hari Terakhir)</option>
          <option value="7d">7 Hari Terakhir</option>
          <option value="month">Rentang Bulan</option>
          <option value="custom">Pilih Tanggal Spesifik</option>
        </select>
        <select id="month-select" style="display: none;" onchange="loadData()"></select>
        <select id="date-select" style="display: none;" onchange="loadData()"></select>
      </div>
    </header>

    <div class="grid-kpi" id="kpi-container">
      <div class="card card-kpi">
        <div class="label">Total Blokir</div>
        <div class="value" id="kpi-total" style="color: var(--accent-red);">-</div>
        <div class="desc">Baris log UFW BLOCK</div>
      </div>
      <div class="card card-kpi">
        <div class="label">IP Unik</div>
        <div class="value" id="kpi-ip" style="color: var(--accent-blue);">-</div>
        <div class="desc">Penyerang IPv4 publik</div>
      </div>
      <div class="card card-kpi">
        <div class="label">Port Scanner</div>
        <div class="value" id="kpi-scanner" style="color: var(--accent-orange);">-</div>
        <div class="desc">&ge; 6 port berbeda</div>
      </div>
      <div class="card card-kpi">
        <div class="label">Burst Attack</div>
        <div class="value" id="kpi-burst" style="color: var(--accent-yellow);">-</div>
        <div class="desc">&ge; 10 req / 5 menit</div>
      </div>
      <div class="card card-kpi">
        <div class="label">Anomali ML</div>
        <div class="value" id="kpi-anomali" style="color: var(--accent-purple);">-</div>
        <div class="desc">IsolationForest outlier</div>
      </div>
      <div class="card card-kpi">
        <div class="label">Retransmisi Dominan</div>
        <div class="value" id="kpi-retrans">-</div>
        <div class="desc">&ge; 50% koneksi ulang</div>
      </div>
    </div>

    <div class="grid-charts">
      <div class="card">
        <h3 style="font-size: 0.95rem; margin-bottom: 1rem; color: var(--text-muted);">Tren Blokir & Penyerang</h3>
        <div class="chart-container">
          <canvas id="trendChart"></canvas>
        </div>
      </div>
      <div class="card">
        <h3 style="font-size: 0.95rem; margin-bottom: 1rem; color: var(--text-muted);">Distribusi Tipe Serangan</h3>
        <div class="chart-container">
          <canvas id="categoryChart"></canvas>
        </div>
      </div>
    </div>

    <div class="card table-section">
      <h2>
        <span>Top 50 IP Penyerang</span>
        <input type="text" id="search-ip" placeholder="Cari IP..." onkeyup="filterTable()" style="width: 200px;">
      </h2>
      <div class="table-wrapper">
        <table id="ip-table">
          <thead>
            <tr>
              <th>#</th>
              <th>IP Address</th>
              <th>Total Blokir</th>
              <th>Port Unik</th>
              <th>Max Burst (5m)</th>
              <th>Durasi (mnt)</th>
              <th>Kategori</th>
              <th>ML Anomali</th>
              <th>Terakhir Terlihat</th>
            </tr>
          </thead>
          <tbody id="table-body">
            <tr><td colspan="9" class="empty-msg">Memuat data IP...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let trendChartInstance = null;
    let categoryChartInstance = null;
    let currentIPList = [];

    async function init() {
      try {
        const res = await fetch('/api/options');
        const opts = await res.json();
        
        const mSel = document.getElementById('month-select');
        mSel.innerHTML = (opts.months || []).map(m => `<option value="${m}">${m}</option>`).join('');
        
        const dSel = document.getElementById('date-select');
        dSel.innerHTML = (opts.dates || []).map(d => `<option value="${d}">${d}</option>`).join('');

        loadData();
      } catch (err) {
        document.getElementById('sub-title').textContent = 'Gagal memuat opsi data: ' + err;
      }
    }

    function onRangeChange() {
      const mode = document.getElementById('range-select').value;
      document.getElementById('month-select').style.display = (mode === 'month') ? 'inline-block' : 'none';
      document.getElementById('date-select').style.display = (mode === 'custom') ? 'inline-block' : 'none';
      loadData();
    }

    async function loadData() {
      document.body.classList.add('loading');
      const mode = document.getElementById('range-select').value;
      let url = '/api/data?range=' + mode;
      if (mode === 'month') {
        url += '&val=' + document.getElementById('month-select').value;
      } else if (mode === 'custom') {
        url += '&val=' + document.getElementById('date-select').value;
      }

      try {
        const res = await fetch(url);
        const data = await res.json();
        renderDashboard(data);
      } catch (err) {
        alert('Gagal mengambil data monitoring: ' + err);
      } finally {
        document.body.classList.remove('loading');
      }
    }

    function renderDashboard(data) {
      document.getElementById('sub-title').textContent = data.title || 'Data Analisis UFW';
      
      const s = data.summary || {};
      document.getElementById('kpi-total').textContent = (s.total_baris_ufw_block || 0).toLocaleString();
      document.getElementById('kpi-ip').textContent = (s.ip_unik || 0).toLocaleString();
      document.getElementById('kpi-scanner').textContent = (s.port_scanner || 0).toLocaleString();
      document.getElementById('kpi-burst').textContent = (s.burst || 0).toLocaleString();
      document.getElementById('kpi-anomali').textContent = (s.anomali_iso || 0).toLocaleString();
      document.getElementById('kpi-retrans').textContent = (s.retransmisi_dominan || 0).toLocaleString();

      renderCharts(data);
      renderTable(data.top_ips || []);
    }

    function renderCharts(data) {
      const ts = data.time_series || [];
      const labels = ts.map(x => x.tanggal);
      const totalBlock = ts.map(x => x.total_baris);
      const totalIP = ts.map(x => x.ip_unik);

      // Trend Chart
      if (trendChartInstance) trendChartInstance.destroy();
      const ctxTrend = document.getElementById('trendChart').getContext('2d');
      trendChartInstance = new Chart(ctxTrend, {
        type: 'bar',
        data: {
          labels: labels.length ? labels : ['Tidak Ada Data'],
          datasets: [
            {
              label: 'Total Blokir',
              data: totalBlock,
              backgroundColor: '#ef4444aa',
              borderColor: '#ef4444',
              borderWidth: 1,
              yAxisID: 'y'
            },
            {
              label: 'IP Unik',
              data: totalIP,
              type: 'line',
              borderColor: '#38bdf8',
              backgroundColor: '#38bdf8',
              borderWidth: 2,
              tension: 0.2,
              yAxisID: 'y1'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: { position: 'left', grid: { color: '#33415555' }, ticks: { color: '#94a3b8' } },
            y1: { position: 'right', grid: { drawOnChartArea: false }, ticks: { color: '#94a3b8' } },
            x: { grid: { color: '#33415533' }, ticks: { color: '#94a3b8' } }
          },
          plugins: {
            legend: { labels: { color: '#f8fafc' } }
          }
        }
      });

      // Category Donut Chart
      const s = data.summary || {};
      const catData = [
        s.normal || 0,
        s.port_scanner || 0,
        s.burst || 0,
        s.burst_plus_scanner || 0
      ];

      if (categoryChartInstance) categoryChartInstance.destroy();
      const ctxCat = document.getElementById('categoryChart').getContext('2d');
      categoryChartInstance = new Chart(ctxCat, {
        type: 'doughnut',
        data: {
          labels: ['Normal', 'Port Scanner', 'Burst', 'Burst + Scanner'],
          datasets: [{
            data: catData,
            backgroundColor: ['#64748b', '#f97316', '#eab308', '#ef4444'],
            borderColor: '#1e293b',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#f8fafc', boxWidth: 12, font: { size: 11 } } }
          }
        }
      });
    }

    function renderTable(ips) {
      currentIPList = ips;
      filterTable();
    }

    function filterTable() {
      const q = (document.getElementById('search-ip').value || '').toLowerCase().trim();
      const tbody = document.getElementById('table-body');
      
      const filtered = currentIPList.filter(row => !q || row.ip_address.toLowerCase().includes(q));
      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-msg">Tidak ada IP yang cocok.</td></tr>';
        return;
      }

      tbody.innerHTML = filtered.map((row, idx) => {
        let badgeClass = 'badge-normal';
        if (row.label === 'burst+scanner') badgeClass = 'badge-burst-scanner';
        else if (row.label === 'port_scanner') badgeClass = 'badge-port-scanner';
        else if (row.label === 'burst') badgeClass = 'badge-burst';

        const anomaliBadge = (row.anomali_iso === 'True' || row.anomali_iso === true)
          ? '<span class="badge badge-anomali">Anomali</span>'
          : '<span style="color: var(--text-muted); font-size: 0.8rem;">-</span>';

        return `<tr>
          <td>${idx + 1}</td>
          <td><strong>${row.ip_address}</strong></td>
          <td style="font-weight: 600; color: #f87171">${Number(row.total_percobaan).toLocaleString()}</td>
          <td>${row.jumlah_port_berbeda}</td>
          <td>${row.max_burst_5menit}</td>
          <td>${row.durasi_aktif_menit}</td>
          <td><span class="badge ${badgeClass}">${row.label}</span></td>
          <td>${anomaliBadge}</td>
          <td style="color: var(--text-muted); font-size: 0.8rem;">${row.terakhir_terlihat || '-'}</td>
        </tr>`;
      }).join('');
    }

    window.addEventListener('DOMContentLoaded', init);
  </script>
</body>
</html>
"""


class DashboardData:
    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(data_dir)

    def get_available_dates(self):
        """Ambil semua tanggal hasil analisis yang ada (urutan descending)."""
        pattern = os.path.join(self.data_dir, "hasil-*-ufw-ringkasan.csv")
        files = glob.glob(pattern)
        dates = []
        for f in files:
            m = re.search(r"hasil-(\d{4}-\d{2}-\d{2})-ufw-ringkasan\.csv$", os.path.basename(f))
            if m:
                dates.append(m.group(1))
        dates.sort(reverse=True)
        return dates

    def get_available_months(self):
        """Ambil daftar bulan unik (format YYYY-MM) dari tanggal yang ada."""
        dates = self.get_available_dates()
        months = sorted(list(set(d[:7] for d in dates)), reverse=True)
        return months

    def _read_csv(self, path):
        if not os.path.isfile(path):
            return []
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            return list(reader)

    def get_summary_and_ips(self, date_list, title=""):
        """Agregasi data ringkasan dan daftar top IP dari kumpulan tanggal terpilih."""
        date_set = set(date_list)
        time_series = []
        all_ips = {}
        summary = {
            "total_baris_ufw_block": 0,
            "total_baris_ipv4_publik": 0,
            "ip_unik": 0,
            "normal": 0,
            "port_scanner": 0,
            "burst": 0,
            "burst_plus_scanner": 0,
            "anomali_iso": 0,
            "retransmisi_dominan": 0,
        }

        # Urutkan tanggal ascending untuk time-series chart
        sorted_dates = sorted(date_list)
        for dt in sorted_dates:
            r_path = os.path.join(self.data_dir, f"hasil-{dt}-ufw-ringkasan.csv")
            r_rows = self._read_csv(r_path)
            if r_rows:
                r = r_rows[0]
                tb = int(r.get("total_baris_ufw_block") or 0)
                iu = int(r.get("ip_unik") or 0)
                time_series.append({
                    "tanggal": dt,
                    "total_baris": tb,
                    "ip_unik": iu,
                    "port_scanner": int(r.get("port_scanner") or 0),
                    "burst": int(r.get("burst") or 0),
                    "anomali": int(r.get("anomali_iso") or 0),
                })
                summary["total_baris_ufw_block"] += tb
                summary["total_baris_ipv4_publik"] += int(r.get("total_baris_ipv4_publik") or 0)
                summary["normal"] += int(r.get("normal") or 0)
                summary["port_scanner"] += int(r.get("port_scanner") or 0)
                summary["burst"] += int(r.get("burst") or 0)
                summary["burst_plus_scanner"] += int(r.get("burst_plus_scanner") or 0)
                summary["anomali_iso"] += int(r.get("anomali_iso") or 0)
                summary["retransmisi_dominan"] += int(r.get("retransmisi_dominan") or 0)

            # Baca detail IP
            ip_path = os.path.join(self.data_dir, f"hasil-{dt}-ufw.csv")
            ip_rows = self._read_csv(ip_path)
            for row in ip_rows:
                ip = row.get("ip_address")
                if not ip:
                    continue
                percobaan = int(row.get("total_percobaan") or 0)
                port_unik = int(row.get("jumlah_port_berbeda") or 0)
                burst = int(row.get("max_burst_5menit") or 0)
                durasi = float(row.get("durasi_aktif_menit") or 0.0)
                lbl = row.get("label", "normal")
                is_anomali = str(row.get("anomali_iso", "False")).lower() in ("true", "1")
                terakhir = row.get("terakhir_terlihat", "")

                if ip not in all_ips:
                    all_ips[ip] = {
                        "ip_address": ip,
                        "total_percobaan": percobaan,
                        "jumlah_port_berbeda": port_unik,
                        "max_burst_5menit": burst,
                        "durasi_aktif_menit": durasi,
                        "label": lbl,
                        "anomali_iso": is_anomali,
                        "terakhir_terlihat": terakhir
                    }
                else:
                    cur = all_ips[ip]
                    cur["total_percobaan"] += percobaan
                    cur["jumlah_port_berbeda"] = max(cur["jumlah_port_berbeda"], port_unik)
                    cur["max_burst_5menit"] = max(cur["max_burst_5menit"], burst)
                    cur["durasi_aktif_menit"] = round(cur["durasi_aktif_menit"] + durasi, 1)
                    # Label terparah
                    prioritas = {"burst+scanner": 4, "port_scanner": 3, "burst": 2, "normal": 1}
                    if prioritas.get(lbl, 0) > prioritas.get(cur["label"], 0):
                        cur["label"] = lbl
                    if is_anomali:
                        cur["anomali_iso"] = True
                    if terakhir > cur["terakhir_terlihat"]:
                        cur["terakhir_terlihat"] = terakhir

        summary["ip_unik"] = len(all_ips)
        sorted_ips = sorted(all_ips.values(), key=lambda x: x["total_percobaan"], reverse=True)
        top_ips = sorted_ips[:50]

        return {
            "title": title,
            "summary": summary,
            "time_series": time_series,
            "top_ips": top_ips
        }

    def fetch_data(self, range_type="yesterday", val=""):
        all_dates = self.get_available_dates()
        if not all_dates:
            return {
                "title": "Belum ada data ufw/hasil",
                "summary": {},
                "time_series": [],
                "top_ips": []
            }

        if range_type == "yesterday":
            # Ambil tanggal kemarin berdasarkan tanggal teratas atau tanggal aktual
            selected_date = all_dates[0]
            title = f"Analisis Harian ({selected_date})"
            return self.get_summary_and_ips([selected_date], title=title)

        elif range_type == "7d":
            # Ambil hingga 7 tanggal terbaru
            selected_dates = all_dates[:7]
            title = f"Analisis 7 Hari Terakhir ({selected_dates[-1]} s/d {selected_dates[0]})"
            return self.get_summary_and_ips(selected_dates, title=title)

        elif range_type == "month":
            target_month = val or (all_dates[0][:7] if all_dates else "")
            selected_dates = [d for d in all_dates if d.startswith(target_month)]
            title = f"Analisis Bulanan ({target_month}) - {len(selected_dates)} Hari"
            return self.get_summary_and_ips(selected_dates, title=title)

        elif range_type == "custom":
            selected_date = val if val in all_dates else all_dates[0]
            title = f"Analisis Harian ({selected_date})"
            return self.get_summary_and_ips([selected_date], title=title)

        return self.get_summary_and_ips([all_dates[0]], title=f"Analisis ({all_dates[0]})")


class MonitoringHandler(BaseHTTPRequestHandler):
    def __init__(self, data_helper, *args, **kwargs):
        self.data_helper = data_helper
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            return

        elif path == "/api/options":
            dates = self.data_helper.get_available_dates()
            months = self.data_helper.get_available_months()
            payload = json.dumps({"dates": dates, "months": months})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return

        elif path == "/api/data":
            range_type = query.get("range", ["yesterday"])[0]
            val = query.get("val", [""])[0]
            data = self.data_helper.fetch_data(range_type=range_type, val=val)
            payload = json.dumps(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Format log minimalis
        sys.stderr.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}\n")


def make_handler(data_helper):
    return lambda *args, **kwargs: MonitoringHandler(data_helper, *args, **kwargs)


def run_server(data_dir, host="0.0.0.0", port=8080):
    data_helper = DashboardData(data_dir)
    handler = make_handler(data_helper)
    server = HTTPServer((host, port), handler)
    print(f"UFW Dashboard running on http://{host}:{port} (Data dir: {data_dir})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UFW Web Monitoring Dashboard")
    parser.add_argument("--data-dir", default=os.environ.get("DATA_DIR", "ufw/hasil"),
                        help="Direktori hasil analisis CSV (default: ufw/hasil)")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"),
                        help="Host bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")),
                        help="Port bind (default: 8080)")
    args = parser.parse_args()

    run_server(args.data_dir, args.host, args.port)
