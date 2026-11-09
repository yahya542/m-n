# Panduan Uji Coba Monitoring UFW di Lokal

Panduan langkah demi langkah untuk menguji engine analisis dan dashboard web di komputer lokal sebelum deploy ke server.

---

## 1. Persiapan Lingkungan

Muat ulang virtual environment agar path baru terbaca di shell Anda:
```bash
deactivate 2>/dev/null || true
source .venv/bin/activate

# Jalankan pengujian unit untuk memastikan seluruh modul terpasang (19 tests)
python -m unittest discover -s tests -v

# Atau jalankan langsung via path venv:
# .venv/bin/python -m unittest discover -s tests -v
```

---

## 2. Generate Data Sampel untuk Pengujian

Buat data log UFW tiruan untuk menguji proses analisis:
```bash
# Buat folder kerja
mkdir -p ufw/in ufw/hasil

# Buat file log simulasi 100 baris UFW BLOCK (tanggal 2026-11-08)
cat << 'EOF' > ufw/in/sample-ufw.log
Nov  7 23:59:59 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.1 DST=10.0.0.1 PROTO=TCP SPT=40000 DPT=22
Nov  8 00:01:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51000 DPT=80
Nov  8 00:02:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51001 DPT=443
Nov  8 00:03:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51002 DPT=8080
Nov  8 00:04:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51003 DPT=3306
Nov  8 00:05:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51004 DPT=5432
Nov  8 00:06:00 srv [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.0.0.1 PROTO=TCP SPT=51005 DPT=6379
Nov  8 01:00:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:01:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:02:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:03:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:04:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:05:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:06:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:07:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:08:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:09:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  8 01:10:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.55 DST=10.0.0.1 PROTO=TCP SPT=42100 DPT=22
Nov  9 00:01:00 srv [UFW BLOCK] IN=eth0 SRC=198.51.100.1 DST=10.0.0.1 PROTO=TCP SPT=40001 DPT=22
EOF

# Jalankan analisis harian untuk tanggal 2026-11-08
python analisis_harian.py --input ufw/in/sample-ufw.log --tanggal 2026-11-08 --out-dir ufw/hasil
```

Periksa hasil CSV yang terbentuk:
```bash
ls -l ufw/hasil/
# Akan muncul:
# hasil-2026-11-08-ufw.csv
# hasil-2026-11-08-ufw-ringkasan.csv
```

---

## 3. Uji Coba Web Dashboard (Tanpa Docker)

Jalankan dashboard langsung via Python:
```bash
python dashboard.py --data-dir ufw/hasil --port 8080
```
Buka browser: **http://localhost:8080**

Yang bisa diuji:
- Lihat KPI: Total Blokir, IP Unik, Port Scanner, Burst.
- Cek Chart tren dan donat kategori serangan.
- Cek tabel Top IP (ada fitur filter teks pencarian IP).
- Uji dropdown rentang (Kemarin, 7 Hari, Rentang Bulan).

---

## 4. Uji Coba dengan Docker Compose

Jika Docker sudah terpasang di komputer lokal:
```bash
# 1. Siapkan file .env
cp .env.example .env

# 2. Build dan jalankan container dashboard di background
docker compose up -d --build dashboard

# 3. Cek status container
docker compose ps

# 4. Cek log dashboard
docker compose logs -f dashboard
```

Buka kembali **http://localhost:8080** di browser.

Untuk mematikan container:
```bash
docker compose down
```
