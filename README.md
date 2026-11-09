# ufw-monitor

Ringkasan harian log UFW `BLOCK` per IP sumber (fitur + KMeans + IsolationForest) untuk server OJS.
Data (`ufw/`, `.env`, `*.csv`, `*.log`) **tidak pernah** di-commit: lihat `.gitignore`.

## Alur
```
GitHub Actions: test -> build image -> push ke GHCR (hanya dari main)
Server (cron 06:00): deploy/run_harian.sh
   1. staging: baris "UFW BLOCK" dari ufw.log.1 + ufw.log -> ufw/in/ufw-block.log (0600)
   2. docker compose pull (image terbaru/tag yang dipin) lalu run --rm analisis
      (tanpa jaringan, root FS read-only, tidak menyentuh /var/log)
   -> ufw/hasil/hasil-YYYY-MM-DD-ufw.csv dan ...-ufw-ringkasan.csv
```
`--ketat` membatalkan job (exit 3, tanpa file hasil) bila input tidak terbukti mencakup seluruh hari target.

## Pasang di server (sekali)
```bash
git clone <url-repo> /opt/ufw-monitor && cd /opt/ufw-monitor
cp .env.example .env && nano .env          # TZ harus sama dgn `timedatectl`; isi APP_UID/APP_GID
sed -i 's#OWNER/REPO#<owner>/<repo>#' docker-compose.yml   # huruf kecil
echo <PAT read:packages> | docker login ghcr.io -u <user> --password-stdin   # jika image private
sudo usermod -aG adm "$USER"               # agar bisa membaca /var/log/ufw.log (login ulang)
./deploy/run_harian.sh 2026-11-03          # uji manual dengan tanggal yang log-nya masih ada

# Jalankan dashboard web monitoring (konsumsi RAM ~15MB)
docker compose up -d dashboard
```
Cron (`crontab -e`):
```
0 6 * * * /opt/ufw-monitor/deploy/run_harian.sh
```
Periksa `ufw/logs/harian.log` dan umur file `ufw/logs/terakhir_sukses`.

### Akses Dashboard Web
Dashboard ter-bind secara default ke `127.0.0.1:8080` (aman, tidak terekspos publik).
Akses dari laptop via SSH Tunnel:
```bash
ssh -L 8080:127.0.0.1:8080 user@ip-server
```
Buka browser: `http://localhost:8080`

Atau buka port khusus untuk IP publik admin via UFW di server:
Ubah `DASHBOARD_HOST=0.0.0.0` di `.env`, lalu izinkan hanya IP admin:
```bash
sudo ufw allow from <IP_PUBLIK_ADMIN> to any port 8080 proto tcp
```

## Pengembangan lokal
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
python analisis_harian.py --input ufw.log.1 ufw.log --tanggal 2026-11-03 --out-dir ufw/hasil
python dashboard.py --data-dir ufw/hasil --port 8080
```
