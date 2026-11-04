## cara kumpulin log 1 hari :
echo Bulan,Hari,Waktu,Host,Aksi,Interface_In,Mac_Address,IP_Sumber,IP_Tujuan,Protokol,Port_Sumber,Port_Tujuan > /analisis/ufw/26-oct-26.csv

awk -v sekarang="$(date +%s)" '
BEGIN {
    # Membuat mapping nama bulan ke angka untuk konversi timestamp
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
    for (i=1; i<=12; i++) bln[m[i]] = i
}
/^... [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/ && /UFW BLOCK/ {
    # Ambil tahun saat ini karena log syslog biasanya tidak mencantumkan tahun
    "date +%Y" | getline thn; close("date +%Y")
    
    # Format ulang waktu log agar bisa dikonversi ke epoch second
    waktu_str = thn " " bln[$1] " " $2 " " gensub(/:/, " ", "g", $3)
    waktu_log = mktime(waktu_str)
    
    # Filter: Hanya ambil jika waktu log berada dalam rentang 24 jam terakhir (86400 detik)
    if (sekarang - waktu_log <= 86400 && sekarang - waktu_log >= 0) {
        src= ""; dst= ""; in_if= ""; mac= ""; proto= ""; spt= ""; dpt= ""
        for (i=1; i<=NF; i++) {
            if ($i ~ /^SRC=/) src=substr($i,5)
            if ($i ~ /^DST=/) dst=substr($i,5)
            if ($i ~ /^IN=/) in_if=substr($i,4)
            if ($i ~ /^MAC=/) mac=substr($i,5)
            if ($i ~ /^PROTO=/) proto=substr($i,7)
            if ($i ~ /^SPT=/) spt=substr($i,5)
            if ($i ~ /^DPT=/) dpt=substr($i,5)
        }
        print $1, $2, $3, $4, "BLOCK", in_if, mac, src, dst, proto, spt, dpt
    }
}' OFS=, ufw.log >> /analisis/ufw/26-oct-26.csv



## cara pakai analisis_harian.py
- Script otomatis mencari file input di `ufw/data/` jika path tidak ditemukan di cwd.
- Output default disimpan di `ufw/hasil/hasil-<tgl><bln>-ufw.csv` (folder dibuat otomatis).
- Venv sudah ada di `.venv/`; gunakan `.venv/bin/python` untuk menjalankan.

Contoh:
  .venv/bin/python analisis_harian.py --input 25b-oct-26.csv --fecha "Oct 25"
  .venv/bin/python analisis_harian.py --input 25b-oct-26.csv --fecha "Oct 25" --ref hasil-24oct-ufw.csv
  .venv/bin/python analisis_harian.py --input ufw.log --fecha "Oct 26" --abaikan 203.0.113.7,203.0.113.8

Argumen:
  --input   : file rekap .csv (12 kolom) atau log mentah ufw.log
  --fecha   : tanggal yang diinginkan, contoh "Oct 25". Kosong = tanggal paling banyak muncul
  --tahun   : tahun (default: tahun sekarang)
  --ref     : file hasil sebelumnya (bisa tanpa path, otomatis dicari di ufw/hasil/)
  --abaikan : IP yang dibuang, dipisah koma
  --out     : nama file output (default: ufw/hasil/hasil-<tgl><bln>-ufw.csv)
