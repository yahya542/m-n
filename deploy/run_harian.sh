#!/usr/bin/env bash
# Dipanggil cron di HOST. Dua langkah:
#   1) staging: salin baris "UFW BLOCK" dari ufw.log.1 + ufw.log ke folder input (hak akses 0600)
#   2) jalankan container analisis sekali jalan (tanpa jaringan, root FS read-only)
# Container tidak pernah menyentuh /var/log. Pemakaian: run_harian.sh [YYYY-MM-DD]
set -euo pipefail
export LC_ALL=C

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
# Nilai: environment menang atas .env (sama seperti docker compose). .env dibaca sebagai data,
# tidak dieksekusi sebagai shell.
envval() {
  local k="$1" v="${!1-}"
  if [ -z "$v" ] && [ -f .env ]; then
    v="$(grep -E "^${k}=" .env | tail -n1 | cut -d= -f2- || true)"
    v="${v%\"}"; v="${v#\"}"
  fi
  printf '%s' "$v"
}
LOG_DIR="$(envval UFW_LOG_DIR)";  LOG_DIR="${LOG_DIR:-/var/log}"
IN_DIR="$(envval UFW_IN_DIR)";    IN_DIR="${IN_DIR:-$DIR/ufw/in}"
OUT_DIR="$(envval UFW_OUT_DIR)";  OUT_DIR="${OUT_DIR:-$DIR/ufw/hasil}"
ABAIKAN="$(envval ABAIKAN_IP)"
APP_LOG="${APP_LOG:-$DIR/ufw/logs/harian.log}"
TANGGAL="${1:-}"

mkdir -p "$IN_DIR" "$OUT_DIR" "$(dirname "$APP_LOG")"
log() { echo "[$(date '+%F %T')] $*" >> "$APP_LOG"; }
trap 'rc=$?; [ $rc -ne 0 ] && log "GAGAL (exit $rc)"; rm -f "${TMP:-}"' EXIT

# --- 1) staging ---
TMP="$(umask 077; mktemp "$IN_DIR/.ufw-block.XXXXXX")"
for f in "$LOG_DIR/ufw.log.1" "$LOG_DIR/ufw.log"; do
  if [ -e "$f" ]; then
    [ -r "$f" ] || { log "tidak bisa membaca $f (cek keanggotaan grup adm)"; exit 1; }
    grep -aF 'UFW BLOCK' "$f" >> "$TMP" || true
  elif [ "$f" = "$LOG_DIR/ufw.log" ]; then
    log "$f tidak ada"; exit 1
  fi
done
mv -f "$TMP" "$IN_DIR/ufw-block.log"

# --- 2) analisis ---
if [ "${SKIP_PULL:-0}" != "1" ]; then
  docker compose pull --quiet analisis >> "$APP_LOG" 2>&1 \
    || log "peringatan: pull gagal, memakai image lokal yang ada"
fi
log "mulai analisis ${TANGGAL:-kemarin}"
docker compose run --rm -T analisis \
  --input /data/in/ufw-block.log --out-dir /data/hasil --ketat \
  --abaikan "$ABAIKAN" ${TANGGAL:+--tanggal "$TANGGAL"} >> "$APP_LOG" 2>&1
log "selesai OK"
date -Is > "$(dirname "$APP_LOG")/terakhir_sukses"
