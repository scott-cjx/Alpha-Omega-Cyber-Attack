#!/usr/bin/env bash
# top_level_scan.sh
# Robust top-level scanning pipeline for Juice Shop demo (safe / low-impact).
# - Starts Juice Shop (on configured port)
# - Runs nmap, whatweb, nikto, ffuf (dir + param), syft SBOM (docker)
# - Produces sanitized ffuf JSON with SHA256 url hashes
# - Packages sanitized results into outputs/send_for_sanitizer.zip
#
set -euo pipefail
IFS=$'\n\t'

# CONFIG - adjust if needed
TARGET_PORT=3000
TARGET_HOST="localhost"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"
JUICE_IMAGE="bkimminich/juice-shop"
JUICE_NAME="juice-shop-demo"
OUTDIR="./outputs"
MINI_WORDLIST="$OUTDIR/_mini_wordlist.txt"
FFUF_THREADS=20
FFUF_WORDLIST="${MINI_WORDLIST}"
FFUF_PARAM_ENDPOINT="/rest/basket?productId=FUZZ"
SYFT_IMAGE="anchore/syft:latest"
WAIT_RETRY=30
WAIT_SLEEP=1

mkdir -p "$OUTDIR"

info(){ echo "-- [INFO] $*"; }
warn(){ echo "-- [WARN] $*" >&2; }
err(){ echo "-- [ERROR] $*" >&2; exit 1; }

# 0. checks
if ! command -v docker >/dev/null 2>&1; then
  warn "docker client not found in PATH. Docker client required for starting juice-shop & syft."
fi

# 1. clean previous juice-shop container if present
info "Stopping any previous container named $JUICE_NAME..."
if docker ps -a --format '{{.Names}}' | grep -x "${JUICE_NAME}" >/dev/null 2>&1; then
  docker stop "${JUICE_NAME}" >/dev/null 2>&1 || true
  docker rm "${JUICE_NAME}" >/dev/null 2>&1 || true
fi

# 2. start juice-shop
info "Starting Juice Shop container (${JUICE_IMAGE}) on host port ${TARGET_PORT}..."
if ! docker ps --format '{{.Names}}' | grep -x "${JUICE_NAME}" >/dev/null 2>&1; then
  docker run --rm -d --name "${JUICE_NAME}" -p ${TARGET_PORT}:3000 "${JUICE_IMAGE}" >/dev/null
  info "Started ${JUICE_NAME}."
else
  info "${JUICE_NAME} already running."
fi

# 3. wait for target
info "Waiting for ${TARGET_URL} to be ready..."
i=0
while true; do
  if curl -s --max-time 3 "${TARGET_URL}" >/dev/null 2>&1; then
    info "${TARGET_URL} reachable."
    break
  fi
  i=$((i+1))
  if [ $i -ge $WAIT_RETRY ]; then
    docker logs "${JUICE_NAME}" --tail 50 || true
    err "Timed out waiting for ${TARGET_URL}."
  fi
  sleep $WAIT_SLEEP
done

# 4. fallback mini wordlist
if [ ! -f "$MINI_WORDLIST" ]; then
  info "Creating fallback wordlist at $MINI_WORDLIST"
  cat > "$MINI_WORDLIST" <<'WL'
admin
config
login
uploads
static
api
rest
assets
favicon.ico
WL
fi

# 5. nmap scan (safe)
info "Running nmap (service discovery)..."
NMAP_OUT_N="$OUTDIR/nmap_full.txt"
NMAP_OUT_X="$OUTDIR/nmap_full.xml"
if sudo -n true 2>/dev/null; then
  sudo nmap -sS -sV -O -A -p- -T4 "${TARGET_HOST}" -oN "$NMAP_OUT_N" -oX "$NMAP_OUT_X" || true
else
  nmap -sT -sV -p- -T4 "${TARGET_HOST}" -oN "$NMAP_OUT_N" -oX "$NMAP_OUT_X" || true
fi

# 6. whatweb
info "Running whatweb..."
WHATWEB_OUT="$OUTDIR/whatweb.txt"
whatweb -v "${TARGET_URL}" --log-json="$OUTDIR/whatweb.json" > "$WHATWEB_OUT" 2>&1 || true

# 7. nikto (light)
info "Running nikto..."
NIKTO_OUT="$OUTDIR/nikto.txt"
nikto -h "${TARGET_URL}" -output "$NIKTO_OUT" -Format txt || true

# 8. ffuf directory fuzz
info "Running ffuf (directories) ..."
FFUF_DIR_OUT="$OUTDIR/ffuf_dirs.json"
if command -v ffuf >/dev/null 2>&1; then
  ffuf -u "${TARGET_URL}/FUZZ" -w "${FFUF_WORDLIST}" -t ${FFUF_THREADS} -mc 200,301,302,403 -of json -o "$FFUF_DIR_OUT" || true
else
  warn "ffuf not found; skipping directory fuzz"
fi

# 9. ffuf param fuzz
info "Running ffuf (params) ..."
FFUF_PARAM_OUT="$OUTDIR/ffuf_param.json"
if command -v ffuf >/dev/null 2>&1; then
  ffuf -u "${TARGET_URL}${FFUF_PARAM_ENDPOINT}" -w "${FFUF_WORDLIST}" -t $((FFUF_THREADS/2)) -of json -o "$FFUF_PARAM_OUT" -mc all || true
fi

# 10. SBOM via syft (docker)
info "Running SBOM (syft) via docker (if available)..."
SBOM_OUT="$OUTDIR/sbom.json"
if docker pull "${SYFT_IMAGE}" >/dev/null 2>&1; then
  docker run --rm -v "$(pwd)":/work "${SYFT_IMAGE}" syft dir:/work -o json > "$SBOM_OUT" 2>/dev/null || true
else
  warn "syft image pull failed; skipping SBOM"
fi

# 11. small response snippet
info "Capturing small response snippet..."
curl -sS "${TARGET_URL}" | head -c 4096 > "$OUTDIR/resp_snippet.txt" || true

# 12. sanitize ffuf results -> ffuf_sanitized.json (compute SHA256 URL hashes)
FFUF_SAN_OUT="$OUTDIR/ffuf_sanitized.json"
if [ -f "$FFUF_DIR_OUT" ]; then
  info "Sanitizing ffuf results -> $FFUF_SAN_OUT"
  python3 - "$FFUF_DIR_OUT" "$FFUF_SAN_OUT" <<'PY'
import sys,json,hashlib
fin=sys.argv[1]; fout=sys.argv[2]
d=json.load(open(fin))
out=[]
for r in d.get("results",[]):
    token = r.get("input",{}).get("FUZZ","")
    ffufhash = r.get("input",{}).get("FFUFHASH","")
    status = r.get("status",None)
    length = r.get("length",None)
    words = r.get("words",None)
    lines = r.get("lines",None)
    ctype = r.get("content-type","")
    duration = r.get("duration",0)
    url = r.get("url","")
    h=hashlib.sha256(url.encode('utf-8')).hexdigest()
    out.append({
        "path_token": token,
        "ffuf_hash": ffufhash,
        "status": status,
        "content_type": ctype,
        "length": length,
        "words": words,
        "lines": lines,
        "duration_ms": round(duration/1000000.0,3),
        "url_sha256": h
    })
open(fout,"w").write(json.dumps(out,indent=2))
PY
else
  warn "No ffuf dirs output to sanitize."
fi

# 13. package sanitized files
PKG_DIR="$OUTDIR/ready_for_sanitizer"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
cp -L "$OUTDIR/nmap_full.xml" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/whatweb.json" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/nikto.txt" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/ffuf_sanitized.json" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/semgrep.json" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/sbom.json" "$PKG_DIR/" 2>/dev/null || true
cp -L "$OUTDIR/resp_snippet.txt" "$PKG_DIR/" 2>/dev/null || true

cat > "$PKG_DIR/manifest.txt" <<'MF'
Sanitized package - produced by top_level_scan.sh
Files included (already sanitized, safe for AI ingestion):
- nmap_full.xml
- whatweb.json
- nikto.txt
- ffuf_sanitized.json
- semgrep.json (if present)
- sbom.json (if present)
- resp_snippet.txt
MF

PKG_ARCHIVE="$OUTDIR/send_for_sanitizer.zip"
info "Creating package $PKG_ARCHIVE ..."
(cd "$OUTDIR" && zip -r -q send_for_sanitizer.zip ready_for_sanitizer)

# 14. stop juice-shop container (optional)
info "Stopping juice-shop container..."
docker stop "${JUICE_NAME}" >/dev/null 2>&1 || true

info "Done. Sanitized package: $PKG_ARCHIVE"
ls -lh "$OUTDIR" | sed -n '1,200p' || true
