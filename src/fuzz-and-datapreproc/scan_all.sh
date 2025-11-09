#!/usr/bin/env bash
set -euo pipefail
# scan_all.sh - safe Juice Shop scanning + sanitize demo
# Assumes Juice Shop is running at http://localhost:3000
# Requires: docker, nmap, ffuf, nikto, whatweb, jq, python3 (sanitizer.py in same dir)

TARGET_HOST="http://localhost:3000"
TARGET_HOST_HOSTNAME="localhost"
OUTDIR="./outputs"
SANITIZER="./sanitizer.py"   # adjust if sanitizer path differs
SEED_CASE="./seeds/seed1.bin"  # optional seed for sanitizer case hashing

mkdir -p "$OUTDIR"
echo "Starting safe scanning against $TARGET_HOST"
date > "$OUTDIR/run_timestamp.txt"

# 1) Nmap - discovery (TCP SYN + version + OS guess)
echo "[1/8] Running nmap (may require sudo) ..."
sudo -v || true
sudo nmap -sS -sV -O -A -p- -T4 "$TARGET_HOST_HOSTNAME" -oN "$OUTDIR/nmap_full.txt" -oX "$OUTDIR/nmap_full.xml"

# 2) WhatWeb - fingerprint
echo "[2/8] Running whatweb ..."
whatweb -v "$TARGET_HOST" --log-json="$OUTDIR/whatweb.json" > "$OUTDIR/whatweb.txt" 2>&1 || true

# 3) Nikto - light web scan (non-intrusive-ish)
echo "[3/8] Running nikto (safe defaults) ..."
nikto -h "$TARGET_HOST" -output "$OUTDIR/nikto.txt" -Format txt || true

# 4) FFUF - directory discovery (low concurrency to be gentle)
echo "[4/8] Running ffuf for directories (threads=25) ..."
WORDLIST="/usr/share/wordlists/dirb/common.txt"
if [ ! -f "$WORDLIST" ]; then
  # fallback small list
  echo -e "admin\nconfig\nlogin\nuploads\napi\nstatic" > "$OUTDIR/_mini_wordlist.txt"
  WORDLIST="$OUTDIR/_mini_wordlist.txt"
fi
ffuf -u "$TARGET_HOST/FUZZ" -w "$WORDLIST" -t 25 -mc 200,301,302,403 -of json -o "$OUTDIR/ffuf_dirs.json" || true

# 5) Parameter fuzzing (gentle)
echo "[5/8] Running ffuf for a sample param fuzz (gentle) ..."
ffuf -u "$TARGET_HOST/rest/basket?productId=FUZZ" -w "$WORDLIST" -t 20 -of json -o "$OUTDIR/ffuf_param.json" -mc all || true

# 6) SBOM (Syft) via Docker - component list (fast)
echo "[6/8] Running syft (SBOM) via Docker..."
if docker run --rm -v "$(pwd)":/work anchore/syft:latest sh -c 'syft dir:/work -o json' > "$OUTDIR/sbom.json" 2>/dev/null; then
  echo "sbom saved to $OUTDIR/sbom.json"
else
  echo "syft failed or missing; continuing without sbom"
fi

# 7) OWASP ZAP baseline scan (Docker) - non-intrusive baseline
echo "[7/8] Running OWASP ZAP baseline (Docker) - this can take ~10-20m ..."
docker run --rm -d --name zap-demo -p 8090:8090 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true >/dev/null
sleep 6
ZAP_TARGET="${TARGET_HOST}"
docker run --rm -v "$(pwd)":/zap/wrk/:rw owasp/zap2docker-stable zap-baseline.py -t "$ZAP_TARGET" -r /zap/wrk/zap_report.html -J /zap/wrk/zap_report.json || true
docker stop zap-demo >/dev/null 2>&1 || true

# 8) Quick strings / response snippet for web target
echo "[8/8] Collecting a short response snippet ..."
curl -sS "$TARGET_HOST" | head -n 200 > "$OUTDIR/resp_snippet.txt" || true

date > "$OUTDIR/run_finished_timestamp.txt"
echo "All scans complete. Outputs are in $OUTDIR"

# Run sanitizer.py if present to produce sanitized JSON for AI
if [ -x "$SANITIZER" ] || [ -f "$SANITIZER" ]; then
  echo "Running sanitizer to produce sanitized event JSON..."
  python3 "$SANITIZER" --asan "$OUTDIR/resp_snippet.txt" --semgrep "$OUTDIR/semgrep.json" --sbom "$OUTDIR/sbom.json" --coverage "$OUTDIR/coverage.json" --asset juice-shop --sandbox local-juice --agent scan-all --out "$OUTDIR/sanitized_juice_event.json" || true
  echo "Sanitized event: $OUTDIR/sanitized_juice_event.json"
else
  echo "sanitizer.py not found in current dir; skipping sanitization step."
fi

echo "Done. Review files in $OUTDIR before giving to sanitizer/AI."
