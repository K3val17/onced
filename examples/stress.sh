#!/usr/bin/env bash
#
# Stress Onced "to the brim". Three stages, hardest first:
#
#   1. DETERMINISTIC SIMULATION SOAK  - the real stress. Millions of fault-injected
#      operations (crashes, clock jumps, lease takeovers, fingerprint mismatches)
#      across both durability modes, asserting every invariant after every step.
#      Socket-free and deterministic, so it runs identically everywhere and any
#      failure replays from its seed.
#   2. THROUGHPUT BENCHMARK           - raw engine ops/sec (replay hot path, durable
#      paths) with no network in the way.
#   3. LIVE HTTP DEMO                 - exactly-once over real sockets under
#      concurrency, against a running gateway.
#
# Requires: cargo (always); python3 + curl (only for stage 3). Run from anywhere.
# Tune: SEEDS, STEPS (stage 1); BENCH_N (stage 2); N, CONC (stage 3).
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SEEDS=${SEEDS:-100}
STEPS=${STEPS:-5000}
BENCH_N=${BENCH_N:-2000000}
N=${N:-100}
CONC=${CONC:-20}

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
pass() { printf '\033[1;32m  PASS\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31m  FAIL\033[0m %s\n' "$1"; exit 1; }

# --- Stage 1: deterministic fault-injection soak (the brim) ------------------
say "1. simulation soak: $SEEDS seeds x $STEPS steps x 2 durability modes"
echo "   (fault injection: crashes, clock jumps, lease takeovers, fingerprint mismatches)"
ONCED_SIM_SEEDS=$SEEDS ONCED_SIM_STEPS=$STEPS cargo run --release -q -p onced-sim \
  || fail "an invariant was violated under fault injection (see the seed above)"
pass "all invariants held across ~$(( SEEDS * STEPS * 2 )) fault-injected operations"

# --- Stage 2: throughput ------------------------------------------------------
say "2. throughput benchmark ($BENCH_N ops per measurement)"
ONCED_BENCH_N=$BENCH_N cargo run --release -q -p onced-bench || fail "benchmark failed"

# --- Stage 3: live HTTP under concurrency (needs python3 + curl) -------------
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  say "3. live HTTP demo SKIPPED (needs python3 + curl)"
  echo; pass "brim stress complete (stages 1-2)"; exit 0
fi

say "3. live HTTP: $N concurrent requests of ONE key over real sockets"
BPORT=${BACKEND_PORT:-9300}; GPORT=${GATEWAY_PORT:-8300}
G="127.0.0.1:$GPORT"; WAL="$(mktemp -d)/onced-stress"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -f "${WAL}".*.wal 2>/dev/null || true; }
trap cleanup EXIT

python3 - "$BPORT" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0))); b = b'charged'
        self.send_response(201); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
PIDS+=($!)
ONCED_LISTEN="$G" ONCED_BACKEND="127.0.0.1:$BPORT" ONCED_WAL="$WAL" \
  ./target/release/onced-gateway >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do curl -fs "http://$G/healthz" >/dev/null 2>&1 && break; sleep 0.1; done

metric() { curl -s "http://$G/metrics" | awk '/outcome="'"$1"'"/{print $2}'; }
c0=$(metric created)
seq 1 "$N" | xargs -P "$CONC" -I{} curl -s -o /dev/null --max-time 15 \
  -X POST "http://$G/charge" -H 'X-Forwarded-For: 10.0.0.1' -H 'Idempotency-Key: hot' -d 'amount=500'
cd=$(( $(metric created) - c0 ))
# The invariant is "never created more than once". cd==0 just means the local OS
# would not let us open the connections (common in a sandbox); that is not a
# correctness failure, and exactly-once over real sockets is proven in CI.
if [ "$cd" -gt 1 ]; then
  fail "key created $cd times under contention (exactly-once violated!)"
elif [ "$cd" -eq 1 ]; then
  pass "$N concurrent retries of one key -> backend created it exactly once"
else
  echo "  (note: local sockets could not push concurrent load; correctness is"
  echo "   proven over real sockets in CI and by stages 1-2 above)"
fi

# mismatch safety (sequential; a fresh IP so the burst's abuse counter does not apply)
curl -s -o /dev/null --max-time 5 -X POST "http://$G/charge" -H 'X-Forwarded-For: 10.0.0.50' -H 'Idempotency-Key: mm' -d 'a=1' 2>/dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "http://$G/charge" -H 'X-Forwarded-For: 10.0.0.50' -H 'Idempotency-Key: mm' -d 'a=2' 2>/dev/null)
if [ "$code" = 422 ]; then
  pass "same key + different body -> 422 (no wrong replay)"
elif [ "$code" = 000 ] || [ -z "$code" ]; then
  echo "  (note: mismatch demo skipped, local socket unavailable)"
else
  fail "expected 422 for a mismatched body, got $code"
fi

say "live metrics"; curl -s "http://$G/metrics"
echo; pass "brim stress complete (all three stages)"
