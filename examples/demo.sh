#!/usr/bin/env bash
#
# End-to-end demo of Onced: exactly-once effect, replay, mismatch rejection,
# passthrough, and metrics — over real sockets, against a tiny Python backend.
#
# Requires: cargo, python3, curl. Run from anywhere:  ./examples/demo.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_PORT=9009
GATEWAY_PORT=8089
WAL_PREFIX="$(mktemp -d)/onced-demo"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -f "${WAL_PREFIX}".*.wal 2>/dev/null || true
}
trap cleanup EXIT

say() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }

# 1. A minimal backend that returns 201 and counts how many times it is actually
#    hit — so we can see Onced call it exactly once across retries.
say "starting backend on :$BACKEND_PORT"
python3 - "$BACKEND_PORT" <<'PY' &
import http.server, sys
hits = 0
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global hits
        hits += 1
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        body = b'{"status":"charged","backend_hits":%d}' % hits
        self.send_response(201)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
PIDS+=($!)

# 2. Build and start the gateway (single shard for a deterministic demo).
say "building + starting onced gateway on :$GATEWAY_PORT"
( cd "$ROOT" && cargo build --release -q -p onced-gateway )
ONCED_LISTEN="127.0.0.1:$GATEWAY_PORT" \
ONCED_BACKEND="127.0.0.1:$BACKEND_PORT" \
ONCED_WAL="$WAL_PREFIX" \
ONCED_SHARDS=1 \
  "$ROOT/target/release/onced-gateway" &
PIDS+=($!)

# Wait for the gateway to accept connections.
for _ in $(seq 1 50); do
  curl -fs "127.0.0.1:$GATEWAY_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done

G="127.0.0.1:$GATEWAY_PORT"

say "same Idempotency-Key, sent twice -> backend charged ONCE, second is replayed"
curl -s -i -X POST "$G/charge" -H 'Idempotency-Key: demo-1' -d 'amount=500' | grep -Ei 'onced-status|backend_hits'
curl -s -i -X POST "$G/charge" -H 'Idempotency-Key: demo-1' -d 'amount=500' | grep -Ei 'onced-status|backend_hits'

say "same key, DIFFERENT body -> 422 mismatch, backend untouched"
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST "$G/charge" -H 'Idempotency-Key: demo-1' -d 'amount=999'

say "no key -> straight passthrough each time"
curl -s -X POST "$G/charge" -d 'x' ; echo
curl -s -X POST "$G/charge" -d 'x' ; echo

say "metrics"
curl -s "$G/metrics"

say "done"
