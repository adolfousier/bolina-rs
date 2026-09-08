#!/usr/bin/env bash
# rung-e-provision.sh — Provision a Zig daemon data dir for rung E interop.
#
# Usage: ./rung-e-provision.sh <data_dir>
#
# Writes the vector executor identity + CA1 trust anchor to <data_dir>
# in the format the Zig daemon's keys.zig expects:
#   <data_dir>/sig.key      (32B raw — executor Ed25519 seed)
#   <data_dir>/sig.pub      (32B raw — executor Ed25519 pubkey)
#   <data_dir>/static.key   (32B raw — executor X25519 secret)
#   <data_dir>/static.pub   (32B raw — executor X25519 pubkey)
#   <data_dir>/ca/ca0.pub   (32B raw — CA1 Ed25519 pubkey, trust anchor)
#
# Then prints:
#   BOLINA_RESOURCES value
#   Client flags (--zig-kex-pub, --zig-sig-pub)
#
# No cert.bin: executor doesn't need one for inbound binding verification.
# The Zig daemon enters bound-require mode based on own_cert_len > 0, but
# inbound binding frames are processed regardless of mode — the daemon's
# trusted CAs verify the CLIENT's cert, not the daemon's own.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$SCRIPT_DIR/test/vectors.json"

if [ $# -lt 1 ]; then
  echo "usage: $0 <data_dir>" >&2
  exit 2
fi

DATA_DIR="$1"
mkdir -p "$DATA_DIR/ca"

# Extract hex values from vectors.json
SIG_SEED=$(jq -r '.keys.executor.seed' "$VECTORS")
SIG_PUB=$(jq -r '.keys.executor.sig_pubkey' "$VECTORS")
KEX_SEED=$(jq -r '.keys.executor.kex_seed' "$VECTORS")
KEX_PUB=$(jq -r '.keys.executor.kex_pubkey' "$VECTORS")
CA1_PUB=$(jq -r '.keys.ca1.sig_pubkey' "$VECTORS")
RESOURCE=$(jq -r '.structures.envelope_intent.fields.body_resource_id' "$VECTORS")

# hex2bin via python3 (portable — xxd not available on all platforms)
hex2bin() {
  python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))" "$1"
}

# Write raw bytes (hex → binary) with correct Zig keys.zig filenames
hex2bin "$SIG_SEED" > "$DATA_DIR/sig.key"
hex2bin "$SIG_PUB"  > "$DATA_DIR/sig.pub"
hex2bin "$KEX_SEED" > "$DATA_DIR/static.key"
hex2bin "$KEX_PUB"  > "$DATA_DIR/static.pub"
hex2bin "$CA1_PUB"  > "$DATA_DIR/ca/ca0.pub"

# Set permissions (private keys 0600, matching keys.zig writeKeyFile)
chmod 0600 "$DATA_DIR/sig.key" "$DATA_DIR/static.key"
chmod 0644 "$DATA_DIR/sig.pub" "$DATA_DIR/static.pub" "$DATA_DIR/ca/ca0.pub"

echo "=== Provisioned $DATA_DIR ==="
echo "  sig.key:     $(wc -c < "$DATA_DIR/sig.key")B"
echo "  sig.pub:     $(wc -c < "$DATA_DIR/sig.pub")B"
echo "  static.key:  $(wc -c < "$DATA_DIR/static.key")B"
echo "  static.pub:  $(wc -c < "$DATA_DIR/static.pub")B"
echo "  ca/ca0.pub:  $(wc -c < "$DATA_DIR/ca/ca0.pub")B"
echo ""
echo "=== Daemon env ==="
echo "  BOLINA_RESOURCES=$RESOURCE"
echo ""
echo "=== Client flags ==="
echo "  --zig-kex-pub $KEX_PUB"
echo "  --zig-sig-pub $SIG_PUB"
echo ""
echo "=== Run the Zig daemon ==="
echo "  BOLINA_RESOURCES=$RESOURCE <zig-daemon-binary> --data-dir $DATA_DIR ..."
echo ""
echo "=== Then rung E ==="
echo "  ./tools/g4-integration-soak.sh rung-e \\"
echo "    --zig-daemon 127.0.0.1:<udp-port> \\"
echo "    --zig-control 127.0.0.1:<tcp-port> \\"
echo "    --zig-kex-pub $KEX_PUB \\"
echo "    --zig-sig-pub $SIG_PUB \\"
echo "    --zig-token \"\$(cat <data_dir>/control.token)\""
