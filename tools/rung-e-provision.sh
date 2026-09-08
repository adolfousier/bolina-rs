#!/usr/bin/env bash
# rung-e-provision.sh — Provision a Zig daemon data dir for rung E interop.
#
# Usage: ./rung-e-provision.sh <data_dir>
#
# Writes the vector executor identity + CA1 trust anchor + executor cert to <data_dir>
# in the format the Zig daemon's keys.zig expects:
#   <data_dir>/sig.key      (32B raw — executor Ed25519 seed)
#   <data_dir>/sig.pub      (32B raw — executor Ed25519 pubkey)
#   <data_dir>/static.key   (32B raw — executor X25519 secret)
#   <data_dir>/static.pub   (32B raw — executor X25519 pubkey)
#   <data_dir>/ca/ca0.pub   (32B raw — CA1 Ed25519 pubkey, trust anchor)
#   <data_dir>/cert.bin     (190B — executor cert signed by CA1, for bound-require mode)
#
# The Zig daemon needs cert.bin (own_cert_len > 0) to leave unbound-accept mode.
# Without it, binding frames from inbound peers are silently dropped.
#
# Then prints:
#   BOLINA_RESOURCES value
#   Client flags (--zig-kex-pub, --zig-sig-pub)

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

# Generate cert.bin: executor cert signed by CA1.
# The Zig daemon needs own_cert_len > 0 to leave unbound-accept mode.
# Without cert.bin, binding frames from inbound peers are silently dropped
# (self.drop() at daemon.zig:201).
CERT_SCRIPT=$(mktemp)
trap 'rm -f "$CERT_SCRIPT"' EXIT
cat > "$CERT_SCRIPT" << 'CERTPY'
import json, struct, sys
from nacl.signing import SigningKey

data_dir = sys.argv[1]
vectors_path = sys.argv[2]

with open(vectors_path) as f:
    v = json.load(f)

ca1_seed = bytes.fromhex(v["keys"]["ca1"]["seed"])
ca1_pub = bytes.fromhex(v["keys"]["ca1"]["sig_pubkey"])
exec_pub = bytes.fromhex(v["keys"]["executor"]["sig_pubkey"])
exec_kex = bytes.fromhex(v["keys"]["executor"]["kex_pubkey"])

# Build cert body (tbs): version(1) + role(1) + sig_pub(32) + kex_pub(32)
#   + not_before(8) + not_after(8) + name_len(2) + name + scope_count(1)
tbs = bytearray()
tbs.append(3)           # version
tbs.append(0x04)        # role_bits: ROLE_EXECUTOR = 1<<2
tbs.extend(exec_pub)    # sig_pubkey (32B)
tbs.extend(exec_kex)    # kex_pubkey (32B)
tbs.extend(struct.pack(">Q", 0))                    # not_before = 0
tbs.extend(struct.pack(">Q", 0xFFFFFFFFFFFFFFFF))   # not_after = max u64
name = b"executor"
tbs.extend(struct.pack(">H", len(name)))
tbs.extend(name)
tbs.append(0)           # scope_count = 0

# Sign: DOMAIN_CERT (0x01) || tbs
sig_input = bytes([0x01]) + bytes(tbs)
sk = SigningKey(ca1_seed)
sig = sk.sign(sig_input).signature  # 64 bytes

# Wire: tbs + ca_sig_count(1) + ca1_pub(32) + sig(64)
wire = bytearray(tbs)
wire.append(1)          # ca_sig_count = 1
wire.extend(ca1_pub)    # ca1 pubkey (32B)
wire.extend(sig)        # ed25519 sig (64B)

cert_path = data_dir + "/cert.bin"
with open(cert_path, "wb") as f:
    f.write(wire)
print(f"  cert.bin:    {len(wire)}B (executor cert, signed by ca1)")
CERTPY
python3 "$CERT_SCRIPT" "$DATA_DIR" "$VECTORS"

# Set permissions (private keys 0600, matching keys.zig writeKeyFile)
chmod 0600 "$DATA_DIR/sig.key" "$DATA_DIR/static.key"
chmod 0644 "$DATA_DIR/sig.pub" "$DATA_DIR/static.pub" "$DATA_DIR/ca/ca0.pub" "$DATA_DIR/cert.bin"

echo "=== Provisioned $DATA_DIR ==="
echo "  sig.key:     $(wc -c < "$DATA_DIR/sig.key")B"
echo "  sig.pub:     $(wc -c < "$DATA_DIR/sig.pub")B"
echo "  static.key:  $(wc -c < "$DATA_DIR/static.key")B"
echo "  static.pub:  $(wc -c < "$DATA_DIR/static.pub")B"
echo "  ca/ca0.pub:  $(wc -c < "$DATA_DIR/ca/ca0.pub")B"
echo "  cert.bin:    $(wc -c < "$DATA_DIR/cert.bin")B"
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
