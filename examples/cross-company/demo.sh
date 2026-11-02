#!/usr/bin/env bash
# Cross-company demo: XYZ Corporation's procurement agent calls Supplier ABC.
#
#   ./demo.sh            (uses `nexum` on PATH, or builds it with cargo)
#
# Everything runs locally in a temp directory. No cloud services involved.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
if command -v nexum >/dev/null 2>&1; then
  NEXUM="nexum"
else
  (cd "$HERE/../.." && cargo build -q -p nexum)
  NEXUM="$HERE/../../target/debug/nexum"
fi
PORT="${PORT:-8088}"
GW="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
cd "$WORK"
trap 'kill "${GW_PID:-}" 2>/dev/null || true' EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
xyz() { "$NEXUM" -c xyz/nexum.yaml "$@"; }
abc() { "$NEXUM" -c abc/nexum.yaml "$@"; }

step "Two independent organizations, each with its own root of trust"
"$NEXUM" init --domain xyz.com --dir xyz >/dev/null
"$NEXUM" init --domain abc.com --dir abc --listen "127.0.0.1:$PORT" >/dev/null
echo "xyz.com and abc.com initialized in $WORK"

step "XYZ registers its agents (keys stay with XYZ)"
xyz agents register --id spiffe://xyz.com/agents/procurement --name procurement \
  --owner jane@xyz.com --framework langgraph --protocol a2a >/dev/null
xyz agents register --id spiffe://xyz.com/agents/inventory-checker --name inventory-checker \
  --owner jane@xyz.com --framework custom-python >/dev/null
xyz agents list

step "ABC decides what it accepts from XYZ (only XYZ's public key is shared)"
abc trust add xyz.com --issuer https://identity.xyz.com --key xyz/org.jwk.json \
  --allow inventory.read --allow pricing.read --allow quote.create \
  --deny payment.execute --deny customer.export >/dev/null
cp "$HERE/abc-policy.yaml" abc/policy.yaml
abc trust list

step "ABC starts its gateway"
"$NEXUM" -c abc/nexum.yaml gateway start >gateway.log 2>&1 &
GW_PID=$!
for _ in $(seq 50); do curl -sf "$GW/healthz" >/dev/null && break; sleep 0.1; done

step "XYZ issues a 15-minute grant to its procurement agent, acting for jane@xyz.com"
xyz grants issue --sub spiffe://xyz.com/agents/procurement \
  --holder xyz/.nexum/keys/procurement.key.json \
  --cap inventory.read --cap pricing.read --cap quote.create \
  --res 'supplier://abc/*' --aud abc.com \
  --delegatable inventory.read --max-depth 1 \
  --actor jane@xyz.com --purpose q3-restock --ttl 900 --out root.jwt

PROC=(--grant root.jwt --key xyz/.nexum/keys/procurement.key.json --gateway "$GW")

step "Request 1: procurement agent reads inventory"
"$NEXUM" call "${PROC[@]}" --action inventory.read --resource supplier://abc/sku/123 || true

step "Request 2: procurement delegates ONLY inventory.read to a sub-agent"
xyz grants delegate --parent root.jwt --key xyz/.nexum/keys/procurement.key.json \
  --sub spiffe://xyz.com/agents/inventory-checker \
  --holder xyz/.nexum/keys/inventory-checker.key.json \
  --cap inventory.read --ttl 300 --out child.jwt
CHILD=(--grant root.jwt --grant child.jwt --key xyz/.nexum/keys/inventory-checker.key.json --gateway "$GW")
"$NEXUM" call "${CHILD[@]}" --action inventory.read --resource supplier://abc/sku/123 || true

step "Request 3: the sub-agent tries to execute a payment"
"$NEXUM" call "${CHILD[@]}" --action payment.execute --resource supplier://abc/invoice/77 --value 9000 || true

step "The sub-agent cannot mint itself more authority either"
xyz grants delegate --parent root.jwt --parent child.jwt --key xyz/.nexum/keys/inventory-checker.key.json \
  --sub spiffe://xyz.com/agents/inventory-checker --holder xyz/.nexum/keys/inventory-checker.key.json \
  --cap payment.execute 2>&1 || true

step "Request 4: procurement asks for a \$250,000 quote"
OUT="$("$NEXUM" call "${PROC[@]}" --action quote.create --resource supplier://abc/quote/new --value 250000 || true)"
echo "$OUT"
APPROVAL="$(echo "$OUT" | awk '/Approval:/ {print $2}')"

step "An ABC approver reviews and approves it"
abc approvals list
abc approvals approve "$APPROVAL" --by cfo@abc.com

step "Procurement retries with the approval (single use)"
"$NEXUM" call "${PROC[@]}" --action quote.create --resource supplier://abc/quote/new --value 250000 --approval "$APPROVAL" || true

step "ABC revokes trust in XYZ; everything from XYZ stops immediately"
abc trust revoke xyz.com --reason "contract ended"
"$NEXUM" call "${PROC[@]}" --action inventory.read --resource supplier://abc/sku/123 || true

step "ABC's tamper-evident audit trail"
abc audit tail
abc audit verify
