#!/usr/bin/env bash
# Creates (or completes) a public OCI Load Balancer for HTTP-01 test traffic.
#
# Prerequisites:
# - OCI CLI configured with permission to manage load balancers in COMPARTMENT_ID.
# - SUBNET_ID must be a public subnet (route to an Internet Gateway).
# - BACKEND_IP must belong to a VNIC in the same VCN and OCI region as SUBNET_ID.
#   Set BACKEND_SUBNET_ID when the backend is in a different subnet of that VCN.
#
# Optional TLS support: set CERTIFICATE_ID to an OCI Certificates OCID before
# running the script to add an HTTPS listener on port 443. The certificate is
# never created or changed by this script.

set -euo pipefail

: "${COMPARTMENT_ID:?Set COMPARTMENT_ID to the OCI compartment OCID.}"
: "${SUBNET_ID:?Set SUBNET_ID to the public subnet OCID.}"
: "${BACKEND_IP:?Set BACKEND_IP to the private IPv4 address of the HTTP-01 responder.}"

: "${OCI_REGION:?Set OCI_REGION to the region containing the subnet.}"
export OCI_CLI_REGION="$OCI_REGION"
BACKEND_SUBNET_ID="${BACKEND_SUBNET_ID:=$SUBNET_ID}"
LOAD_BALANCER_NAME="${LOAD_BALANCER_NAME:=oci-acme-test-lb}"
BACKEND_SET_NAME="${BACKEND_SET_NAME:=acme-http01-backends}"
HTTP_LISTENER_NAME="${HTTP_LISTENER_NAME:=http-80}"
HTTPS_LISTENER_NAME="${HTTPS_LISTENER_NAME:=https-443}"
BACKEND_PORT="${BACKEND_PORT:=8080}"
CERTIFICATE_ID="${CERTIFICATE_ID:=}"
WAIT_SECONDS="${WAIT_SECONDS:=900}"
LB_NSG_NAME="${LB_NSG_NAME:=oci-acme-test-lb-nsg}"
BACKEND_NSG_NAME="${BACKEND_NSG_NAME:=oci-acme-test-backend-nsg}"

command -v oci >/dev/null 2>&1 || {
  echo "OCI CLI was not found in PATH." >&2
  exit 127
}
command -v jq >/dev/null 2>&1 || {
  echo "jq was not found in PATH (required to preserve existing NSGs)." >&2
  exit 127
}

require_ocid() {
  local value="$1"
  local label="$2"
  if [[ ! "$value" =~ ^ocid1\.[A-Za-z0-9._-]+ ]]; then
    echo "$label must be a valid OCI OCID." >&2
    exit 2
  fi
}

require_ocid "$COMPARTMENT_ID" "COMPARTMENT_ID"
require_ocid "$SUBNET_ID" "SUBNET_ID"
require_ocid "$BACKEND_SUBNET_ID" "BACKEND_SUBNET_ID"
if [[ -n "$CERTIFICATE_ID" ]]; then
  require_ocid "$CERTIFICATE_ID" "CERTIFICATE_ID"
fi
if [[ ! "$BACKEND_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "BACKEND_IP must be an IPv4 address." >&2
  exit 2
fi
read -r ip_octet_1 ip_octet_2 ip_octet_3 ip_octet_4 <<<"${BACKEND_IP//./ }"
for ip_octet in "$ip_octet_1" "$ip_octet_2" "$ip_octet_3" "$ip_octet_4"; do
  if (( ip_octet > 255 )); then
    echo "BACKEND_IP must be a valid IPv4 address." >&2
    exit 2
  fi
done
if (( BACKEND_PORT < 1 || BACKEND_PORT > 65535 )); then
  echo "BACKEND_PORT must be between 1 and 65535." >&2
  exit 2
fi
if (( WAIT_SECONDS < 1 )); then
  echo "WAIT_SECONDS must be greater than zero." >&2
  exit 2
fi

has_value() {
  [[ -n "$1" && "$1" != "null" && "$1" != "None" ]]
}

wait_for_active() {
  local state=""
  local elapsed=0

  while (( elapsed < WAIT_SECONDS )); do
    state="$(oci lb load-balancer get \
      --load-balancer-id "$LOAD_BALANCER_ID" \
      --query 'data."lifecycle-state"' --raw-output)"
    case "$state" in
      ACTIVE)
        return 0
        ;;
      FAILED)
        echo "Il provisioning del Load Balancer è fallito." >&2
        exit 1
        ;;
    esac
    sleep 15
    ((elapsed += 15))
  done

  echo "Timeout: Load Balancer ancora nello stato $state dopo ${WAIT_SECONDS}s." >&2
  exit 1
}

wait_for_load_balancer_id() {
  local elapsed=0
  local candidate_id=""

  while (( elapsed < WAIT_SECONDS )); do
    candidate_id="$(oci lb load-balancer list \
      --compartment-id "$COMPARTMENT_ID" \
      --display-name "$LOAD_BALANCER_NAME" \
      --query 'data[0].id' --raw-output)"
    if has_value "$candidate_id"; then
      LOAD_BALANCER_ID="$candidate_id"
      return 0
    fi
    sleep 15
    ((elapsed += 15))
  done

  echo "Timeout: impossibile trovare il Load Balancer $LOAD_BALANCER_NAME." >&2
  exit 1
}

wait_for_nsg_id() {
  local nsg_name="$1"
  local elapsed=0
  local candidate_id=""

  while (( elapsed < WAIT_SECONDS )); do
    candidate_id="$(oci network nsg list \
      --compartment-id "$COMPARTMENT_ID" \
      --vcn-id "$VCN_ID" \
      --display-name "$nsg_name" \
      --lifecycle-state AVAILABLE \
      --query 'data[0].id' --raw-output)"
    if has_value "$candidate_id"; then
      printf '%s\n' "$candidate_id"
      return 0
    fi
    sleep 15
    ((elapsed += 15))
  done

  echo "Timeout: impossibile trovare il NSG $nsg_name." >&2
  exit 1
}

ensure_nsg() {
  local nsg_name="$1"
  local nsg_id

  nsg_id="$(oci network nsg list \
    --compartment-id "$COMPARTMENT_ID" \
    --vcn-id "$VCN_ID" \
    --display-name "$nsg_name" \
    --lifecycle-state AVAILABLE \
    --query 'data[0].id' --raw-output)"
  if ! has_value "$nsg_id"; then
    echo "Creo il Network Security Group $nsg_name..." >&2
    oci network nsg create \
      --compartment-id "$COMPARTMENT_ID" \
      --vcn-id "$VCN_ID" \
      --display-name "$nsg_name" >/dev/null
    nsg_id="$(wait_for_nsg_id "$nsg_name")"
  fi
  printf '%s\n' "$nsg_id"
}

ensure_nsg_rule() {
  local nsg_id="$1"
  local description="$2"
  local rule_json="$3"
  local rule_id

  rule_id="$(oci network nsg rules list \
    --nsg-id "$nsg_id" \
    --query "data[?description=='$description'].id | [0]" --raw-output)"
  if ! has_value "$rule_id"; then
    oci network nsg rules add \
      --nsg-id "$nsg_id" \
      --security-rules "[$rule_json]" >/dev/null
  fi
}

append_nsg_id() {
  local current_ids="$1"
  local nsg_id="$2"

  jq -c --arg nsg_id "$nsg_id" \
    'if type != "array" then [] elif index($nsg_id) then . else . + [$nsg_id] end' \
    <<<"$current_ids"
}

existing_lb_id="$(oci lb load-balancer list \
  --compartment-id "$COMPARTMENT_ID" \
  --display-name "$LOAD_BALANCER_NAME" \
  --query 'data[0].id' --raw-output)"

if has_value "$existing_lb_id"; then
  LOAD_BALANCER_ID="$existing_lb_id"
  echo "Uso il Load Balancer esistente: $LOAD_BALANCER_ID"
  wait_for_active
else
  echo "Creo il Load Balancer pubblico $LOAD_BALANCER_NAME..."
  oci lb load-balancer create \
    --compartment-id "$COMPARTMENT_ID" \
    --display-name "$LOAD_BALANCER_NAME" \
    --shape-name flexible \
    --shape-details '{"minimumBandwidthInMbps":10,"maximumBandwidthInMbps":10}' \
    --subnet-ids "[\"$SUBNET_ID\"]" \
    --is-private false >/dev/null
  wait_for_load_balancer_id
  wait_for_active
fi

VCN_ID="$(oci network subnet get \
  --subnet-id "$SUBNET_ID" \
  --query 'data."vcn-id"' --raw-output)"
if ! has_value "$VCN_ID"; then
  echo "Impossibile determinare il VCN della subnet." >&2
  exit 1
fi

LB_NSG_ID="$(ensure_nsg "$LB_NSG_NAME")"
BACKEND_NSG_ID="$(ensure_nsg "$BACKEND_NSG_NAME")"

# The LB NSG only exposes its public listeners and can only initiate traffic
# to the configured private backend. The backend NSG accepts that traffic only
# when it originates from the LB NSG.
ensure_nsg_rule "$LB_NSG_ID" "oci-acme-test-public-http" \
  '{"description":"oci-acme-test-public-http","direction":"INGRESS","protocol":"6","source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","tcpOptions":{"destinationPortRange":{"min":80,"max":80}}}'
ensure_nsg_rule "$LB_NSG_ID" "oci-acme-test-public-https" \
  '{"description":"oci-acme-test-public-https","direction":"INGRESS","protocol":"6","source":"0.0.0.0/0","sourceType":"CIDR_BLOCK","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}}'
ensure_nsg_rule "$LB_NSG_ID" "oci-acme-test-lb-to-backend" \
  "{\"description\":\"oci-acme-test-lb-to-backend\",\"direction\":\"EGRESS\",\"protocol\":\"6\",\"destination\":\"${BACKEND_IP}/32\",\"destinationType\":\"CIDR_BLOCK\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":${BACKEND_PORT},\"max\":${BACKEND_PORT}}}}"
ensure_nsg_rule "$BACKEND_NSG_ID" "oci-acme-test-backend-from-lb" \
  "{\"description\":\"oci-acme-test-backend-from-lb\",\"direction\":\"INGRESS\",\"protocol\":\"6\",\"source\":\"${LB_NSG_ID}\",\"sourceType\":\"NETWORK_SECURITY_GROUP\",\"tcpOptions\":{\"destinationPortRange\":{\"min\":${BACKEND_PORT},\"max\":${BACKEND_PORT}}}}"

lb_nsg_ids="$(oci lb load-balancer get \
  --load-balancer-id "$LOAD_BALANCER_ID" \
  --query 'data."network-security-group-ids"' --output json)"
updated_lb_nsg_ids="$(append_nsg_id "$lb_nsg_ids" "$LB_NSG_ID")"
if ! jq -e --arg nsg_id "$LB_NSG_ID" 'index($nsg_id) != null' <<<"$lb_nsg_ids" >/dev/null; then
  echo "Associo il NSG del Load Balancer..."
  oci lb nsg update \
    --load-balancer-id "$LOAD_BALANCER_ID" \
    --nsg-ids "$updated_lb_nsg_ids" \
    --force \
    --wait-for-state SUCCEEDED \
    --max-wait-seconds "$WAIT_SECONDS" >/dev/null
fi

backend_vnic_id="$(oci network private-ip list \
  --subnet-id "$BACKEND_SUBNET_ID" \
  --ip-address "$BACKEND_IP" \
  --query 'data[0]."vnic-id"' --raw-output)"
if ! has_value "$backend_vnic_id"; then
  echo "Impossibile trovare la VNIC associata a $BACKEND_IP in BACKEND_SUBNET_ID." >&2
  echo "LB e backend devono essere nella stessa VCN e nella stessa regione OCI." >&2
  exit 1
fi
BACKEND_VCN_ID="$(oci network subnet get \
  --subnet-id "$BACKEND_SUBNET_ID" \
  --query 'data."vcn-id"' --raw-output)"
if [[ "$BACKEND_VCN_ID" != "$VCN_ID" ]]; then
  echo "La VNIC del backend non appartiene al VCN del Load Balancer." >&2
  echo "LB e backend devono essere nella stessa VCN e nella stessa regione OCI." >&2
  exit 1
fi
backend_vnic_nsg_ids="$(oci network vnic get \
  --vnic-id "$backend_vnic_id" \
  --query 'data."nsg-ids"' --output json)"
updated_backend_vnic_nsg_ids="$(append_nsg_id "$backend_vnic_nsg_ids" "$BACKEND_NSG_ID")"
if ! jq -e --arg nsg_id "$BACKEND_NSG_ID" 'index($nsg_id) != null' <<<"$backend_vnic_nsg_ids" >/dev/null; then
  echo "Associo il NSG del backend alla sua VNIC..."
  oci network vnic update \
    --vnic-id "$backend_vnic_id" \
    --nsg-ids "$updated_backend_vnic_nsg_ids" \
    --force >/dev/null
fi

backend_set="$(oci lb backend-set get \
  --load-balancer-id "$LOAD_BALANCER_ID" \
  --backend-set-name "$BACKEND_SET_NAME" \
  --query 'data.name' --raw-output 2>/dev/null || true)"
if ! has_value "$backend_set"; then
  echo "Creo il backend set $BACKEND_SET_NAME..."
  oci lb backend-set create \
    --load-balancer-id "$LOAD_BALANCER_ID" \
    --name "$BACKEND_SET_NAME" \
    --policy ROUND_ROBIN \
    --health-checker-protocol TCP \
    --health-checker-port "$BACKEND_PORT" \
    --health-checker-interval-in-ms 10000 \
    --health-checker-timeout-in-ms 3000 \
    --health-checker-retries 3 \
    --wait-for-state SUCCEEDED \
    --max-wait-seconds "$WAIT_SECONDS" >/dev/null
fi

backend_name="${BACKEND_IP}:${BACKEND_PORT}"
backend="$(oci lb backend get \
  --load-balancer-id "$LOAD_BALANCER_ID" \
  --backend-set-name "$BACKEND_SET_NAME" \
  --backend-name "$backend_name" \
  --query 'data.name' --raw-output 2>/dev/null || true)"
if ! has_value "$backend"; then
  echo "Aggiungo il backend $backend_name..."
  oci lb backend create \
    --load-balancer-id "$LOAD_BALANCER_ID" \
    --backend-set-name "$BACKEND_SET_NAME" \
    --ip-address "$BACKEND_IP" \
    --port "$BACKEND_PORT" \
    --weight 1 \
    --wait-for-state SUCCEEDED \
    --max-wait-seconds "$WAIT_SECONDS" >/dev/null
fi

listener="$(oci lb load-balancer get \
  --load-balancer-id "$LOAD_BALANCER_ID" \
  --query "data.listeners.\"$HTTP_LISTENER_NAME\".name" --raw-output)"
if ! has_value "$listener"; then
  echo "Creo il listener HTTP :80..."
  oci lb listener create \
    --load-balancer-id "$LOAD_BALANCER_ID" \
    --name "$HTTP_LISTENER_NAME" \
    --default-backend-set-name "$BACKEND_SET_NAME" \
    --port 80 \
    --protocol HTTP \
    --wait-for-state SUCCEEDED \
    --max-wait-seconds "$WAIT_SECONDS" >/dev/null
fi

if [[ -n "$CERTIFICATE_ID" ]]; then
  listener="$(oci lb load-balancer get \
    --load-balancer-id "$LOAD_BALANCER_ID" \
    --query "data.listeners.\"$HTTPS_LISTENER_NAME\".name" --raw-output)"
  if ! has_value "$listener"; then
    echo "Creo il listener HTTPS :443..."
    oci lb listener create \
      --load-balancer-id "$LOAD_BALANCER_ID" \
      --name "$HTTPS_LISTENER_NAME" \
      --default-backend-set-name "$BACKEND_SET_NAME" \
      --port 443 \
      --protocol HTTPS \
      --ssl-certificate-ids "[\"$CERTIFICATE_ID\"]" \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds "$WAIT_SECONDS" >/dev/null
  fi
fi

public_ip="$(oci lb load-balancer get \
  --load-balancer-id "$LOAD_BALANCER_ID" \
  --query 'data."ip-addresses"[0]."ip-address"' --raw-output)"

cat <<EOF

Load Balancer pronto.
  OCID:      $LOAD_BALANCER_ID
  IP pubblico: $public_ip
  HTTP:      http://$public_ip/.well-known/acme-challenge/<token>
  Backend:   $backend_name
  NSG LB:    $LB_NSG_ID
  NSG backend: $BACKEND_NSG_ID

I NSG sono configurati per Internet -> LB TCP/80 e LB -> $backend_name.
Per TLS, riesegui impostando CERTIFICATE_ID.
EOF
