#!/usr/bin/env bash
###############################################################################
# Generate TLS certificates for Wazuh stack
# Creates self-signed CA + certs for indexer, manager, dashboard, and NGINX.
# For production, replace with certs from your internal CA.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="$PROJECT_ROOT/docker/wazuh/certs"
NGINX_CERT_DIR="$PROJECT_ROOT/docker/nginx/ssl"
DAYS=365
KEY_SIZE=2048

log() { echo "[certs] $*"; }

mkdir -p "$CERT_DIR" "$NGINX_CERT_DIR"

# ─── Root CA ─────────────────────────────────────────────────────────────────
if [[ ! -f "$CERT_DIR/root-ca.pem" ]]; then
    log "Generating Root CA..."
    openssl req -x509 -new -nodes \
        -newkey rsa:$KEY_SIZE \
        -keyout "$CERT_DIR/root-ca-key.pem" \
        -out "$CERT_DIR/root-ca.pem" \
        -days $DAYS \
        -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=Wazuh Root CA"
else
    log "Root CA already exists, skipping..."
fi

# ─── Helper function ────────────────────────────────────────────────────────
generate_cert() {
    local name="$1"
    local cn="$2"
    local san="${3:-}"
    local output_dir="${4:-$CERT_DIR}"

    if [[ -f "$output_dir/$name.pem" ]]; then
        log "$name cert already exists, skipping..."
        return
    fi

    log "Generating $name certificate (CN=$cn)..."

    # Create CSR config with SAN
    local conf
    conf=$(mktemp)
    cat > "$conf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
L = California
O = Wazuh
OU = Wazuh
CN = $cn

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $cn
DNS.2 = localhost
IP.1 = 127.0.0.1
${san}
EOF

    openssl req -new -nodes \
        -newkey rsa:$KEY_SIZE \
        -keyout "$output_dir/$name-key.pem" \
        -out "$output_dir/$name.csr" \
        -config "$conf"

    openssl x509 -req \
        -in "$output_dir/$name.csr" \
        -CA "$CERT_DIR/root-ca.pem" \
        -CAkey "$CERT_DIR/root-ca-key.pem" \
        -CAcreateserial \
        -out "$output_dir/$name.pem" \
        -days $DAYS \
        -extfile "$conf" \
        -extensions v3_req

    rm -f "$output_dir/$name.csr" "$conf"
}

# ─── Generate component certificates ────────────────────────────────────────
generate_cert "indexer" "indexer" "DNS.3 = wazuh-indexer"
generate_cert "filebeat" "filebeat" "DNS.3 = wazuh-manager"
generate_cert "dashboard" "dashboard" "DNS.3 = wazuh-dashboard"
generate_cert "admin" "admin" ""
generate_cert "nginx" "wazuh.example.com" "DNS.3 = wazuh-api.example.com" "$NGINX_CERT_DIR"

# Copy root CA to NGINX dir
cp "$CERT_DIR/root-ca.pem" "$NGINX_CERT_DIR/"

log "All certificates generated successfully."
log "Certificate directory: $CERT_DIR"
log ""
log "WARNING: These are self-signed certificates for development/lab use."
log "For production, use certificates from your organization's CA."
