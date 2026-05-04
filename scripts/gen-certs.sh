#!/usr/bin/env bash
# gen-certs.sh - generates self-signed TLS certificates for local development.
# Output: certs/gateway.{crt,key}, certs/ca.{crt,key}
set -euo pipefail

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

echo "Generating CA key and certificate..."
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=mcpids-dev-ca/O=MCPIDS Dev/C=US"

echo "Generating gateway key and CSR..."
openssl genrsa -out "${CERT_DIR}/gateway.key" 2048
openssl req -new -key "${CERT_DIR}/gateway.key" \
    -out "${CERT_DIR}/gateway.csr" \
    -subj "/CN=localhost/O=MCPIDS/C=US"

echo "Signing gateway certificate with CA..."
openssl x509 -req -days 365 \
    -in "${CERT_DIR}/gateway.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/gateway.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n")

chmod 600 "${CERT_DIR}"/*.key
echo "Certificates generated in ${CERT_DIR}/"
echo "  CA:      ${CERT_DIR}/ca.crt"
echo "  Gateway: ${CERT_DIR}/gateway.crt + gateway.key"
