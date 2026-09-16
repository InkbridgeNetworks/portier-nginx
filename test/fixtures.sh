#!/bin/sh
# Generates the test keys once: the ES256 signing key the identity provider
# under test uses, and the RSA key the broker stub signs id_tokens with.
set -eu
cd "$(dirname "$0")/.."
mkdir -p test/fixtures
if [ ! -f test/fixtures/es256-key.pem ]; then
	openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out test/fixtures/es256-key.pem
fi
if [ ! -f test/fixtures/broker-rsa.pem ]; then
	openssl genrsa -out test/fixtures/broker-rsa.pem 2048 2>/dev/null
fi
