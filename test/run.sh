#!/bin/sh
# Runs the specs under OpenResty in a container. Generates the ES256 test key
# and its JWKS on first run. Needs docker.
set -eu
cd "$(dirname "$0")/.."
mkdir -p test/fixtures
if [ ! -f test/fixtures/es256-key.pem ]; then
	openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out test/fixtures/es256-key.pem
fi
if [ ! -f test/fixtures/broker-rsa.pem ]; then
	openssl genrsa -out test/fixtures/broker-rsa.pem 2048 2>/dev/null
fi
docker run --rm -v "$PWD:/work" -w /work openresty/openresty:bookworm-fat sh -c '
	set -e
	luarocks install lua-resty-jwt >/dev/null 2>&1
	luarocks install lua-resty-openssl >/dev/null 2>&1
	luarocks install lua-resty-http >/dev/null 2>&1
	echo "== token_spec"
	resty -I /work/src -I /work/test test/token_spec.lua
	echo "== jwks fixture"
	resty -I /work/src -I /work/test -e "
		local cjson = require \"cjson\"
		local key = assert(require(\"portier.token\").key_load())
		local f = assert(io.open(\"/work/test/fixtures/jwks.json\", \"w\"))
		f:write(cjson.encode({ keys = { key.jwk } }))
		f:close()
		print(\"kid \" .. key.kid)
	"
	echo "== nginx"
	mkdir -p /tmp/nginx-body /var/cache/nginx/portier /etc/portier/webroot
	cp /work/webroot/index.html /etc/portier/webroot/
	/usr/local/openresty/nginx/sbin/nginx -c /work/test/nginx.conf
	echo "== sp_spec"
	sh test/sp_spec.sh; rc1=$?
	echo "== idp_spec"
	sh test/idp_spec.sh; rc2=$?
	/usr/local/openresty/nginx/sbin/nginx -c /work/test/nginx.conf -s quit
	[ $rc1 -eq 0 ] && [ $rc2 -eq 0 ]
'
