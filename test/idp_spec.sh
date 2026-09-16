#!/bin/sh
# Drives the identity provider vhost in test/nginx.conf with curl, then feeds
# the session cookie it mints to the service provider vhost. Runs inside the
# OpenResty container; test/run.sh starts it.
set -u
IDP=http://127.0.0.1:18082
BROKER=http://127.0.0.1:18081
SP=http://127.0.0.1:18080
fail=0
check() {
	if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$3] got [$2]"; fail=$((fail + 1)); fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# Every login start below claims to come from the login page itself.
SFS="Sec-Fetch-Site: same-origin"
header() { curl -s -D - -o /dev/null "$@" | grep -i "^$1:" | sed "s/^[^:]*: //" | tr -d '\r'; }
# login <email> [return_to] -> prints the portier_login cookie value
login() {
	url="$IDP/.portier/login?email=$1"
	[ $# -gt 1 ] && url="$url&return_to=$(printf %s "$2" | sed 's/:/%3A/g; s#/#%2F#g')"
	curl -s -D - -o /dev/null -H "$SFS" "$url" | grep -i '^Set-Cookie: portier_login=' | sed 's/^[^=]*=//; s/;.*//' | tr -d '\r'
}
nonce_of() { echo "$1" | cut -d'|' -f1; }
# verify <email> <login-cookie> [alg] [nonce] -> prints the response headers
verify() {
	nonce=${4:-$(nonce_of "$2")}
	idt=$(curl -s "$BROKER/id_token?sub=$1&nonce=$nonce&alg=${3:-RS256}")
	curl -s -D - -o /dev/null -X POST -H "Cookie: portier_login=$2" --data-urlencode "id_token=$idt" "$IDP/.portier/verify"
}
session_of() { grep -i '^Set-Cookie: portier_session=' | grep -v 'portier_session=;' | sed 's/^[^=]*=//; s/;.*//' | tr -d '\r'; }
payload_of() { echo "$1" | cut -d. -f2 | tr '_-' '/+' | awk '{ l = length($0) % 4; if (l) $0 = $0 substr("===", 1, 4 - l); print }' | base64 -d 2>/dev/null; }

# Login.
check "login page served" "$(status $IDP/.portier/login)" 200
check "bad address -> back to login with error" "$(header Location -H "$SFS" "$IDP/.portier/login?email=not-an-address" | cut -d'#' -f1)" "http://127.0.0.1:18082/.portier/login"
loc=$(header Location -H "$SFS" "$IDP/.portier/login?email=supported@example.org")
check "good address -> broker auth endpoint" "$(echo "$loc" | cut -d'?' -f1)" "$BROKER/auth"
query=$(echo "$loc" | cut -d'?' -f2 | tr '&' '\n')
check "broker request names us as client" "$(echo "$query" | grep -c '^client_id=http%3A%2F%2F127.0.0.1%3A18082$')" 1
check "broker request uses form_post id_token" "$(echo "$query" | grep -c -E '^(response_mode=form_post|response_type=id_token)$')" 2
lc=$(login supported@example.org)
check "login cookie carries nonce and return" "$(echo "$lc" | grep -c '^[0-9a-f]\{32\}|')" 1
check "login cookie attributes" "$(curl -s -D - -o /dev/null -H "$SFS" "$IDP/.portier/login?email=supported@example.org" | grep -i '^Set-Cookie: portier_login' | grep -c 'Path=/.portier; HttpOnly; Secure; SameSite=None; Max-Age=600')" 1

# Login start origin gate.
check "cross-site login start -> 403" "$(status -H "Sec-Fetch-Site: cross-site" "$IDP/.portier/login?email=supported@example.org")" 403
check "login start with no origin evidence -> 403" "$(status "$IDP/.portier/login?email=supported@example.org")" 403
check "same-site login start (RT's form) -> 302" "$(status -H "Sec-Fetch-Site: same-site" "$IDP/.portier/login?email=supported@example.org")" 302
check "old browser with audience Referer -> 302" "$(status -H "Referer: https://rt.example.org/" "$IDP/.portier/login?email=supported@example.org")" 302
check "old browser with foreign Referer -> 403" "$(status -H "Referer: https://evil.example.com/" "$IDP/.portier/login?email=supported@example.org")" 403
check "repeated email arg -> 400" "$(status -H "$SFS" "$IDP/.portier/login?email=a@example.org&email=b@example.org")" 400
check "bare email arg -> 400" "$(status -H "$SFS" "$IDP/.portier/login?email")" 400

# Verify: happy path.
hdrs=$(verify supported@example.org "$lc")
check "verify -> redirect to landing" "$(echo "$hdrs" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/"
sess=$(echo "$hdrs" | session_of)
check "verify sets session cookie" "$([ -n "$sess" ] && echo yes)" yes
check "session cookie attributes" "$(echo "$hdrs" | grep -i '^Set-Cookie: portier_session=' | grep -c 'Domain=example.org; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=60')" 1
check "verify clears login cookie" "$(echo "$hdrs" | grep -c -i '^Set-Cookie: portier_login=;')" 1
pl=$(payload_of "$sess")
check "token iss is the IdP origin" "$(echo "$pl" | grep -o '"iss":"[^"]*"' | sed 's#\\/#/#g')" '"iss":"http://127.0.0.1:18082"'
check "token carries uid" "$(echo "$pl" | grep -o '"uid":"[^"]*"')" '"uid":"supported"'
check "token carries supported grant" "$(echo "$pl" | grep -c '"grants":\["supported"\]')" 1
check "token carries tier" "$(echo "$pl" | grep -o '"support_tier":"[^"]*"')" '"support_tier":"Gold"'

# Verify: refusals.
check "wrong nonce -> back to login" "$(verify supported@example.org "$(login supported@example.org)" RS256 deadbeef | grep -i '^Location:' | grep -c '/.portier/login#')" 1
check "wrong nonce -> no session" "$(verify supported@example.org "$(login supported@example.org)" RS256 deadbeef | session_of)" ""
check "HS256 id_token -> no session" "$(verify supported@example.org "$(login supported@example.org)" HS256 | session_of)" ""
check "no login cookie -> back to login" "$(curl -s -D - -o /dev/null -X POST --data-urlencode "id_token=x.y.z" "$IDP/.portier/verify" | grep -i '^Location:' | grep -c 'login%20expired')" 1
check "unknown address -> no account error" "$(verify unknown@example.org "$(login unknown@example.org)" | grep -i '^Location:' | grep -c 'no%20account')" 1
check "directory failure -> 502" "$(verify broken@example.org "$(login broken@example.org)" | head -1 | grep -o '[0-9]\{3\}')" 502

# Entitlements are asserted, not enforced, by the IdP.
lapsed=$(verify lapsed@example.org "$(login lapsed@example.org)" | session_of)
check "lapsed org still gets a token" "$([ -n "$lapsed" ] && echo yes)" yes
check "lapsed org token has no supported grant" "$(payload_of "$lapsed" | grep -c '"grants":{}')" 1
staff=$(verify staff@example.org "$(login staff@example.org)" | session_of)
check "employee token names the group" "$(payload_of "$staff" | grep -c 'cn=employees,ou=groups,dc=example,dc=org')" 1

# return_to handling.
check "allowed return_to honoured" "$(verify supported@example.org "$(login supported@example.org https://rt.example.org/Ticket/1)" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/Ticket/1"
check "foreign return_to falls back to landing" "$(verify supported@example.org "$(login supported@example.org https://evil.example.com/)" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/"
check "backslash authority return_to falls back to landing" "$(verify supported@example.org "$(login supported@example.org 'https://evil.example%5Cx.example.org/')" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/"
check "userinfo return_to falls back to landing" "$(verify supported@example.org "$(login supported@example.org 'https://rt.example.org@evil.example.com/')" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/"
check "suffix-only host return_to falls back to landing" "$(verify supported@example.org "$(login supported@example.org 'https://rt.example.org.evil.example.com/')" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://rt.example.org/"
check "upper-case audience host is honoured" "$(verify supported@example.org "$(login supported@example.org 'https://RT.example.org/x')" | grep -i '^Location:' | sed 's/^[^:]*: //' | tr -d '\r')" "https://RT.example.org/x"
check "logout with backslash return_to -> landing" "$(header Location "$IDP/.portier/logout?return_to=https://evil.example%5Cx.example.org/")" "https://rt.example.org/"
check "logout with audience return_to -> honoured" "$(header Location "$IDP/.portier/logout?return_to=https://rt.example.org/bye")" "https://rt.example.org/bye"

# JWKS and logout.
kid=$(payload_of "$sess" >/dev/null; echo "$sess" | cut -d. -f1 | tr '_-' '/+' | awk '{ l = length($0) % 4; if (l) $0 = $0 substr("===", 1, 4 - l); print }' | base64 -d 2>/dev/null | grep -o '"kid":"[^"]*"')
check "jwks names the signing kid" "$(curl -s $IDP/.portier/jwks.json | grep -o '"kid":"[^"]*"')" "$kid"
check "jwks is cacheable" "$(header Cache-Control $IDP/.portier/jwks.json)" "public, max-age=600"
check "logout clears session on the domain" "$(curl -s -D - -o /dev/null $IDP/.portier/logout | grep -i '^Set-Cookie' | grep -c 'portier_session=; Domain=example.org')" 1
check "logout redirects to landing" "$(header Location $IDP/.portier/logout)" "https://rt.example.org/"

# The round trip: the IdP's cookie is accepted by the SP.
check "SP accepts IdP session" "$(status -H "Cookie: portier_session=$sess" $SP/protected)" 200
check "SP sees the uid" "$(curl -s -H "Cookie: portier_session=$sess" $SP/protected | grep '^uid=')" "uid=supported"
check "SP refuses lapsed org with 403" "$(status -H "Cookie: portier_session=$lapsed" $SP/protected)" 403
check "SP refuses employee with 403" "$(status -H "Cookie: portier_session=$staff" $SP/protected)" 403

[ $fail -eq 0 ] && echo "ALL OK" || echo "$fail FAILED"
exit $fail
