#!/bin/sh
# Drives the test vhost in test/sp/nginx.conf with curl. Runs inside the
# OpenResty container; test/run.sh starts it.
set -u
BASE=http://127.0.0.1:18080
fail=0
check() {
	if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$3] got [$2]"; fail=$((fail + 1)); fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

good=$(curl -s "$BASE/mint?grants=supported&groups=cn=customers,ou=groups,dc=example,dc=org")
unsupported=$(curl -s "$BASE/mint?grants=&groups=cn=customers,ou=groups,dc=example,dc=org")
employee=$(curl -s "$BASE/mint?grants=supported&groups=cn=employees,ou=groups,dc=example,dc=org")
wrong_iss=$(curl -s "$BASE/mint?grants=supported&iss=https://evil.example.org")

check "no cookie -> 401" "$(status $BASE/protected)" 401

body=$(curl -s -H "Cookie: portier_session=$good" $BASE/protected)
check "good token -> 200" "$(status -H "Cookie: portier_session=$good" $BASE/protected)" 200
check "good token sets uid" "$(echo "$body" | grep '^uid=')" "uid=user"
check "good token sets email" "$(echo "$body" | grep '^email=')" "email=user@example.org"
check "cookie stripped before upstream" "$(echo "$body" | grep '^cookie=')" "cookie="

body=$(curl -s -H "Cookie: RT_SID=abc; portier_session=$good; theme=dark" $BASE/protected)
check "only our cookie is stripped" "$(echo "$body" | grep '^cookie=')" "cookie=RT_SID=abc; theme=dark"

check "unsupported org -> 403" "$(status -H "Cookie: portier_session=$unsupported" $BASE/protected)" 403
check "unsupported org -> renewal message" "$(curl -s -H "Cookie: portier_session=$unsupported" $BASE/protected)" \
	"Your support contract has been suspended. Please contact acct@example.org for renewal."

check "employee -> 403" "$(status -H "Cookie: portier_session=$employee" $BASE/protected)" 403
check "employee -> staff message" "$(curl -s -H "Cookie: portier_session=$employee" $BASE/protected)" "Staff log in to RT directly."

check "wrong iss -> 401" "$(status -H "Cookie: portier_session=$wrong_iss" $BASE/protected)" 401

tampered="$(echo "$good" | cut -d. -f1).$(echo '{"uid":"root","sub":"x","exp":9999999999,"iat":1,"iss":"https://idp.example.org","aud":["https://rt.example.org"]}' | base64 -w0 | tr '+/' '-_' | tr -d '=').$(echo "$good" | cut -d. -f3)"
check "tampered -> 401" "$(status -H "Cookie: portier_session=$tampered" $BASE/protected)" 401
check "tampered -> cookie cleared" "$(curl -s -D - -o /dev/null -H "Cookie: portier_session=$tampered" $BASE/protected | grep -c 'Set-Cookie: portier_session=;')" 1

check "garbage -> 401" "$(status -H "Cookie: portier_session=nope" $BASE/protected)" 401

body=$(curl -s -H "Cookie: Portier_Session=$good; theme=dark" $BASE/protected)
check "mixed-case cookie name is verified" "$(echo "$body" | grep '^uid=')" "uid=user"
check "mixed-case cookie name is stripped" "$(echo "$body" | grep '^cookie=')" "cookie=theme=dark"

unknown_kid="$(printf '{"typ":"JWT","alg":"ES256","kid":"nope"}' | base64 -w0 | tr '+/' '-_' | tr -d '=').$(echo "$good" | cut -d. -f2).$(echo "$good" | cut -d. -f3)"
check "unknown kid -> 401" "$(status -H "Cookie: portier_session=$unknown_kid" $BASE/protected)" 401
check "unknown kid again -> 401 (negative cache)" "$(status -H "Cookie: portier_session=$unknown_kid" $BASE/protected)" 401
check "tampered -> cookie cleared on the domain" "$(curl -s -D - -o /dev/null -H "Cookie: portier_session=$tampered" $BASE/protected | grep -c 'Set-Cookie: portier_session=; Domain=example.org')" 1

[ $fail -eq 0 ] && echo "ALL OK" || echo "$fail FAILED"
exit $fail
