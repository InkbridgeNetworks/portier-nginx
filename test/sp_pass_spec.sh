#!/bin/sh
# The service provider in "pass" mode: a request without a usable token
# reaches the application anonymously, a denied group is treated the same
# way, and a missing grant is still refused.
set -u
MINT=http://127.0.0.1:18080
BASE=http://127.0.0.1:18090
fail=0
check() {
	if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$3] got [$2]"; fail=$((fail + 1)); fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

good=$(curl -s "$MINT/mint?grants=supported&groups=cn=customers,ou=groups,dc=example,dc=org")
lapsed=$(curl -s "$MINT/mint?grants=&groups=cn=customers,ou=groups,dc=example,dc=org")
employee=$(curl -s "$MINT/mint?grants=supported&groups=cn=employees,ou=groups,dc=example,dc=org")

check "pass: no cookie -> 200 anonymous" "$(curl -s $BASE/protected | grep '^uid=')" "uid="
check "pass: good token -> uid set" "$(curl -s -H "Cookie: portier_session=$good" $BASE/protected | grep '^uid=')" "uid=user"
check "pass: garbage token -> 200 anonymous" "$(curl -s -H "Cookie: portier_session=nope" $BASE/protected | grep '^uid=')" "uid="
check "pass: garbage token -> cookie cleared on the domain" "$(curl -s -D - -o /dev/null -H "Cookie: portier_session=nope" $BASE/protected | grep -c 'Set-Cookie: portier_session=; Domain=example.org')" 1
check "pass: denied group -> 200 anonymous, not 403" "$(status -H "Cookie: portier_session=$employee" $BASE/protected)" 200
check "pass: denied group -> no uid" "$(curl -s -H "Cookie: portier_session=$employee" $BASE/protected | grep '^uid=')" "uid="
check "pass: denied group -> cookie cleared" "$(curl -s -D - -o /dev/null -H "Cookie: portier_session=$employee" $BASE/protected | grep -c 'Set-Cookie: portier_session=; Domain=example.org')" 1
check "pass: denied group -> token not passed upstream" "$(curl -s -H "Cookie: portier_session=$employee" $BASE/protected | grep '^cookie=')" "cookie="
check "pass: missing grant -> 403 still" "$(status -H "Cookie: portier_session=$lapsed" $BASE/protected)" 403

[ $fail -eq 0 ] && echo "ALL OK" || echo "$fail FAILED"
exit $fail
