-- Exercises portier.token under OpenResty: mint, verify, and the refusals a
-- service provider must produce. Run through test/run.sh.

package.path = "/work/src/?.lua;/work/test/?.lua;" .. package.path

local token = require "portier.token"
local jwt = require "resty.jwt"
local cjson = require "cjson.safe"

local failures = 0

local function check(name, ok, detail)
    if ok then
        print("ok   " .. name)
    else
        failures = failures + 1
        print("FAIL " .. name .. (detail and (": " .. tostring(detail)) or ""))
    end
end

-- 1. Key load: kid derived, JWK is an EC P-256 public key with no private part.
local key, err = token.key_load()
check("key_load", key ~= nil, err)
check("kid derived, 16 hex chars", key and key.kid:match("^%x+$") and #key.kid == 16, key and key.kid)
check("jwk is EC P-256", key and key.jwk.kty == "EC" and key.jwk.crv == "P-256", key and cjson.encode(key.jwk))
check("jwk carries no private scalar", key and key.jwk.d == nil)
check("jwk kid/use/alg set", key and key.jwk.kid == key.kid and key.jwk.use == "sig" and key.jwk.alg == "ES256")

-- The service provider resolves the kid to the public PEM out of the JWK.
local pkey = require "resty.openssl.pkey"
local pub_pem
do
    local pk = pkey.new(cjson.encode(key.jwk), { format = "JWK" })
    pub_pem = pk:to_PEM("public")
end
local function key_by_kid(kid)
    if kid == key.kid then
        return pub_pem
    end
    return nil, "unknown"
end
local spec = token.claim_spec()

-- 2. Mint a token and verify it.
local claims = {
    sub = "user@example.org",
    uid = "user",
    groups = { "cn=customers,ou=groups,dc=example,dc=org" },
    grants = { "supported" },
    support_tier = "Gold",
}
local tok
tok, err = token.mint(claims, key, "http://127.0.0.1:18082")
check("mint", tok ~= nil, err)
check("token has three parts", tok and select(2, tok:gsub("%.", "")) == 2)

local payload
payload, err = token.verify(tok, key_by_kid, spec)
check("verify good token", payload ~= nil, err)
check("uid claim round trips", payload and payload.uid == "user")
check("grants claim round trips", payload and payload.grants[1] == "supported")
check("aud is a list", payload and type(payload.aud) == "table" and #payload.aud == 2)
check("exp = iat + lifetime", payload and payload.exp - payload.iat == 60)

-- 3. Refusals.
-- 3a. Tampered payload: flip the uid inside the token body.
do
    local h, p, s = tok:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    local body = jwt:jwt_decode(p, true)
    body.uid = "root"
    local tampered = h .. "." .. jwt:jwt_encode(cjson.encode(body)) .. "." .. s
    local got, why = token.verify(tampered, key_by_kid, spec)
    check("tampered payload refused", got == nil, why)
end

-- 3b. Algorithm confusion: HS256 token signed with the public PEM as the
-- shared secret, same kid. Must be refused before any key lookup.
do
    local hs = jwt:sign(pub_pem, {
        header = { typ = "JWT", alg = "HS256", kid = key.kid },
        payload = claims,
    })
    local looked_up = false
    local function spy(kid)
        looked_up = true
        return key_by_kid(kid)
    end
    local got, why = token.verify(hs, spy, spec)
    check("HS256 refused", got == nil and why:find("unsupported alg"), why)
    check("HS256 refused before key lookup", looked_up == false)
end

-- 3c. Wrong audience for this service provider.
do
    local other = token.claim_spec()
    other.aud = require("resty.jwt-validators").required(
        require("resty.jwt-validators").contains_any_of({ "https://other.example.org" }))
    local got, why = token.verify(tok, key_by_kid, other)
    check("wrong aud refused", got == nil, why)
end

-- 3d. Wrong issuer.
do
    local other = token.claim_spec()
    other.iss = require("resty.jwt-validators").required(
        require("resty.jwt-validators").equals("https://evil.example.org"))
    local got, why = token.verify(tok, key_by_kid, other)
    check("wrong iss refused", got == nil, why)
end

-- 3e. Expired: mint with the clock wound back, via the validators' clock.
do
    local validators = require "resty.jwt-validators"
    validators.set_system_clock(function() return ngx.time() + 3600 end)
    local got, why = token.verify(tok, key_by_kid, token.claim_spec())
    check("expired refused", got == nil and why:find("expired"), why)
    validators.set_system_clock(ngx.time)
end

-- 3f. Unknown kid.
do
    local got, why = token.verify(tok, function() return nil, "not in JWKS" end, spec)
    check("unknown kid refused", got == nil and why:find("no key for kid"), why)
end

-- 3g. Garbage.
do
    local got, why = token.verify("not.a.jwt", key_by_kid, spec)
    check("garbage refused", got == nil, why)
end

print(failures == 0 and "ALL OK" or (failures .. " FAILED"))
os.exit(failures == 0 and 0 or 1)
