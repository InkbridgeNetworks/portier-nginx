-- Stand-in for the portier broker: discovery document, RS256 key set, and an
-- id_token mint that also produces the wrong-algorithm variants the verify
-- phase must refuse. The RSA key comes from test/fixtures/broker-rsa.pem.

local jwt = require "resty.jwt"
local pkey = require "resty.openssl.pkey"
local cjson = require "cjson.safe"

local _M = {}

local BASE = "http://127.0.0.1:18081"
local KID = "broker-test-key"

local key_pem
do
    local f = assert(io.open("/work/test/fixtures/broker-rsa.pem", "r"))
    key_pem = f:read("*a")
    f:close()
end
local pk = assert(pkey.new(key_pem))
local pub_pem = assert(pk:to_PEM("public"))
local jwk = assert(cjson.decode(assert(pk:tostring("public", "JWK"))))
jwk.kid = KID
jwk.use = "sig"
jwk.alg = "RS256"

function _M.openid_configuration()
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
        issuer = BASE,
        authorization_endpoint = BASE .. "/auth",
        jwks_uri = BASE .. "/keys.json",
    }))
end

function _M.keys()
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ keys = { jwk } }))
end

function _M.id_token()
    local args = ngx.req.get_uri_args()
    local alg = args.alg or "RS256"
    local now = ngx.time()
    local payload = {
        iss = args.iss or BASE,
        aud = args.aud or "http://127.0.0.1:18082",
        sub = args.sub,
        nonce = args.nonce,
        iat = now,
        exp = now + 600,
    }
    -- HS256 with the public PEM as the shared secret is the alg-confusion
    -- shape a verifier must refuse.
    local secret = alg == "RS256" and key_pem or pub_pem
    ngx.say(jwt:sign(secret, { header = { typ = "JWT", alg = alg, kid = args.kid or KID }, payload = payload }))
end

return _M
