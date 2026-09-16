-- The portier session token
--
-- One module, two sides. The identity provider calls `key_load` at init and
-- `mint` after the directory lookup. A service provider calls `claim_spec`
-- at init and `verify` on every request. Both sides share the token shape,
-- so the shape lives in one place:
--
--   header:  { typ = "JWT", alg = "ES256", kid = <key id> }
--   payload: { iss, aud = { <audience>, ... }, iat, exp, sub = <email>,
--              uid, groups = { <dn>, ... }, grants = { <grant>, ... },
--              support_tier }
--
-- `aud` is always a list, even for one audience, so a service provider
-- checks membership and never has to handle both a string and a list.
--
-- Signing and verification go through lua-resty-jwt. The algorithm is pinned
-- to ES256 with an explicit check on the token header rather than through
-- `jwt:set_alg_whitelist`, because the whitelist is state on the shared
-- `resty.jwt` module and the identity provider also verifies the broker's
-- RS256 id_token in the same worker.

local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"
local pkey = require "resty.openssl.pkey"
local digest = require "resty.openssl.digest"
local cjson = require "cjson.safe"

local config = require "portier.config"

local _M = {}

--- The only signing algorithm a portier token may carry
local ALG = "ES256"

--- Hex characters of the public key digest that make up a derived kid
local KID_HEX_LENGTH = 16

--- Longest kid a token header may carry before verification refuses it
local KID_MAX_LENGTH = 128

--- Read a whole file
---
--- @param path string Path of the file
--- @return string|nil Contents, or nil on error
--- @return string|nil Error
local function _file_read(path)
    local f, err = io.open(path, "r")
    if not f then
        return nil, err
    end
    local data = f:read("*a")
    f:close()
    return data
end

--- Derive a key id from a public key
---
--- The kid is the first KID_HEX_LENGTH hex characters of the SHA-256 digest
--- of the public key in DER form, so the same key always gets the same kid
--- on every host without anyone having to pick one.
---
--- @param pk table lua-resty-openssl pkey holding at least the public half
--- @return string|nil Key id, or nil on error
--- @return string|nil Error
local function _kid_derive(pk)
    local der, err = pk:tostring("public", "DER")
    if not der then
        return nil, err
    end
    local d
    d, err = digest.new("sha256")
    if not d then
        return nil, err
    end
    local sum
    sum, err = d:final(der)
    if not sum then
        return nil, err
    end
    local hex = {}
    for i = 1, #sum do
        hex[i] = string.format("%02x", sum:byte(i))
    end
    return table.concat(hex):sub(1, KID_HEX_LENGTH)
end

--- Load the identity provider's signing key
---
--- Reads the PEM named by `idp.token.key_file`, derives the kid unless
--- `idp.token.kid` pins one, and builds the JWK the JWKS endpoint serves.
--- Call once from init_by_lua and keep the result for the worker's life.
---
--- @return table|nil { pem = <private PEM>, kid = <key id>, jwk = <public JWK> }
--- @return string|nil Error
function _M.key_load()
    local pem, err = _file_read(config.idp.token.key_file)
    if not pem then
        return nil, "cannot read signing key " .. config.idp.token.key_file .. ": " .. err
    end

    local pk
    pk, err = pkey.new(pem, { format = "PEM", type = "pr" })
    if not pk then
        return nil, "cannot load signing key: " .. err
    end

    local kid = config.idp.token.kid
    if not kid then
        kid, err = _kid_derive(pk)
        if not kid then
            return nil, "cannot derive kid: " .. err
        end
    end

    local jwk_json
    jwk_json, err = pk:tostring("public", "JWK")
    if not jwk_json then
        return nil, "cannot export public JWK: " .. err
    end
    local jwk
    jwk, err = cjson.decode(jwk_json)
    if not jwk then
        return nil, "cannot decode public JWK: " .. err
    end
    jwk.kid = kid
    jwk.use = "sig"
    jwk.alg = ALG

    return { pem = pem, kid = kid, jwk = jwk }
end

--- Mint a session token
---
--- Fills `iss`, `aud`, `iat` and `exp` from `idp.token` and the clock, then
--- signs `claims` with `key`. `claims` carries the identity fields from the
--- directory lookup: `sub`, `uid`, `groups`, `grants`, `support_tier`.
---
--- @param claims table Identity and entitlement claims, mutated in place
--- @param key table    Result of `key_load`
--- @param issuer string `iss` to write, the identity provider's origin
--- @return string|nil Signed token, or nil on error
--- @return string|nil Error
function _M.mint(claims, key, issuer)
    local now = ngx.time()
    claims.iss = issuer
    claims.aud = config.idp.token.audience
    claims.iat = now
    claims.exp = now + config.idp.token.lifetime

    local jwt_obj = {
        header = { typ = "JWT", alg = ALG, kid = key.kid },
        payload = claims,
    }

    -- jwt:sign raises a table { reason = ... } on failure.
    local ok, ret = pcall(jwt.sign, jwt, key.pem, jwt_obj)
    if not ok then
        local reason = type(ret) == "table" and ret.reason or tostring(ret)
        return nil, "cannot sign token: " .. reason
    end
    return ret
end

--- Whether a token's lifetime is within `sp.max_lifetime`
---
--- A validator over the whole payload, so a token whose identity provider
--- was misconfigured with a long lifetime is still refused by the relying
--- party.
---
--- @param payload table Decoded payload
--- @return boolean
local function _lifetime_within_max(payload)
    return type(payload.exp) == "number" and type(payload.iat) == "number"
        and payload.exp - payload.iat <= config.sp.max_lifetime
end

--- Build the claim spec a service provider verifies against
---
--- Call once at init from `sp.issuer` and `sp.audience`. `exp` must be
--- present and in the future, `iat` must be present and not in the future,
--- `iss` must equal the identity provider's origin, `aud` must contain one
--- of this service provider's audiences, and the lifetime must not exceed
--- `sp.max_lifetime`.
---
--- @return table Claim spec for `verify`
function _M.claim_spec()
    return {
        exp = validators.required(validators.is_not_expired()),
        iat = validators.required(validators.is_not_before()),
        iss = validators.required(validators.equals(config.sp.issuer)),
        aud = validators.required(validators.contains_any_of(config.sp.audience)),
        __jwt = function(jwt_obj)
            return _lifetime_within_max(jwt_obj.payload or {})
        end,
    }
end

--- Verify a session token
---
--- Steps, see the numbered comments. `key_by_kid` returns the PEM public key
--- for a kid, or nil and an error. It is called before the signature check
--- so an unknown kid never reaches the verifier.
---
--- @param token string          The compact JWT from the cookie
--- @param key_by_kid function   fn(kid) -> pem|nil, err
--- @param claim_spec table      Result of `claim_spec`
--- @return table|nil Payload claims, or nil when the token is refused
--- @return string|nil Reason the token was refused
function _M.verify(token, key_by_kid, claim_spec)
    -- 1. Parse without verifying, to read the header.
    local jwt_obj = jwt:load_jwt(token)
    if not jwt_obj.valid then
        return nil, jwt_obj.reason
    end

    -- 2. Pin the algorithm before anything looks at the key. A token that
    --    names HS256 with our public key as its shared secret is refused
    --    here, whatever lua-resty-jwt would make of it.
    if jwt_obj.header.alg ~= ALG then
        return nil, "unsupported alg " .. tostring(jwt_obj.header.alg)
    end

    -- 3. Resolve the key named by the header. The kid is attacker-chosen
    --    text until the signature checks out, so it is type-checked here and
    --    quoted wherever it is logged.
    local kid = jwt_obj.header.kid
    if type(kid) ~= "string" or #kid == 0 or #kid > KID_MAX_LENGTH then
        return nil, "kid missing or malformed"
    end
    local pem, err = key_by_kid(kid)
    if not pem then
        return nil, "no key for kid " .. string.format("%q", kid) .. ": " .. (err or "")
    end

    -- 4. Signature and claims in one call. verify_jwt_obj runs the claim
    --    spec first (step 4a) and the signature second (step 4b), and
    --    reports either failure in `reason`.
    jwt_obj = jwt:verify_jwt_obj(pem, jwt_obj, claim_spec)
    if not jwt_obj.verified then
        return nil, jwt_obj.reason
    end

    return jwt_obj.payload
end

return _M
