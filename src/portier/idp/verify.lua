-- Identity provider verify phase
--
-- Runs from access_by_lua_block on the verify location, which receives the
-- broker's form_post. Checks the broker's RS256 id_token, matches its nonce
-- against the login cookie, looks the verified address up in the directory,
-- mints the session token, and sends the browser to the return URL.
--
-- The id_token is checked with lua-resty-jwt against the broker's published
-- key set, with the algorithm pinned to RS256 by an explicit header check.

local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"
local pkey = require "resty.openssl.pkey"
local cjson = require "cjson.safe"

local config = require "portier.config"
local idp = require "portier.idp.init"
local token = require "portier.token"
local directory = require "portier.idp.directory"
local email_validate = require "portier.idp.email_validate"

local _M = {}

--- The only algorithm the broker's id_token may carry
local BROKER_ALG = "RS256"

--- Seconds of clock skew tolerated on the id_token's iat
local BROKER_IAT_LEEWAY = 10

--- Expire the login cookie
local function _login_cookie_clear()
    ngx.header["Set-Cookie"] = idp.LOGIN_COOKIE .. "=; Path=/.portier; HttpOnly; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
end

--- Read the nonce and return URL the login phase stored
---
--- Worked example cookie value: 3f9a...c1|https%3A%2F%2Frt.example.org%2F
---   nonce: 3f9a...c1, return_to: https://rt.example.org/
---
--- @return string|nil Nonce, or nil when the cookie is missing or malformed
--- @return string|nil Return URL
local function _login_cookie_read()
    local value = ngx.var["cookie_" .. idp.LOGIN_COOKIE]
    if not value then
        return nil
    end
    local bar = string.find(value, "|", 1, true)
    if not bar then
        return nil
    end
    return string.sub(value, 1, bar - 1), ngx.unescape_uri(string.sub(value, bar + 1))
end

--- Send the browser back to the login page with an error
---
--- @param email string|nil Address, when known
--- @param message string   Human-readable reason
local function _login_error(email, message)
    local url = idp.origin() .. "/.portier/login#" .. ngx.encode_args({ email = email or "", error = message })
    return ngx.redirect(url, ngx.HTTP_MOVED_TEMPORARILY)
end

--- Find the broker's signing key for a kid, as PEM
---
--- @param kid string Key id from the id_token header
--- @return string|nil PEM public key, or nil on error
--- @return string|nil Error
local function _broker_key_by_kid(kid)
    local openid, err = idp.broker_json_get(config.idp.broker_url .. "/.well-known/openid-configuration")
    if not openid then
        return nil, err
    end
    local jwks
    jwks, err = idp.broker_json_get(openid.jwks_uri)
    if not jwks then
        return nil, err
    end
    for i = 1, #jwks.keys do
        local key = jwks.keys[i]
        if key.kid == kid and key.use == "sig" and key.kty == "RSA" then
            local pk
            pk, err = pkey.new(cjson.encode(key), { format = "JWK" })
            if not pk then
                return nil, "cannot load broker key: " .. err
            end
            return pk:to_PEM("public")
        end
    end
    return nil, "no signing key with kid " .. kid
end

--- Verify the broker's id_token and return its payload
---
--- @param id_token string Compact JWT from the form post
--- @param nonce string    Nonce the login phase issued
--- @return table|nil Payload, or nil when refused
--- @return string|nil Reason
local function _id_token_verify(id_token, nonce)
    local jwt_obj = jwt:load_jwt(id_token)
    if not jwt_obj.valid then
        return nil, jwt_obj.reason
    end
    if jwt_obj.header.alg ~= BROKER_ALG then
        return nil, "unsupported alg " .. tostring(jwt_obj.header.alg)
    end
    if not jwt_obj.header.kid then
        return nil, "no kid in header"
    end

    local pem, err = _broker_key_by_kid(jwt_obj.header.kid)
    if not pem then
        return nil, err
    end

    validators.set_system_leeway(BROKER_IAT_LEEWAY)
    local spec = {
        iss = validators.required(validators.equals(config.idp.broker_url)),
        aud = validators.required(validators.equals(idp.origin())),
        exp = validators.required(validators.is_not_expired()),
        iat = validators.required(validators.is_not_before()),
        nonce = validators.required(validators.equals(nonce)),
        sub = validators.required(),
    }
    jwt_obj = jwt:verify_jwt_obj(pem, jwt_obj, spec)
    validators.set_system_leeway(0)
    if not jwt_obj.verified then
        return nil, jwt_obj.reason
    end
    return jwt_obj.payload
end

--- Run the verify phase for the current request
---
--- Steps, see the numbered comments.
function _M.run()
    -- 1. The broker's form post.
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    if not args then
        ngx.log(ngx.WARN, "no post args")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    if args.error ~= nil then
        ngx.log(ngx.WARN, "broker error: ", idp.log_quote(args.error))
        return _login_error(nil, "email authentication failed at the broker")
    end
    local id_token = idp.arg_string(args.id_token)
    if not id_token then
        ngx.log(ngx.WARN, "missing or malformed id_token")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- 2. The login cookie holds the nonce this id_token must carry.
    local nonce, return_to = _login_cookie_read()
    if not nonce then
        ngx.log(ngx.WARN, "no login cookie on verify")
        return _login_error(nil, "login expired, please try again")
    end

    -- 3. Verify the id_token.
    local payload, err = _id_token_verify(id_token, nonce)
    if not payload then
        ngx.log(ngx.WARN, "id_token refused: ", idp.log_quote(err))
        _login_cookie_clear()
        return _login_error(nil, "email authentication failed, please contact support")
    end

    -- 4. The verified address is the subject. Check it again in case the
    --    broker's idea of an address differs from ours.
    local email = payload.sub
    if type(email) ~= "string" or not email_validate.validemail(email) then
        ngx.log(ngx.WARN, "broker returned invalid address: ", idp.log_quote(email))
        _login_cookie_clear()
        return _login_error(email, "email is invalid")
    end

    -- 5. Directory lookup: identity and entitlements, or no account.
    local identity
    identity, err = directory.lookup(email)
    if err then
        ngx.log(ngx.ERR, "directory lookup failed for ", email, ": ", err)
        return ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end
    if not identity then
        _login_cookie_clear()
        return _login_error(email, "no account for this address, please contact support")
    end

    -- 6. Mint the session token and set it on the shared domain. Max-Age
    --    matches the token lifetime so the browser drops both together.
    local claims = {
        sub = identity.sub,
        uid = identity.uid,
        groups = identity.groups,
        grants = identity.grants,
        support_tier = identity.support_tier,
    }
    local session
    session, err = token.mint(claims, idp.key, idp.origin())
    if not session then
        ngx.log(ngx.ERR, "cannot mint session token for ", email, ": ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    local cookie = config.idp.cookie
    ngx.header["Set-Cookie"] = {
        cookie.name .. "=" .. session .. "; Domain=" .. cookie.domain .. "; Path=" .. cookie.path
            .. "; HttpOnly; Secure; SameSite=" .. cookie.same_site .. "; Max-Age=" .. config.idp.token.lifetime,
        idp.LOGIN_COOKIE .. "=; Path=/.portier; HttpOnly; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    }
    ngx.log(ngx.INFO, "session issued to ", identity.uid, " (", email, ") grants ", table.concat(identity.grants, ","))

    -- 7. Back to where the user was going.
    if not return_to or not idp.return_to_allowed(return_to) then
        return_to = config.idp.landing_url
    end
    return ngx.redirect(return_to, ngx.HTTP_MOVED_TEMPORARILY)
end

return _M
