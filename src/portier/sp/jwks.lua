-- The identity provider's public keys, as a service provider sees them
--
-- Fetches the JWKS document named by `sp.jwks_url`, caches it in the
-- `portier_jwks` shared dict for `sp.jwks_cache_ttl` seconds, and resolves a
-- kid to a PEM public key for `portier.token.verify`. A kid that is not in
-- the cached document triggers one refetch, so a key the identity provider
-- rotated in is picked up without waiting for the cache to expire.
--
-- `sp.jwks_url` may be a file:// URL, so a test can verify offline against a
-- JWKS on disk.

local http = require "resty.http"
local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"

local config = require "portier.config"

local _M = {}

--- Shared dict key holding the JWKS document body
local KEY_DOCUMENT = "jwks"

--- Shared dict key prefix for a resolved PEM, followed by the kid
local KEY_PEM_PREFIX = "pem:"

--- Shared dict key prefix for a kid the key set did not contain
local KEY_MISS_PREFIX = "miss:"

--- Shared dict key that serialises refetches across workers
local KEY_FETCH_LOCK = "fetch_lock"

--- Seconds a refetch lock is held before it expires on its own
local FETCH_LOCK_TTL = 5

--- Key type, curve and use a signing key in the set must declare
local KEY_TYPE = "EC"
local KEY_CURVE = "P-256"
local KEY_USE = "sig"

--- Read a JWKS from a file:// URL
---
--- @param path string Path after file://
--- @return string|nil Body, or nil on error
--- @return string|nil Error
local function _document_read_file(path)
    local f, err = io.open(path, "r")
    if not f then
        return nil, "cannot open " .. path .. ": " .. err
    end
    local data = f:read("*a")
    f:close()
    return data
end

--- Fetch a JWKS from an https:// URL
---
--- @param url string The JWKS URL
--- @return string|nil Body, or nil on error
--- @return string|nil Error
local function _document_fetch_http(url)
    local host = url:match("^https://([^/?#]+)")
    if not host then
        return nil, "JWKS URL must be https:// or file://"
    end

    local httpc = http.new()
    local res, err = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = true,
        ssl_server_name = host,
    })
    if not res then
        return nil, "cannot reach JWKS endpoint: " .. (err or "unknown")
    end
    if res.status ~= 200 then
        return nil, "JWKS endpoint returned " .. res.status
    end
    return res.body
end

--- Load the JWKS document from its URL and cache it
---
--- @return table|nil Decoded JWKS, or nil on error
--- @return string|nil Error
local function _document_load()
    local url = config.sp.jwks_url
    local body, err

    local file_path = url:match("^file://(.+)$")
    if file_path then
        body, err = _document_read_file(file_path)
    else
        body, err = _document_fetch_http(url)
    end
    if not body then
        return nil, err
    end

    local doc
    doc, err = cjson.decode(body)
    if not doc or type(doc.keys) ~= "table" then
        return nil, "JWKS document is not a key set: " .. (err or "no keys member")
    end

    ngx.shared.portier_jwks:set(KEY_DOCUMENT, body, config.sp.jwks_cache_ttl)
    return doc
end

--- Return the cached JWKS document, loading it when the cache is empty
---
--- @return table|nil Decoded JWKS, or nil on error
--- @return string|nil Error
local function _document_get()
    local cached = ngx.shared.portier_jwks:get(KEY_DOCUMENT)
    if type(cached) == "string" then
        return cjson.decode(cached)
    end
    return _document_load()
end

--- Find the ES256 signing key with a given kid in a JWKS document
---
--- A key with the right kid but the wrong type, curve or use is ignored, so
--- a key set that also publishes other keys cannot steer verification onto
--- one of them.
---
--- @param doc table JWKS document
--- @param kid string Key id
--- @return table|nil The JWK, or nil when no signing key carries the kid
local function _jwk_find(doc, kid)
    for i = 1, #doc.keys do
        local key = doc.keys[i]
        if type(key) == "table" and key.kid == kid and key.kty == KEY_TYPE
            and key.crv == KEY_CURVE and key.use == KEY_USE then
            return key
        end
    end
    return nil
end

--- Convert a JWK to a PEM public key
---
--- @param jwk table A single JWK
--- @return string|nil PEM, or nil on error
--- @return string|nil Error
local function _jwk_to_pem(jwk)
    local pk, err = pkey.new(cjson.encode(jwk), { format = "JWK" })
    if not pk then
        return nil, err
    end
    return pk:to_PEM("public")
end

--- Resolve a kid to a PEM public key, for `portier.token.verify`
---
--- Steps, see the numbered comments.
---
--- @param kid string Key id from the token header
--- @return string|nil PEM public key, or nil when the kid is unknown
--- @return string|nil Error
function _M.key_by_kid(kid)
    -- 1. A PEM resolved earlier for this kid is cached under its own key.
    local pem = ngx.shared.portier_jwks:get(KEY_PEM_PREFIX .. kid)
    if type(pem) == "string" then
        return pem
    end

    -- 2. A kid that missed recently is refused without any fetch, so a
    --    flood of made-up kids costs one fetch per jwks_miss_ttl window.
    if ngx.shared.portier_jwks:get(KEY_MISS_PREFIX .. kid) then
        return nil, "kid not in JWKS"
    end

    -- 3. Look the kid up in the cached document.
    local doc, err = _document_get()
    if not doc then
        return nil, err
    end
    local jwk = _jwk_find(doc, kid)

    -- 4. Not there: the identity provider may have rotated. Refetch once,
    --    and only one worker at a time: `add` fails while another holds
    --    the lock, and that worker waits for the winner's document.
    if not jwk then
        local locked = ngx.shared.portier_jwks:add(KEY_FETCH_LOCK, true, FETCH_LOCK_TTL)
        if locked then
            ngx.shared.portier_jwks:delete(KEY_DOCUMENT)
            doc, err = _document_load()
            ngx.shared.portier_jwks:delete(KEY_FETCH_LOCK)
            if not doc then
                return nil, err
            end
        end
        jwk = _jwk_find(doc, kid)
        if not jwk then
            ngx.shared.portier_jwks:set(KEY_MISS_PREFIX .. kid, true, config.sp.jwks_miss_ttl)
            return nil, "kid not in JWKS"
        end
    end

    -- 5. Convert once and cache the PEM for the document's lifetime.
    pem, err = _jwk_to_pem(jwk)
    if not pem then
        return nil, "cannot convert JWK to PEM: " .. err
    end
    ngx.shared.portier_jwks:set(KEY_PEM_PREFIX .. kid, pem, config.sp.jwks_cache_ttl)
    return pem
end

return _M
