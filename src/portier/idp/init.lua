-- Identity provider state built once per worker
--
-- Loaded with `require "portier.idp.init"` from init_by_lua_block. Loads the
-- signing key and the shared helpers the login and verify phases use.
-- `require` caches the module, so the phases share one copy.

local cjson = require "cjson.safe"

local config = require "portier.config"
local token = require "portier.token"

local _M = {}

--- Signing key: { pem, kid, jwk }, see `portier.token.key_load`
do
    local key, err = token.key_load()
    if not key then
        error("portier idp: " .. err)
    end
    _M.key = key
end

--- Name of the short-lived cookie that carries the nonce and return URL
--- across the broker round trip
_M.LOGIN_COOKIE = "portier_login"

--- Decode base64url
---
--- @param s64url string base64url text
--- @return string|nil Decoded bytes, or nil when the text is not base64url
function _M.base64url_decode(s64url)
    local s64 = s64url:gsub("-", "+"):gsub("_", "/")
    local pad = #s64 % 4
    if pad > 0 then
        s64 = s64 .. string.rep("=", 4 - pad)
    end
    return ngx.decode_base64(s64)
end

--- Rewrite an absolute URL as a path under the internal broker proxy location
---
--- The nginx config proxies `/.portier/proxy/<scheme>/<host><path>` to the
--- named host with a cache in front, so the broker's discovery document and
--- key set are fetched once and reused.
---
--- @param url string Absolute URL
--- @return string Internal proxy path
function _M.proxy_url(url)
    local scheme, rest = url:match("^(%w+)://(.*)$")
    return "/.portier/proxy/" .. scheme .. "/" .. rest
end

--- Fetch and decode a JSON document through the broker proxy
---
--- @param url string Absolute URL
--- @return table|nil Decoded document, or nil on error
--- @return string|nil Error
function _M.broker_json_get(url)
    local res = ngx.location.capture(_M.proxy_url(url))
    if res.status >= 400 or res.truncated then
        return nil, "fetch of " .. url .. " returned " .. res.status
    end
    local doc, err = cjson.decode(res.body)
    if not doc then
        return nil, "cannot decode " .. url .. ": " .. err
    end
    return doc
end

--- The identity provider's origin, scheme and host
---
--- `idp.public_origin` when set. Otherwise derived from the request: scheme,
--- host, and the port when it is not the scheme's default.
---
--- @return string Origin such as https://portier.example.org
function _M.origin()
    if config.idp.public_origin then
        return config.idp.public_origin
    end
    local scheme = ngx.var.scheme
    local port = ngx.var.server_port
    local default_port = scheme == "https" and "443" or "80"
    if port == default_port then
        return scheme .. "://" .. ngx.var.host
    end
    return scheme .. "://" .. ngx.var.host .. ":" .. port
end

--- Whether a return URL may be redirected to after login
---
--- Only https URLs whose host is the cookie domain or a host under it are
--- allowed, so the login endpoint is not an open redirect.
---
--- @param url string Candidate return URL
--- @return boolean
function _M.return_to_allowed(url)
    local host = url:match("^https://([^/?#:]+)")
    if not host then
        return false
    end
    local domain = config.idp.cookie.domain
    if host == domain then
        return true
    end
    return host:sub(-(#domain + 1)) == "." .. domain
end

return _M
