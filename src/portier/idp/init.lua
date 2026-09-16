-- Identity provider state built once per worker
--
-- Loaded with `require "portier.idp.init"` from init_by_lua_block. Loads the
-- signing key and the shared helpers the login and verify phases use.
-- `require` caches the module, so the phases share one copy.

local cjson = require "cjson.safe"

local config = require "portier.config"
local token = require "portier.token"

local _M = {}

--- Stop nginx at init when a required identity provider setting is unset
---
--- @param value any    Setting value
--- @param name string  Setting name for the message
local function _require_set(value, name)
    if value == nil or value == "" then
        error("portier idp: " .. name .. " is not set in conf.lua")
    end
end

_require_set(config.idp.public_origin, "idp.public_origin")
_require_set(config.idp.cookie.domain, "idp.cookie.domain")
_require_set(config.idp.token.audience[1], "idp.token.audience")
_require_set(config.idp.ldap.servers[1], "idp.ldap.servers")
_require_set(config.idp.ldap.base_dn, "idp.ldap.base_dn")
_require_set(config.idp.ldap.bind_dn, "idp.ldap.bind_dn")

--- Origins a login may return to, as a set: the audiences plus the IdP
local return_origins = {}
for i = 1, #config.idp.token.audience do
    return_origins[config.idp.token.audience[i]] = true
end
return_origins[config.idp.public_origin] = true

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
--- Always `idp.public_origin`. The origin is the broker client_id, the
--- id_token audience, the `iss` of minted tokens and the base of every
--- redirect, so it is configured rather than read from the request's Host
--- header.
---
--- @return string Origin such as https://portier.example.org
function _M.origin()
    return config.idp.public_origin
end

--- A request argument as a string, or nil
---
--- nginx hands a repeated argument to Lua as a table and a bare `?name` as
--- `true`. Every argument the phases read goes through here, so a request
--- shaped like that is refused rather than raising inside the phase.
---
--- @param value any Value from `ngx.req.get_uri_args` or `get_post_args`
--- @return string|nil
function _M.arg_string(value)
    if type(value) == "string" then
        return value
    end
    return nil
end

--- Quote a request-supplied value for a log line
---
--- @param value any Value from the request
--- @return string Lua-quoted form, control characters escaped
function _M.log_quote(value)
    return string.format("%q", tostring(value))
end

--- Whether a return URL may be redirected to after login
---
--- The URL must be https, and its origin must be one of the configured
--- audiences or the identity provider itself. The origin is taken as the
--- text up to the first "/", "?" or "#" and must contain only host and port
--- characters, so a backslash, an "@" or a percent sign in the authority
--- cannot make a browser and this check disagree about the host.
---
--- Worked example, audience https://rt.example.org:
---   https://rt.example.org/Ticket/1  -> origin https://rt.example.org, allowed
---   https://evil.example\x.example.org/ -> "\" is not a host character, refused
---
--- @param url string Candidate return URL
--- @return boolean
function _M.return_to_allowed(url)
    if type(url) ~= "string" or url:sub(1, 8) ~= "https://" then
        return false
    end
    local stop = #url + 1
    for _, sep in ipairs({ "/", "?", "#" }) do
        local pos = string.find(url, sep, 9, true)
        if pos and pos < stop then
            stop = pos
        end
    end
    local authority = url:sub(9, stop - 1)
    if authority == "" or not authority:match("^[%w%.%-]+:?%d*$") then
        return false
    end
    return return_origins["https://" .. string.lower(authority)] == true
end

return _M
