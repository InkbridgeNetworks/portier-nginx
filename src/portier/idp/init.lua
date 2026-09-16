-- Identity provider state built once per worker
--
-- Loaded with `require "portier.idp.init"` from init_by_lua_block. Loads the
-- signing key and the shared helpers the login and verify phases use.
-- `require` caches the module, so the phases share one copy.

local cjson = require "cjson.safe"

local config = require "portier.config"
local token = require "portier.token"
local utils = require "portier.utils"

local _M = {}

--- Component name that prefixes every init failure message of the identity provider
local COMPONENT = "portier idp"

utils.setting_require(config.idp.public_origin, "idp.public_origin", COMPONENT)
utils.setting_require(config.idp.cookie.domain, "idp.cookie.domain", COMPONENT)
utils.setting_require(config.idp.token.audience[1], "idp.token.audience", COMPONENT)
utils.setting_require(config.idp.ldap.servers[1], "idp.ldap.servers", COMPONENT)
utils.setting_require(config.idp.ldap.base_dn, "idp.ldap.base_dn", COMPONENT)
utils.setting_require(config.idp.ldap.bind_dn, "idp.ldap.bind_dn", COMPONENT)

--- Origins a login may return to, as a set: the audiences plus the IdP
local return_origins = utils.set_from_list(config.idp.token.audience)
return_origins[config.idp.public_origin] = true

--- Signing key: { pem, kid, jwk }, see `portier.token.key_load`
do
    local key, err = token.key_load()
    if not key then
        utils.fail(COMPONENT, err)
    end
    _M.key = key
end

--- Name of the short-lived cookie that carries the nonce and return URL
--- across the broker round trip
_M.LOGIN_COOKIE = "portier_login"

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

--- Send the browser back to the login page with an error
---
--- The login page reads the email address and the reason from the URL
--- fragment. Neither the address nor the reason therefore reaches the server
--- log or the `Referer` header of the next request.
---
--- @param email string|nil Email address, when known
--- @param message string   Human-readable reason
function _M.login_error(email, message)
    local url = _M.origin() .. "/.portier/login#" .. ngx.encode_args({ email = email or "", error = message })
    return ngx.redirect(url, ngx.HTTP_MOVED_TEMPORARILY)
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
