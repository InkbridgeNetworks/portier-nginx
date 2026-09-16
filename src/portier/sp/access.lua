-- Service provider access phase
--
-- Runs from access_by_lua_block, `require("portier.sp.access").run()`, on every request to the protected
-- application. Reads the session token from the cookie, verifies it against
-- the identity provider's JWKS, applies this service provider's policy to
-- the claims, and sets the nginx variables the site passes to the
-- application as REMOTE_USER. The token never reaches the application: the
-- cookie is stripped from the Cookie header before the request goes
-- upstream.
--
-- No directory lookup happens here. The identity provider looked the user
-- up when the token was minted, and the signature is the proof.
--
-- Outcomes:
--   valid token, policy passes  -> variables set, request continues
--   valid token, policy refuses -> 403 with the configured message
--   no token, or invalid token  -> `sp.anonymous` decides: 401, a redirect
--                                  to the identity provider, or pass through
--                                  with no identity

local config = require "portier.config"
local token = require "portier.token"
local jwks = require "portier.sp.jwks"
local sp = require "portier.sp.init"

local byte_semicolon = string.byte(";")
local byte_space = string.byte(" ")

--- Remove one cookie from a Cookie header value
---
--- Walks the header by index rather than with a pattern, because this runs
--- on every request. Cookie segments are separated by ";" with optional
--- spaces, and a segment is ours when the text up to its "=" is `name`.
---
--- Worked example: name = portier_session
---   in:  RT_SID=abc; portier_session=eyJ...; theme=dark
---   out: RT_SID=abc; theme=dark
---
--- @param header string Cookie header value
--- @param name string   Cookie name to drop
--- @return string Header value without that cookie
local function _cookie_header_strip(header, name)
    local kept = {}
    local start = 1
    local len = #header
    local name_len = #name

    while start <= len do
        -- The segment runs to the next ";", or to the end: RT_SID=abc
        local stop = string.find(header, ";", start, true)
        if not stop then
            stop = len + 1
        end
        -- Trim spaces either side of the segment.
        local seg_start = start
        while seg_start < stop and string.byte(header, seg_start) == byte_space do
            seg_start = seg_start + 1
        end
        local seg_stop = stop - 1
        while seg_stop >= seg_start and string.byte(header, seg_stop) == byte_space do
            seg_stop = seg_stop - 1
        end
        if seg_stop >= seg_start then
            -- Ours when the segment starts with "<name>=".
            local is_ours = string.sub(header, seg_start, seg_start + name_len) == name .. "="
            if not is_ours then
                kept[#kept + 1] = string.sub(header, seg_start, seg_stop)
            end
        end
        start = stop + 1
    end

    return table.concat(kept, "; ")
end

--- Expire the session cookie in the browser
local function _cookie_clear()
    ngx.header["Set-Cookie"] = config.sp.cookie_name .. "=; Path=/; HttpOnly; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
end

--- Answer 401 to a request with no usable identity
local function _anonymous_deny()
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

--- Send a browser to the identity provider, remembering where it was going
local function _anonymous_redirect()
    local return_to = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri
    return ngx.redirect(config.sp.login_url .. "?" .. ngx.encode_args({ return_to = return_to }),
                        ngx.HTTP_MOVED_TEMPORARILY)
end

--- Let a request through with no identity set
local function _anonymous_pass()
    return
end

--- What to do with a request that has no valid token, by `sp.anonymous`
local anonymous_handle = {
    deny = _anonymous_deny,
    redirect = _anonymous_redirect,
    pass = _anonymous_pass,
}

--- Refuse a request whose token fails policy
---
--- @param message string|nil Body to send, or nil for the status alone
local function _policy_refuse(message)
    ngx.status = ngx.HTTP_FORBIDDEN
    if message then
        ngx.header["Content-Type"] = "text/plain; charset=utf-8"
        ngx.say(message)
    end
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

--- Apply this service provider's policy to a verified token
---
--- @param claims table Verified payload
--- @return boolean True when the token passes
--- @return string|nil Refusal message when it does not
local function _policy_check(claims)
    local groups = claims.groups or {}
    for i = 1, #groups do
        if sp.groups_denied[groups[i]] then
            return false, config.sp.refusal_messages.groups_denied
        end
    end

    local grants = claims.grants or {}
    local held = {}
    for i = 1, #grants do
        held[grants[i]] = true
    end
    for i = 1, #sp.grants_required do
        local grant = sp.grants_required[i]
        if not held[grant] then
            return false, config.sp.refusal_messages[grant]
        end
    end

    return true
end

local _M = {}

--- Run the access phase for the current request
---
--- Steps, see the numbered comments.
function _M.run()
    -- 1. Take the token out of the cookie, and the cookie out of the header the
    --    application will see.
    local cookie_name = config.sp.cookie_name
    local session = ngx.var["cookie_" .. cookie_name]
    local cookie_header = ngx.var.http_cookie
    if cookie_header then
        ngx.req.set_header("Cookie", _cookie_header_strip(cookie_header, cookie_name))
    end

    -- 2. No cookie: anonymous.
    if not session then
        return anonymous_handle[config.sp.anonymous]()
    end

    -- 3. Verify signature and claims. A token that fails is cleared from the
    --    browser so the next request is plainly anonymous.
    local claims, err = token.verify(session, jwks.key_by_kid, sp.claim_spec)
    if not claims then
        ngx.log(ngx.WARN, "session token refused: ", err)
        _cookie_clear()
        return anonymous_handle[config.sp.anonymous]()
    end

    -- 4. Policy over the claims.
    local passed, message = _policy_check(claims)
    if not passed then
        ngx.log(ngx.INFO, "policy refused ", claims.uid, ": ", message or "no message")
        return _policy_refuse(message)
    end

    -- 5. Hand the identity to the application.
    ngx.var[config.sp.var_uid] = claims.uid
    ngx.var[config.sp.var_email] = claims.sub
end

return _M
