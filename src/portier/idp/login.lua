-- Identity provider login phase
--
-- Runs from access_by_lua_block on the login location. Without an `email`
-- argument the phase returns and nginx serves the login page. With one, it
-- checks the address, confirms the domain accepts mail, remembers the nonce
-- and return URL in a short-lived cookie, and sends the browser to the
-- broker's authorization endpoint. The broker posts the id_token back to the
-- verify location.
--
-- Every failure redirects back to the login page with the address and a
-- message in the URL fragment, which the page shows.

local resolver = require "resty.dns.resolver"
local random = require "resty.random"
local str = require "resty.string"

local config = require "portier.config"
local idp = require "portier.idp.init"
local email_validate = require "portier.idp.email_validate"

local _M = {}

--- Bytes of randomness in the nonce
local NONCE_BYTES = 16

--- Sec-Fetch-Site values under which a login may start
---
--- `same-origin` is the identity provider's own login page, `same-site` is
--- a service provider under the shared parent domain such as RT's login
--- form, and `none` is a URL the user typed or bookmarked. `cross-site` is a
--- page on someone else's origin, which must not be able to start a login
--- in this browser: a login started for the attacker's address and finished
--- by the attacker would otherwise leave the attacker's session in the
--- victim's browser.
local fetch_site_allowed = {
    ["same-origin"] = true,
    ["same-site"] = true,
    ["none"] = true,
}

--- Whether the request may start a login, by its origin
---
--- Uses `Sec-Fetch-Site` when the browser sends it. Otherwise falls back to
--- the `Referer` origin, which must be an allowed return origin. A request
--- with neither header is refused.
---
--- @return boolean
local function _start_allowed()
    local fetch_site = ngx.var.http_sec_fetch_site
    if fetch_site then
        return fetch_site_allowed[fetch_site] == true
    end
    local referer = ngx.var.http_referer
    if not referer then
        return false
    end
    return idp.return_to_allowed(referer)
end

--- Send the browser back to the login page with an error
---
--- @param email string  Address the user typed
--- @param message string Human-readable reason
local function _login_error(email, message)
    local url = idp.origin() .. "/.portier/login#" .. ngx.encode_args({ email = email, error = message })
    return ngx.redirect(url, ngx.HTTP_MOVED_TEMPORARILY)
end

--- Whether the domain of an address accepts mail, by its MX records
---
--- RFC 7505: a single MX of "." with preference 0 is a null MX, and means
--- the domain accepts no mail.
---
--- @param domain string Domain part of the address
--- @return boolean|nil True when mail is accepted, nil on a resolver failure
--- @return string|nil Message for the user when not accepted or on failure
local function _domain_accepts_mail(domain)
    local r, err = resolver:new({ nameservers = config.idp.nameservers })
    if not r then
        ngx.log(ngx.ERR, "no resolver: ", err)
        return nil, "server DNS resolver problem, please contact support"
    end
    local answers
    answers, err = r:query(domain, { qtype = r.TYPE_MX })
    if not answers then
        ngx.log(ngx.WARN, "MX query for ", domain, " failed: ", err)
        return nil, "server DNS timeout problem, please contact support"
    end
    if #answers == 0 or (#answers == 1 and answers[1].preference == 0 and answers[1].exchange == "") then
        return false, "domain does not accept mail"
    end
    return true
end

--- Run the login phase for the current request
---
--- Steps, see the numbered comments.
function _M.run()
    local args = ngx.req.get_uri_args()
    if args.email == nil then
        return
    end
    local email = idp.arg_string(args.email)
    if not email then
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- 1. Only a page on this site may start a login in this browser.
    if not _start_allowed() then
        ngx.log(ngx.WARN, "login start refused, cross-site request from ", idp.log_quote(ngx.var.http_referer or ngx.var.http_origin or "unknown"))
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    -- 2. Address syntax. The validator also refuses the characters that are
    --    unsafe in a directory filter value. A value with control characters
    --    is not written to the log, only its length.
    if #email == 0 or email:find("%c") then
        ngx.log(ngx.WARN, "invalid address of ", #email, " bytes with control characters")
        return _login_error(email, "email has no valid characters")
    end
    local valid, domain = email_validate.validemail(email)
    if not valid then
        ngx.log(ngx.WARN, "invalid address: ", idp.log_quote(email))
        return _login_error(email, "email is invalid")
    end

    -- 3. The domain must accept mail, or the broker can never deliver.
    if config.idp.mx_check then
        local accepts, message = _domain_accepts_mail(domain)
        if not accepts then
            ngx.log(ngx.WARN, "domain refused for ", email, ": ", message)
            return _login_error(email, message)
        end
    end

    -- 4. Where to send the browser after login. Only a URL on an audience
    --    origin is accepted, so this is not an open redirect.
    local return_to = idp.arg_string(args.return_to)
    if not return_to or not idp.return_to_allowed(return_to) then
        return_to = config.idp.landing_url
    end

    -- 5. The broker's endpoints, through the caching proxy.
    local openid, err = idp.broker_json_get(config.idp.broker_url .. "/.well-known/openid-configuration")
    if not openid then
        ngx.log(ngx.ERR, "broker discovery failed: ", err)
        return _login_error(email, "email authentication failed, please contact support")
    end

    -- 6. Remember the nonce and return URL for the verify phase. The broker
    --    posts back cross-site, so the cookie needs SameSite=None to be sent
    --    with that POST.
    local nonce = str.to_hex(random.bytes(NONCE_BYTES))
    ngx.header["Set-Cookie"] = idp.LOGIN_COOKIE .. "=" .. nonce .. "|" .. ngx.escape_uri(return_to)
        .. "; Path=/.portier; HttpOnly; Secure; SameSite=None; Max-Age=" .. config.idp.login_timeout

    -- 7. Off to the broker.
    local origin = idp.origin()
    local query = ngx.encode_args({
        client_id = origin,
        nonce = nonce,
        response_type = "id_token",
        redirect_uri = origin .. "/.portier/verify",
        scope = "openid email",
        login_hint = email,
        response_mode = "form_post",
    })
    return ngx.redirect(openid.authorization_endpoint .. "?" .. query, ngx.HTTP_MOVED_TEMPORARILY)
end

return _M
