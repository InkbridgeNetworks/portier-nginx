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
    local email = args.email
    if not email then
        return
    end

    -- 1. Address syntax. The validator also refuses the characters that are
    --    unsafe in a directory filter value.
    if #email == 0 or email:find("%c") then
        ngx.log(ngx.WARN, "invalid address: ", email)
        return _login_error(email, "email has no valid characters")
    end
    local valid, domain = email_validate.validemail(email)
    if not valid then
        ngx.log(ngx.WARN, "invalid address: ", email)
        return _login_error(email, "email is invalid")
    end

    -- 2. The domain must accept mail, or the broker can never deliver.
    if config.idp.mx_check then
        local accepts, message = _domain_accepts_mail(domain)
        if not accepts then
            ngx.log(ngx.WARN, "domain refused for ", email, ": ", message)
            return _login_error(email, message)
        end
    end

    -- 3. Where to send the browser after login. Only a URL under the cookie
    --    domain is accepted, so this is not an open redirect.
    local return_to = args.return_to
    if not return_to or not idp.return_to_allowed(return_to) then
        return_to = config.idp.landing_url
    end

    -- 4. The broker's endpoints, through the caching proxy.
    local openid, err = idp.broker_json_get(config.idp.broker_url .. "/.well-known/openid-configuration")
    if not openid then
        ngx.log(ngx.ERR, "broker discovery failed: ", err)
        return _login_error(email, "email authentication failed, please contact support")
    end

    -- 5. Remember the nonce and return URL for the verify phase. The broker
    --    posts back cross-site, so the cookie needs SameSite=None to be sent
    --    with that POST.
    local nonce = str.to_hex(random.bytes(NONCE_BYTES))
    ngx.header["Set-Cookie"] = idp.LOGIN_COOKIE .. "=" .. nonce .. "|" .. ngx.escape_uri(return_to)
        .. "; Path=/.portier; HttpOnly; Secure; SameSite=None; Max-Age=" .. config.idp.login_timeout

    -- 6. Off to the broker.
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
