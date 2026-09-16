-- Identity provider logout
--
-- Runs from content_by_lua_block on the logout location. Expires the
-- session cookie on the shared domain and sends the browser to the return
-- URL, or to the landing URL when none is given or the URL is not under the
-- cookie domain.

local config = require "portier.config"
local idp = require "portier.idp.init"

local _M = {}

--- Clear the session and redirect
function _M.run()
    local cookie = config.idp.cookie
    ngx.header["Set-Cookie"] = cookie.name .. "=; Domain=" .. cookie.domain .. "; Path=" .. cookie.path
        .. "; HttpOnly; Secure; SameSite=" .. cookie.same_site .. "; Expires=Thu, 01 Jan 1970 00:00:00 GMT"

    local return_to = idp.arg_string(ngx.req.get_uri_args().return_to)
    if not return_to or not idp.return_to_allowed(return_to) then
        return_to = config.idp.landing_url
    end
    return ngx.redirect(return_to, ngx.HTTP_MOVED_TEMPORARILY)
end

return _M
