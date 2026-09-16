-- Identity provider key set endpoint
--
-- Runs from content_by_lua_block on the JWKS location. Serves the public
-- half of the signing key as a JWKS document, so a service provider can
-- verify tokens without holding a copy of the key.

local cjson = require "cjson.safe"

local config = require "portier.config"
local idp = require "portier.idp.init"

local _M = {}

--- The document, encoded once at load
local document = cjson.encode({ keys = { idp.key.jwk } })

--- Serve the key set
function _M.run()
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "public, max-age=" .. config.idp.jwks_max_age
    ngx.say(document)
end

return _M
