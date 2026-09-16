-- Service provider state built once per worker
--
-- Loaded from init_by_lua_file on a service provider host. Builds the claim
-- spec from `sp.issuer` and `sp.audience`, and turns the policy lists into
-- lookup sets, so the access phase does no work per request that it can do
-- once. `portier.sp.access` requires this module, and `require` caches it,
-- so a worker builds the state one time.

local config = require "portier.config"
local token = require "portier.token"
local utils = require "portier.utils"

local _M = {}

--- Component name that prefixes every init failure message of the service provider
local COMPONENT = "portier sp"

utils.setting_require(config.sp.issuer, "sp.issuer", COMPONENT)
utils.setting_require(config.sp.audience[1], "sp.audience", COMPONENT)
utils.setting_require(config.sp.jwks_url, "sp.jwks_url", COMPONENT)
utils.setting_require(config.sp.cookie_domain, "sp.cookie_domain", COMPONENT)
if config.sp.anonymous == "redirect" then
    utils.setting_require(config.sp.login_url, "sp.login_url", COMPONENT)
end

--- Claim spec every token must satisfy on this service provider
_M.claim_spec = token.claim_spec()

--- Grants the policy requires, as a list, in the order they are checked.
--- The list order fixes which refusal message a token missing several
--- grants gets.
_M.grants_required = config.sp.policy.grants_required

--- Group DNs the policy refuses, as a set
_M.groups_denied = utils.set_from_list(config.sp.policy.groups_denied)

return _M
