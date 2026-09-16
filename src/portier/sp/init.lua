-- Service provider state built once per worker
--
-- Loaded from init_by_lua_file on a service provider host. Builds the claim
-- spec from `sp.issuer` and `sp.audience`, and turns the policy lists into
-- lookup sets, so the access phase does no work per request that it can do
-- once. `portier.sp.access` requires this module, and `require` caches it,
-- so a worker builds the state one time.

local config = require "portier.config"
local token = require "portier.token"

local _M = {}

--- Turn a list of strings into a set keyed by the string
---
--- @param list table List of strings
--- @return table Set, value true for every member
local function _set_from_list(list)
    local set = {}
    for i = 1, #list do
        set[list[i]] = true
    end
    return set
end

--- Claim spec every token must satisfy on this service provider
_M.claim_spec = token.claim_spec()

--- Grants the policy requires, as a list, in the order they are checked.
--- The list order fixes which refusal message a token missing several
--- grants gets.
_M.grants_required = config.sp.policy.grants_required

--- Group DNs the policy refuses, as a set
_M.groups_denied = _set_from_list(config.sp.policy.groups_denied)

return _M
