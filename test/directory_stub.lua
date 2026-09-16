-- Stand-in for portier.idp.directory: fixed identities, no LDAP.

local _M = {}

_M.GRANT_SUPPORTED = "supported"

local identities = {
    ["supported@example.org"] = {
        uid = "supported", groups = { "cn=customers,ou=groups,dc=example,dc=org" },
        grants = { "supported" }, support_tier = "Gold",
    },
    ["lapsed@example.org"] = {
        uid = "lapsed", groups = { "cn=customers,ou=groups,dc=example,dc=org" },
        grants = {}, support_tier = "Silver",
    },
    ["staff@example.org"] = {
        uid = "staff", groups = { "cn=employees,ou=groups,dc=example,dc=org" },
        grants = { "supported" }, support_tier = nil,
    },
}

function _M.lookup(email)
    if email == "broken@example.org" then
        return nil, "directory unreachable"
    end
    local found = identities[email]
    if not found then
        return nil
    end
    return {
        sub = email, uid = found.uid, dn = "uid=" .. found.uid .. ",ou=people,o=Acme,dc=example,dc=org",
        groups = found.groups, grants = found.grants, support_tier = found.support_tier,
    }
end

return _M
