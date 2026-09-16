-- Directory lookup: verified email address to identity and entitlements
--
-- Runs once per login, after the broker has proven the user owns the
-- address. Finds the person entry, the organisation that owns the person,
-- and the organisation's support agreement, and returns the claims the
-- session token carries. Policy is not decided here: an employee or a
-- customer with a lapsed agreement gets a full answer, and each service
-- provider decides what to admit.
--
-- Worked example, person DN:
--   uid=jane,ou=people,o=Acme,dc=customers,dc=example,dc=org
--   organisation DN: o=Acme,dc=customers,dc=example,dc=org
--   the organisation is the entry two levels above the person.

local lualdap = require "lualdap"

local config = require "portier.config"

local _M = {}

--- Grant written when the organisation's support agreement is active
_M.GRANT_SUPPORTED = "supported"

local byte_comma = string.byte(",")
local byte_backslash = string.byte("\\")

--- Bind password, read once at load from `idp.ldap.bind_pw_file`
local bind_pw
do
    local f, err = io.open(config.idp.ldap.bind_pw_file, "r")
    if not f then
        error("portier directory: cannot read bind password " .. config.idp.ldap.bind_pw_file .. ": " .. err)
    end
    bind_pw = f:read("*l")
    f:close()
    if not bind_pw or bind_pw == "" then
        error("portier directory: bind password file " .. config.idp.ldap.bind_pw_file .. " is empty")
    end
end

--- Escape a value for use inside an LDAP search filter, RFC 4515
---
--- @param value string Raw value
--- @return string Escaped value
local function _filter_escape(value)
    return (value:gsub("[\\%*%(%)%z]", {
        ["\\"] = "\\5c",
        ["*"] = "\\2a",
        ["("] = "\\28",
        [")"] = "\\29",
        ["\0"] = "\\00",
    }))
end

--- Return an attribute as a list whatever lualdap returned
---
--- lualdap returns a string for one value, a table for several, and true
--- for an attribute that is present with no values.
---
--- @param value string|table|boolean|nil Attribute value from a search
--- @return table List of values, empty when absent
local function _values_list(value)
    if type(value) == "table" then
        return value
    end
    if type(value) == "string" then
        return { value }
    end
    return {}
end

--- Return an attribute as one string whatever lualdap returned
---
--- @param value string|table|boolean|nil Attribute value from a search
--- @return string|nil First value, or nil when absent
local function _value_first(value)
    if type(value) == "table" then
        return value[1]
    end
    if type(value) == "string" then
        return value
    end
    return nil
end

--- Return the DN two levels above a DN
---
--- Walks the DN by index and skips a comma preceded by a backslash, which is
--- an escaped comma inside a value rather than a separator.
---
--- Worked example: uid=jane,ou=people,o=Acme,dc=customers,dc=example,dc=org
---   after one separator:  ou=people,o=Acme,dc=customers,dc=example,dc=org
---   after two separators: o=Acme,dc=customers,dc=example,dc=org
---
--- @param dn string A DN with at least three components
--- @return string|nil The grandparent DN, or nil when the DN is too short
local function _dn_grandparent(dn)
    local separators_seen = 0
    for i = 1, #dn do
        if string.byte(dn, i) == byte_comma and string.byte(dn, i - 1) ~= byte_backslash then
            separators_seen = separators_seen + 1
            if separators_seen == 2 then
                return string.sub(dn, i + 1)
            end
        end
    end
    return nil
end

--- Read one entry by DN
---
--- @param ld table    lualdap connection
--- @param dn string   Entry DN
--- @param attrs table Attribute names to read
--- @return table|nil Attributes, or nil when the entry does not exist
--- @return string|nil Error
local function _entry_read(ld, dn, attrs)
    local iter, err = ld:search({
        base = dn,
        scope = "base",
        filter = "(objectClass=*)",
        attrs = attrs,
        sizelimit = 1,
        timeout = config.idp.ldap.timeout,
    })
    if not iter then
        return nil, err
    end
    local _, found = iter()
    return found
end

--- Look up a verified email address
---
--- Steps, see the numbered comments.
---
--- @param email string Address the broker verified
--- @return table|nil { sub, uid, dn, groups, grants, support_tier }, or nil
---                   when no person carries the address
--- @return string|nil Error, set only for a directory failure, not for an
---                    unknown address
function _M.lookup(email)
    local ldap = config.idp.ldap

    -- 1. Connect and bind. lualdap tries the space-separated URIs in order.
    local ld, err = lualdap.open_simple(table.concat(ldap.servers, " "), ldap.bind_dn, bind_pw, nil, ldap.timeout)
    if not ld then
        return nil, "cannot connect to directory: " .. (err or "unknown")
    end

    -- 2. Find the person by primary or alternate address.
    local escaped = _filter_escape(email)
    local iter
    iter, err = ld:search({
        base = ldap.base_dn,
        scope = "subtree",
        filter = "(&(objectClass=inetOrgPerson)(|(" .. ldap.attr_mail .. "=" .. escaped .. ")(" .. ldap.attr_mail_alternate .. "=" .. escaped .. ")))",
        attrs = { ldap.attr_uid, ldap.attr_member_of },
        sizelimit = 1,
        timeout = ldap.timeout,
    })
    if not iter then
        ld:close()
        return nil, "person search failed: " .. (err or "unknown")
    end
    local person_dn, person = iter()
    if not person_dn then
        ld:close()
        ngx.log(ngx.INFO, "no directory entry for ", email)
        return nil
    end

    local identity = {
        sub = email,
        uid = _value_first(person[ldap.attr_uid]),
        dn = person_dn,
        groups = _values_list(person[ldap.attr_member_of]),
        grants = {},
        support_tier = nil,
    }

    -- 3. The organisation is two levels above the person. Read the support
    --    agreement off it.
    local org_dn = _dn_grandparent(person_dn)
    local org
    if org_dn then
        org, err = _entry_read(ld, org_dn, { ldap.attr_support_active, ldap.attr_support_class })
        if err then
            ld:close()
            return nil, "organisation read failed: " .. err
        end
    end

    if org then
        -- 4. An agreement is active unless the attribute says FALSE, which is
        --    the reading the login gate applied before this module existed.
        --    An organisation with no attribute is treated as supported.
        local active = _value_first(org[ldap.attr_support_active])
        if active ~= "FALSE" then
            identity.grants[#identity.grants + 1] = _M.GRANT_SUPPORTED
        end

        -- 5. The tier is the cn of the entry the class attribute points at.
        local class_dn = _value_first(org[ldap.attr_support_class])
        if class_dn then
            local class
            class, err = _entry_read(ld, class_dn, { "cn" })
            if err then
                ld:close()
                return nil, "support class read failed: " .. err
            end
            if class then
                identity.support_tier = _value_first(class.cn)
            end
        end
    end

    ld:close()
    return identity
end

return _M
