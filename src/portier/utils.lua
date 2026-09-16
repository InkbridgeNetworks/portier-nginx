-- Helpers shared by the identity provider and the service provider
--
-- The module holds functions over plain Lua values, plus the nginx wrappers
-- that both rocks need. The module depends on nothing else in portier, so
-- `portier.config` can call the module while `portier.config` itself loads.
-- The `portier-sp` rock contains the module, and the `portier-idp` rock
-- depends on the `portier-sp` rock.

local _M = {}

--- Read a whole file
---
--- @param path string Path of the file
--- @return string|nil Contents, or nil on error
--- @return string|nil Error, which names the path
function _M.file_read(path)
    local f, err = io.open(path, "r")
    if not f then
        return nil, "cannot open " .. path .. ": " .. err
    end
    local data = f:read("*a")
    f:close()
    return data
end

--- Whether a table is a map, a table with at least one non-integer key
---
--- @param t table
--- @return boolean
local function _is_map(t)
    for k in pairs(t) do
        if type(k) ~= "number" then
            return true
        end
    end
    return false
end

--- Overlay `override` onto `base` in place
---
--- A map in `override` merges into the map at the same key in `base`,
--- recursively. Every other value replaces: a scalar, a list, and an empty
--- table. So an override that sets a list replaces the whole list, and a
--- list shorter than the default does not keep the default's tail.
---
--- Worked example: base { ldap = { timeout = 5, servers = { "a", "b" } } },
--- override { ldap = { servers = { "c" } } }
---   result { ldap = { timeout = 5, servers = { "c" } } }
---
--- @param base table     Table that receives the values
--- @param override table Table whose values win
function _M.table_merge(base, override)
    for k, v in pairs(override) do
        if type(v) == "table" and type(base[k]) == "table" and _is_map(v) then
            _M.table_merge(base[k], v)
        else
            base[k] = v
        end
    end
end

--- Normalise a value that may be one string or a list of strings to a list
---
--- A config file may hold one string where the setting accepts a list.
--- lualdap returns a string for one attribute value, a table for several,
--- and true for an attribute that is present with no values. Every
--- consumer then reads a list.
---
--- @param value string|table|boolean|nil The value
--- @return table List, empty when the value is neither a string nor a table
function _M.list_normalise(value)
    if type(value) == "table" then
        return value
    end
    if type(value) == "string" then
        return { value }
    end
    return {}
end

--- Return the first string of a value that may be a string or a list of strings
---
--- @param value string|table|boolean|nil The value
--- @return string|nil First string, or nil when the value holds no string
function _M.list_first(value)
    if type(value) == "table" then
        return value[1]
    end
    if type(value) == "string" then
        return value
    end
    return nil
end

--- Turn a list of strings into a set keyed by each string
---
--- @param list table List of strings
--- @return table Set, value true for every member
function _M.set_from_list(list)
    local set = {}
    for i = 1, #list do
        set[list[i]] = true
    end
    return set
end

--- Stop nginx at init with a message that names the component and the problem
---
--- @param component string Component that prefixes the message, such as
---                         "portier config"
--- @param msg string       What is wrong
function _M.fail(component, msg)
    ngx.log(ngx.EMERG, component, ": ", msg)
    error(component .. ": " .. msg)
end

--- Stop nginx at init when a required setting is unset
---
--- A nil or empty-string value counts as unset.
---
--- @param value any        Setting value
--- @param name string      Setting name for the message
--- @param component string Component that prefixes the message, such as
---                         "portier idp"
function _M.setting_require(value, name, component)
    if value == nil or value == "" then
        _M.fail(component, name .. " is not set in conf.lua")
    end
end

--- Return a request argument as a string, or nil
---
--- nginx passes a repeated argument to Lua as a table and a bare `?name` as
--- `true`. Every argument that a phase reads goes through this function, so
--- the phase refuses a request that carries either form rather than raising
--- an error inside the phase.
---
--- @param value any Value from `ngx.req.get_uri_args` or `ngx.req.get_post_args`
--- @return string|nil The argument, or nil when the value is not a string
function _M.arg_string(value)
    if type(value) == "string" then
        return value
    end
    return nil
end

--- Quote a request-supplied value for a log line
---
--- @param value any Value from the request
--- @return string Lua-quoted form, control characters escaped
function _M.log_quote(value)
    return string.format("%q", tostring(value))
end

--- Decode base64url
---
--- @param s64url string base64url text
--- @return string|nil Decoded bytes, or nil when the text is not base64url
function _M.base64url_decode(s64url)
    local s64 = s64url:gsub("-", "+"):gsub("_", "/")
    local pad = #s64 % 4
    if pad > 0 then
        s64 = s64 .. string.rep("=", 4 - pad)
    end
    return ngx.decode_base64(s64)
end

--- Expire a cookie in the browser
---
--- The browser identifies a cookie by name, domain, and path. `attributes`
--- must repeat the `Domain` and `Path` from the `Set-Cookie` header that
--- created the cookie. Otherwise the browser keeps the real cookie and gains
--- an empty cookie.
---
--- @param name string       Cookie name
--- @param attributes string Cookie attributes, "; " separated, such as
---                          "Domain=example.org; Path=/; HttpOnly; Secure"
function _M.cookie_clear(name, attributes)
    ngx.header["Set-Cookie"] = name .. "=; " .. attributes .. "; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
end

return _M
