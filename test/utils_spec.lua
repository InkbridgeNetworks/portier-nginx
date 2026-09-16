-- `utils_spec.lua` exercises the value helpers of `portier.utils` that both
-- rocks share, under OpenResty. Run through `test/run.sh`. The nginx wrappers
-- (`cookie_clear`) need a request, so `sp_spec.sh` and `idp_spec.sh` cover
-- the wrappers.

package.path = "/work/src/?.lua;/work/test/?.lua;" .. package.path

local utils = require "portier.utils"

local failures = 0

local function check(name, ok, detail)
    if ok then
        print("ok   " .. name)
    else
        failures = failures + 1
        print("FAIL " .. name .. (detail and (": " .. tostring(detail)) or ""))
    end
end

-- 1. file_read returns the contents, or an error that names the path.
local data, err = utils.file_read("/work/test/utils_spec.lua")
check("file_read reads a file", data ~= nil and data:find("portier.utils", 1, true) ~= nil, err)
data, err = utils.file_read("/work/test/does-not-exist")
check("file_read missing file is nil", data == nil)
check("file_read error names the path", err ~= nil and err:find("/work/test/does-not-exist", 1, true) ~= nil, err)

-- 2. table_merge merges sub-tables and replaces lists and scalars.
local base = { a = { x = 1, y = 2 }, list = { "one", "two" }, s = "old" }
utils.table_merge(base, { a = { y = 3, z = 4 }, list = { "three" }, s = "new" })
check("table_merge keeps untouched key", base.a.x == 1)
check("table_merge overrides nested scalar", base.a.y == 3)
check("table_merge adds nested key", base.a.z == 4)
check("table_merge replaces a list", #base.list == 1 and base.list[1] == "three")
check("table_merge replaces a scalar", base.s == "new")
utils.table_merge(base, { a = {} })
check("table_merge replaces with an empty table", next(base.a) == nil)

-- 3. list_normalise turns a string, a table, nil, and lualdap's true into lists.
local one = utils.list_normalise("only")
check("list_normalise wraps a string", #one == 1 and one[1] == "only")
local several = { "a", "b" }
check("list_normalise returns a table as is", utils.list_normalise(several) == several)
check("list_normalise nil is empty", #utils.list_normalise(nil) == 0)
check("list_normalise true is empty", #utils.list_normalise(true) == 0)

-- 4. list_first returns the first member of a list, the string for a string, and nil otherwise.
check("list_first of a list", utils.list_first({ "a", "b" }) == "a")
check("list_first of a string", utils.list_first("a") == "a")
check("list_first of nil", utils.list_first(nil) == nil)
check("list_first of true", utils.list_first(true) == nil)
check("list_first of an empty list", utils.list_first({}) == nil)

-- 5. set_from_list keys the set by the strings.
local set = utils.set_from_list({ "cn=a", "cn=b" })
check("set_from_list members are true", set["cn=a"] == true and set["cn=b"] == true)
check("set_from_list non-member is nil", set["cn=c"] == nil)
check("set_from_list of an empty list", next(utils.set_from_list({})) == nil)

-- 6. arg_string passes a string and refuses nginx's table and true forms.
check("arg_string passes a string", utils.arg_string("x") == "x")
check("arg_string refuses a repeated argument", utils.arg_string({ "x", "y" }) == nil)
check("arg_string refuses a bare argument", utils.arg_string(true) == nil)
check("arg_string of nil", utils.arg_string(nil) == nil)

-- 7. log_quote quotes and escapes control characters, whatever the type.
check("log_quote quotes a string", utils.log_quote("abc") == '"abc"')
check("log_quote escapes a newline", utils.log_quote("a\nb") == '"a\\\nb"')
check("log_quote of a number", utils.log_quote(12) == '"12"')
check("log_quote of nil", utils.log_quote(nil) == '"nil"')

-- 8. base64url_decode restores padding and maps the URL alphabet to the standard alphabet.
check("base64url_decode without padding", utils.base64url_decode("aGVsbG8") == "hello")
check("base64url_decode URL alphabet", utils.base64url_decode("_-8") == "\255\239")
check("base64url_decode invalid is nil", utils.base64url_decode("!!!") == nil)

-- 9. fail and setting_require raise an error that names the component.
local ok, ferr = pcall(utils.fail, "portier test", "broken")
check("fail raises", not ok)
check("fail names the component", tostring(ferr):find("portier test: broken", 1, true) ~= nil, ferr)
ok, ferr = pcall(utils.setting_require, "", "sp.issuer", "portier sp")
check("setting_require refuses an empty string", not ok)
check("setting_require names the setting", tostring(ferr):find("portier sp: sp.issuer is not set in conf.lua", 1, true) ~= nil, ferr)
ok, ferr = pcall(utils.setting_require, nil, "sp.issuer", "portier sp")
check("setting_require refuses nil", not ok)
check("setting_require passes a value", pcall(utils.setting_require, "x", "sp.issuer", "portier sp"))

if failures > 0 then
    print(failures .. " failure(s)")
    os.exit(1)
end
print("all utils checks passed")
