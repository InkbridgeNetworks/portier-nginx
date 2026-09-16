-- Email address syntax check
--
-- based on https://gist.github.com/james2doyle/67846afd05335822c149
--
-- The final pattern also forbids the characters ( ) * \ and other punctuation
-- that is unsafe in an LDAP search value, because the address is used as a
-- filter value by the directory lookup.

local _M = {}

function _M.validemail(str)
  if (type(str) ~= 'string') then
    return nil, "Expected string"
  end
  local lastAt = str:find("[^%@]+$")
  if (lastAt == nil) then lastAt = #str + 1 end -- https://gist.github.com/james2doyle/67846afd05335822c149#gistcomment-2568897
  local localPart = str:sub(1, (lastAt - 2)) -- Returns the substring before '@' symbol
  local domainPart = str:sub(lastAt, #str) -- Returns the substring after '@' symbol
  -- we werent able to split the email properly
  if localPart == nil then
    return nil, "Local name is invalid"
  end

  if domainPart == nil then
    return nil, "Domain is invalid"
  end
  -- local part is maxed at 64 characters
  if #localPart > 64 then
    return nil, "Local name must be less than 64 characters"
  end
  -- domains are maxed at 253 characters
  if #domainPart > 253 then
    return nil, "Domain must be less than 253 characters"
  end
  -- somthing is wrong
  if lastAt >= 65 then
    return nil, "Invalid @ symbol usage"
  end
  -- quotes are only allowed at the beginning of a the local name
  local quotes = localPart:find("[\"]")
  if type(quotes) == 'number' and quotes > 1 then
    return nil, "Invalid usage of quotes"
  end
  -- no @ symbols allowed outside quotes
  if localPart:find("%@+") and quotes == nil then
    return nil, "Invalid @ symbol usage in local part"
  end
  -- no whitespace symbols allowed outside quotes
  if localPart:find("%s+") and quotes == nil then
    return nil, "Invalid whitespace usage in local part"
  end
  -- no dot found in domain name
  if not domainPart:find("%.") then
    return nil, "No TLD found in domain"
  end
  -- only 1 period in succession allowed
  if domainPart:find("%.%.") then
    return nil, "Too many periods in domain"
  end
  if localPart:find("%.%.") then
    return nil, "Too many periods in local part"
  end
  -- forbid the characters that are unsafe in an LDAP search value
  if not str:match("^[A-Za-z0-9.!#$%%&'+/=?^_{|}~-]+@[A-Za-z0-9.-]+%.[A-Za-z]+$") then
    return nil, "Email pattern test failed"
  end
  -- all our tests passed, so we are ok
  return true, domainPart
end

return _M
