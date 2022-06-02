local jwt_parser = require "kong.plugins.jwt.jwt_parser"
local utils = require "kong.tools.utils"

local split = utils.split


--- Verify the claim requirements
-- @param claim_raw claim value
-- @param requirement list of requirements : can be a plain string, a comma-separated string or a table
-- @return A Boolean indicating true if the scope are valid
-- @return A Table listing the matched requirements
local function claim_has_requirements(claim_raw, requirement)
  local requirement_type = type(requirement)

  if requirement_type == 'string' then
    local all = true
    local matches = {}

    for word in requirement:gmatch("[%w%p]+") do
      -- activate plain text matching
      -- to avoid interpretation of lua magic characters
      local match = claim_raw:find(word, 0, true) ~= nil
      if match then
        table.insert(matches, word)
      end
      all = all and match
    end
    return all, matches
  end

  if requirement_type  == 'table' then
    local any = false
    local matches = {}

    for _, item in pairs(requirement) do
      local hasMatch, local_matches = claim_has_requirements(claim_raw, item)
      any = any or hasMatch
      if hasMatch then
        for _, local_match in ipairs(local_matches) do
          table.insert(matches, local_match)
        end
      end
    end
    return any, matches
  end

  return false, {}
end


local _M = {}


_M.__index = _M

--- Instantiate a JWT parser
-- Parse a JWT and instantiate a JWT parser for further operations
-- Return errors instead of an instance if any encountered
-- @param token JWT to parse
-- @return JWT parser
-- @return error if any
function _M:new(token)
  local token, err = jwt_parser:new(token)

  if err then
    return nil, err
  end

  return setmetatable(token, _M)
end

--- Validate a scope claim against list of possibilities
-- @param scopes_claim name of the claim used as scope
-- @param scopes_required list of requirements for the scope value
-- @return A Boolean indicating true if the scope are valid
function _M:validate_scopes(scopes_claim, scopes_required)
  local claim_raw= self.claims[scopes_claim]
  local claim

  -- claim can be express as
  -- a single space separated string
  -- or a table of string
  if type(claim_raw) == "table" then
    claim = table.concat(claim_raw, ' ')
  else
    claim = claim_raw
  end


  if claim ~= nil then
    for _, scope_requirement in ipairs(scopes_required) do
      local matches
      local filtered_scopes
      local scope_requirement_type = type(scope_requirement)

      if scope_requirement_type == "string" and scope_requirement:find(',') then
        matches, filtered_scopes = claim_has_requirements(claim, split(scope_requirement, ','))
      else
        matches, filtered_scopes = claim_has_requirements(claim, scope_requirement)
      end

      if (matches) then
        -- First match win
        return matches, filtered_scopes
      end
    end
  end
  
  return false, {}
end

return _M
