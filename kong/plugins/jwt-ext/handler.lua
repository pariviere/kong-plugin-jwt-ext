-- If you're not sure your plugin is executing, uncomment the line below and restart Kong
-- then it will throw an error which indicates the plugin is being loaded at least.

--assert(ngx.get_phase() == "timer", "The world is coming to an end!")

---------------------------------------------------------------------------------------------
-- In the code below, just remove the opening brackets; `[[` to enable a specific handler
--
-- The handlers are based on the OpenResty handlers, see the OpenResty docs for details
-- on when exactly they are invoked and what limitations each handler has.
---------------------------------------------------------------------------------------------

local jwt_decoder_ext = require "kong.plugins.jwt-ext.jwt_parser_ext"
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local match = string.match
local noop = function() end

local plugin = {
  PRIORITY = 1004, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1", -- version in X.Y.Z format. Check hybrid-mode compatibility requirements.
}


local function iter(config_array)
  if type(config_array) ~= "table" then
    return noop
  end

  return function(config_array, i)
    i = i + 1

    local header_to_test = config_array[i]
    if header_to_test == nil then -- n + 1
      return nil
    end

    local header_to_test_name, header_to_test_value = match(header_to_test, "^([^:]+):*(.-)$")
    if header_to_test_value == "" then
      header_to_test_value = nil
    end

    return i, header_to_test_name, header_to_test_value
  end, config_array, 0
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the configured header_names (defaults to `[Authorization]`).
-- (copy from original jwt plugin)
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
  local args = kong.request.get_query()
  for _, v in ipairs(conf.uri_param_names) do
    if args[v] then
      return args[v]
    end
  end

  local var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local cookie = var["cookie_" .. v]
    if cookie and cookie ~= "" then
      return cookie
    end
  end

  local request_headers = kong.request.get_headers()
  for _, v in ipairs(conf.header_names) do
    local token_header = request_headers[v]
    if token_header then
      if type(token_header) == "table" then
        token_header = token_header[1]
      end
      local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
      if not iterator then
        kong.log.err(iter_err)
        break
      end

      local m, err = iterator()
      if err then
        kong.log.err(err)
        break
      end

      if m and #m > 0 then
        return m[1]
      end
    end
  end
end

local function set_claims_headers(claims, claims_headers)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  for _, claim_name, header_name in iter(claims_headers) do
    local claim_value = claims[claim_name]
    if  claim_value ~= nil then
      if type(claim_value) == "table" then
        set_header(header_name, table.concat(claim_value, ','))
      else
        set_header(header_name, claim_value)
      end
    else
      clear_header(header_name)
    end
  end
end



-- runs in the 'access_by_lua_block'
function plugin:access(conf)
  if #conf.scopes_required == 0 then
    kong.log.warn("jwt-ext plugin activated but no requirements defined: noop mode")
    return true
  end
  
  local token, err = retrieve_token(conf)
  if err then
    return error(err)
  end

  local token_type = type(token)
  if token_type ~= "string" then
    if token_type == "nil" then
      return kong.response.exit(401, {message = "Unauthorized" })
    elseif token_type == "table" then
      return kong.response.exit(401, {message = "Multiple tokens provided" })
    else
      return kong.response.exit(401, {message = "Unrecognizable token" })
    end
  end

  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder_ext:new(token)

  if err then
    return false, { status = 401, message = "Bad token; " .. tostring(err) }
  end


  local claims = jwt.claims

  if #conf.scopes_required > 0 then
    local ok, filtered_scopes = jwt:validate_scopes(conf.scopes_claim, conf.scopes_required)

    if not ok then
      return kong.response.exit(401, { message = "Invalid scope" })
    else
      claims['_validated_scope'] = table.concat(filtered_scopes, ',')
    end
  end

  set_claims_headers(claims, conf.claims_headers)

  return true
end --]]

return plugin
