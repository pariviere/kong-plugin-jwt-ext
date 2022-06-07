local helpers = require "spec.helpers"
local cjson   = require "cjson"


local PLUGIN_NAME = "jwt-ext"

local jwt_encoder = require("kong.plugins.jwt.jwt_parser")

function dump(o)
  if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
              if type(k) ~= 'number' then k = '"'..k..'"' end
              s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
  else
      return tostring(o)
  end
end


consumer_secret = "somethingnotusedwithjwt-ext"


allowed_scope = "allowed"
unknow_scope = "unknow"
issuer_claim = "issuer"
sub_claim = "jdoe"

jwt_allowed_scope_as_string = {
  iss = issuer_claim,
  sub = sub_claim,
  scope = allowed_scope
}

jwt_contains_allowed_scope_as_string = {
  iss = issuer_claim,
  sub = sub_claim,
  scope = allowed_scope .. unknow_scope
}

jwt_contains_allowed_scope_as_array = {
  iss = issuer_claim,
  sub = sub_claim,
  scope = { allowed_scope, unknow_scope }
}

jwt_unknow_scope_as_string = {
  iss = issuer_claim,
  sub = sub_claim,
  scope = unknow_scope
}

jwt_unknow_scope_as_array = {
  iss = issuer_claim,
  sub = sub_claim,
  scope = { unknow_scope }
}

function bearer_header(token)
  local jwt = jwt_encoder.encode(token, consumer_secret)
  return "Bearer " .. jwt
end


for _, strategy in helpers.all_strategies() do
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()

      local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })


      -- route1: test1.com
      -- no configuration: should do nothing
      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {},
      }


      -- route2: test2.com
      -- access only with giveaccess scope
      local route2 = bp.routes:insert({
        hosts = { "test2.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route2.id },
        config = {
          scopes_required= { allowed_scope }
        },
      }

      -- route3: test3.com
      -- access only with giveaccess scope
      -- no upstream headers sent
      local route3 = bp.routes:insert({
        hosts = { "test3.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route3.id },
        config = {
          scopes_required= { allowed_scope },
          claims_headers = {}
        },
      }

      -- route4: test4.com
      -- access only with giveaccess scope
      -- rename uupstream headers
      local route4 = bp.routes:insert({
        hosts = { "test4.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route4.id },
        config = {
          scopes_required= { allowed_scope },
          claims_headers = {
            "iss:x-renamed-iss",
            "sub:x-renamed-sub",
            "scope:x-renamed-scope",
            "_validated_scope:x-renamed-validated-scope"
          },
        },
      }

      -- route5: test5.com
      -- jwt plugin is required to validate access
      -- before jwt-ext plugin
      local route5 = bp.routes:insert({
        hosts = { "test5.com"},
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route5.id },
        config = {
          scopes_required= { allowed_scope }
        },
      }
      consumer1   = bp.consumers:insert({ username = "jwt_tests_consumer" })
      consumer1_jwt_secret        = bp.jwt_secrets:insert { consumer = { id = consumer1.id } }
      consumer1_jwt_secret_secret = consumer1_jwt_secret.secret
      consumer1_jwt_secret_key    = consumer1_jwt_secret.key

      bp.plugins:insert({
        name     = "jwt",
        route = { id = route5.id },
        config   = {header_names = { "authorization" }, key_claim_name = "iss"},
      })


      -- start kong
      assert(helpers.start_kong({
        -- set the strategy
        database   = strategy,
        -- use the custom test template to create a local mock server
        nginx_conf = "spec/fixtures/custom_nginx.template",
        -- make sure our plugin gets loaded
        plugins = "bundled," .. PLUGIN_NAME,
        -- write & load declarative config, only if 'strategy=off'
        declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    describe("#test1.com", function()
      local target_host = "test1.com"
      it("is allowed without token", function()
        local r = client:get("/request", {
          headers= {
            host = target_host
          }          
        })
        assert.response(r).has.status(200)
      end)

      it("is allowed with any token", function()
        for index, jwt_token in pairs({jwt_contains_allowed_scope_as_string, jwt_contains_allowed_scope_as_array, jwt_unknow_scope_as_array, jwt_unknow_scope_as_string}) do
          local r = client:get("/request", {
            headers= {
              host = target_host,
              authorization = bearer_header(jwt_token)
            }
          })
          assert.response(r).has.status(200)
        end
      end)

      it ("does not propagate claims headers to #upstream", function()
        for index, jwt_token in pairs({jwt_contains_allowed_scope_as_string, jwt_contains_allowed_scope_as_array, jwt_unknow_scope_as_array, jwt_unknow_scope_as_string}) do
          local r = client:get("/request", {
            headers= {
              host = target_host,
              authorization = bearer_header(jwt_token)
            }
          })
          assert.request(r).has.no.header("x-jwt-validated-scope")
          assert.request(r).has.no.header("x-jwt-scope")
          assert.request(r).has.no.header("x-jwt-iss") 
        end
      end)
    end)

    for index, target_host in pairs({"test2.com", "test3.com", "test4.com"}) do
      describe("#" .. target_host, function()
  
        it("is forbidden without token", function()
          local r = client:get("/request", {
            headers = {
              host = target_host
            }
          })
          assert.response(r).has.status(401)
        end)
  
        it("is allowed with allowed scope string", function()
          local r = client:get("/request", {
            headers = {
              host = target_host,
              authorization = bearer_header(jwt_allowed_scope_as_string)
            }
          })
          assert.response(r).has.status(200)
        end)
  
        it("is allowed with allowed scope array", function() 
          local r = client:get("/request", {
            headers = {
              host = target_host,
              authorization = bearer_header(jwt_contains_allowed_scope_as_array)
            }
          })
          assert.response(r).has.status(200)
        end)
  
        it("is forbidden with unknown scope string", function()
          local r = client:get("/request", {
            headers = {
              host = target_host,
              authorization = bearer_header(jwt_unknow_scope_as_string)
            }
          })
          assert.response(r).has.status(401)
        end)
  
        it("is forbidden with unknown scope array", function()
          local r = client:get("/request", {
            headers = {
              host = target_host,
              authorization = bearer_header(jwt_unknow_scope_as_array)
            }
          })
          assert.response(r).has.status(401)
        end)
      end)
    end

    describe("#test2.com", function()
      local target_host = "test2.com"
      it("propagates default claims headers to #upstream", function()
        local r = client:get("/request", {
          headers = {
            host = target_host,
            authorization = bearer_header(jwt_allowed_scope_as_string)
          }
        })
        local upstream_validated_scope = assert.request(r).has.header("x-jwt-validated-scope")
        local upstream_scope = assert.request(r).has.header("x-jwt-scope")
        local upstream_iss = assert.request(r).has.header("x-jwt-iss")

          
        assert.equals(allowed_scope, upstream_validated_scope)
        assert.equals(jwt_allowed_scope_as_string['scope'], upstream_scope)
        assert.equals(issuer_claim, upstream_iss)
      end)
    end)

    describe("#test3.com", function()
      local target_host = "test3.com"
      it("does not propagates default claims headers to #upstream", function()
        local r = client:get("/request", {
          headers = {
            host = target_host,
            authorization = bearer_header(jwt_allowed_scope_as_string)
          }
        })
        assert.request(r).has.no.header("x-jwt-validated-scope")
        assert.request(r).has.no.header("x-jwt-scope")
        assert.request(r).has.no.header("x-jwt-iss")
      end)
    end)

    describe("#test4.com", function()
      local target_host = "test4.com"
      it("propages custom claims headers to #upstream", function()
        local r = client:get("/request", {
          headers = {
            host = target_host,
            authorization = bearer_header(jwt_allowed_scope_as_string)
          }
        })
        assert.request(r).has.no.header("x-jwt-validated-scope")
        assert.request(r).has.no.header("x-jwt-scope")
        assert.request(r).has.no.header("x-jwt-iss")

        local upstream_validated_scope = assert.request(r).has.header("x-renamed-validated-scope")
        local upstream_scope = assert.request(r).has.header("x-renamed-scope")
        local upstream_iss = assert.request(r).has.header("x-renamed-iss")

        assert.equals(allowed_scope, upstream_validated_scope)
        assert.equals(jwt_allowed_scope_as_string['scope'], upstream_scope)
        assert.equals(issuer_claim, upstream_iss)
      end)
    end)

    describe("#test5.com", function()
      local target_host = "test5.com"

      it("is forbidden without token", function()
        local r = client:get("/request", {
          headers = {
            host = target_host
          }
        })
        assert.response(r).has.status(401)
      end)

      it("is forbidden if token is not verified by jwt plugin", function()
        for index, jwt_token in pairs({jwt_contains_allowed_scope_as_string, jwt_contains_allowed_scope_as_array, jwt_unknow_scope_as_array, jwt_unknow_scope_as_string}) do
          local r = client:get("/request", {
            headers= {
              host = target_host,
              authorization = bearer_header(jwt_token)
            }
          })

          assert.response(r).has.status(401)
        end
      end)

      it("is allowed if token is verified by jwt and jwt-ext plugin", function()

        for index, jwt_token in pairs({jwt_contains_allowed_scope_as_string, jwt_contains_allowed_scope_as_array}) do
          jwt_token.iss = consumer1_jwt_secret_key

          local customize_token = jwt_encoder.encode(jwt_token, consumer1_jwt_secret_secret)
          local r = client:get("/request", {
            headers= {
              host = target_host,
              authorization = customize_token
            }
          })
          -- FIXME: should be 200
          assert.response(r).has.status(200)
        end
      end)
    end)
  end)
end
