local typedefs = require "kong.db.schema.typedefs"


local PLUGIN_NAME = "jwt-ext"


local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        fields = {
          { uri_param_names = {
            type = "set",
            elements = { type = "string" },
            default = { "jwt" },
          }, },
          { cookie_names = {
              type = "set",
              elements = { type = "string" },
              default = {}
          }, },
          { header_names = {
            type = "set",
            elements = { type = "string" },
            default = { "authorization" },
          }, },
          { scopes_claim = { type = "string", default = "scope" }, },
          { scopes_required = {
            type = "set",
            elements = { type = "string" },
            default = {}
          }, },
          { claims_headers =  {
            type = "array",
            default = {
              "iss:x-jwt-iss",
              "sub:x-jwt-sub",
              "scope:x-jwt-scope",
              "_validated_scope:x-jwt-validated-scope"
            },
            required = true,
            elements = { type = "string", match = "^[^:]+:.*$" },
          }, },
        }
      },
    },
  },
}

return schema
