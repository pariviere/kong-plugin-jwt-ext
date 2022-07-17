Kong jwt-ext plugin
====================

This repositoriy contains the source code of the Kong `jwt-ext` .

The `jwt-ext` plugin is intended to work alongside the [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) plugin and allows to :

 - validate scope claims
 - propage jwt claims as upstream headers

The bundled [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) plugin must still be used to verify the JWT token validity, algorithm and signature.


Quickstart
==========

 - Plugin installation:
   - either by `LuaRocks`
   - or by making this repository root directory added in `KONG_LUA_PACKAGE_PATH`
 - Load plugin in Kong by adding `jwt-ext` to `KONG_PLUGINS` and reload Kong instance
 - Configure your services / routes to use the `jwt-ext` plugin
 - The bundled [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) plugin must also be enabled to have proper validation of JWT token


The following is an example of usage of the `jwt-ext` plugin written in the declarative format.

```yaml
_format_version: "1.1"
consumers:
  - username: custom
    jwt_secrets:
      - key: mycustomjwtissuer
        algorithm: HS256
        secret: mysecretjwtsecret
services:
  - name: mockbin-request
    url: http://mockbin.org/request
    routes:
    - name: mockbin-request-route
      paths:
        - /request
    plugins:
      - name: jwt
        enabled: true
        config:
          key_claim_name: iss
          claims_to_verify:
            - exp
      - name: jwt-ext
        enabled: true
        config:
          scopes_claim: scope
          scopes_required: ['haveaccess']
```


 Access to the `mockbin-request-route` will be allowed only if:

 - The `iss` claim is equals to `mycustomjwtissuer` (bundled `jwt` plugin)
 - The signature is verified against `mysecretjwtsecret` and HS256 (bundled `jwt` plugin)
 - The `exp` claims is valid (bundled `jwt` plugin)
 - The `scope` claims contains `haveaccess` value (custom `jwt-ext` plugin)

Headers `x-jwt-iss`, `x-jwt-sub`, `x-jwt-scope` and 
`x-jwt-validated-scope` will be added to the upstream request with values corresponding respectively to `iss`, `sub` and `scope` claims. The `x-jwt-validated-scope` contains only scope which are validated against `scope_required` configuration value.



Plugin Configuration
====================

| Parameter | Description |
| -- | -- |
| uri_param_names | A list of querystring parameters that Kong will inspect to retrieve JWTs.<br>Defaults to `jwt`.<br>Works the same way as the  [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/)`|
| cookie_names | A list of cookie names that Kong will inspect to retrieve JWTs.<br>Works the same way as the  [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) |
| header_names | A list of HTTP header names that Kong will inspect to retrieve JWTs.<br>Defaults to `authorization`.<br>Works the same way as the  [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/)
| | |
| scopes_claim | The name of claims which must be validated.<br>Defaults to `scope` |
| scopes_required | <p>The scopes (<code>scopes_claim</code> claim) required to be present in the access token (or introspection results) for successful authorization. This config parameter works in both AND / OR cases.<ul><li>When <code>["scope1 scope2"]</code> are in the same array indices, both scope1 AND scope2 need to be present in access token (or introspection results).</li><li> When <code>["scope1", "scope2"]</code> are in different array indices, either scope1 OR scope2 need to be present in access token (or introspection results)</li></ul></p><p>It tries to mimic the scope claims validation rules of the [Kong Entreprise OpenID Connect Plugin](https://docs.konghq.com/hub/kong-inc/openid-connect/#claims-based-authorization) |
| claims_headers | A mapping between token claims and upstream headers.<br>Defaults to <code>["iss:x-jwt-iss", "sub:x-jwt-sub", "scope:x-jwt-scope", "_validated_scope:x-jwt-validated-scope"</code><br><br>The `_validated_scope` is a dynamic claims added by the plugin and  which contains the list of scope contained in `scopes_claim` and matching `scopes_required` rules handled by the plugin and contains the matching  |
| anonymous | An optional string (consumer uuid) value to use as an anonymous consumer if authentication fails. If empty (default), the request will fail with an authentication failure 4xx. The anonymous value must refer to the Consumer id attribute that is internal to Kong, and not its custom_id. |




Development
============

It is built with the [Kong Plugin Template](https://github.com/Kong/kong-plugin) and work with the [`kong-pongo`](https://github.com/Kong/kong-pongo) and
[`kong-vagrant`](https://github.com/Kong/kong-vagrant) development environments.


Caveats
=======

Duplicated configuration
------------------------

For most case `jwt` and `jwt-ext` plugin must be used together. If you change `uri_param_names`, `cookie_names` or `header_names` of the `jwt` plugin be sure to report the same configuration for the `jwt-ext` plugin.
JWT processing is handled by the bundle `jwt_parser` which is extend by the plugin. Bundled [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) `retrieve_token` function is copied.

Example:
```yaml
      - name: jwt
        enabled: true
        config:
          uri_param_names: accesstoken
          key_claim_name: iss
          claims_to_verify:
            - exp
      - name: jwt-ext
        enabled: true
        config:
          uri_param_names: accesstoken
          scopes_claim: scope
          scopes_required: ['haveaccess']
```
No JWT signature and reserved claims verification
-----------------------------------------------

JWT signature and reserved claims verification must be addressed by the bundled [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) plugin.

Updating Kong
-------------

This plugin has been tested from Kong 2.4.x to Kong 2.8.x but should works for each 2.x.

However it relies on some bundled [`jwt`](https://docs.konghq.com/hub/kong-inc/jwt/) plugin functions :

 - `jwt_parser`
 - `retrieve_token`

Future release of Kong might change this functions in a way which may broke this plugin.

Other
=====

This plugin is based on the works initiated with https://github.com/Kong/kong/pull/6875.




