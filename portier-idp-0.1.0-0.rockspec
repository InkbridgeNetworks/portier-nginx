rockspec_format = "3.0"
package = "portier-idp"
version = "0.1.0-0"
source = {
  url = "/Users/arr2036/Documents/Repositories/nr_admin/portier-nginx/portier-idp-0.1.0-0.tar.gz"
}
description = {
  summary = "Identity provider side of portier single sign-on for OpenResty",
  detailed = [[
    Runs the portier broker login flow inside nginx: starts the login,
    verifies the broker's id_token post back, looks the verified address up
    in the directory for its identity and entitlements, and mints the
    ES256-signed session token that portier-sp verifies. Publishes the
    signing public key as a JWKS document. Ships the login page and the
    nginx location snippet the IdP vhost includes.
  ]],
  homepage = "https://github.com/NetworkRADIUS/portier-nginx",
  license = "AGPL-3.0"
}
dependencies = {
  "lua >= 5.1",
  "portier-sp",
  -- Directory lookup at login. A C rock: the host needs the OpenLDAP headers
  -- and a C toolchain at install time.
  "lualdap",
  -- MX lookup on the address domain before the broker is contacted.
  "lua-resty-dns",
}
build = {
   type = "builtin",
   modules = {
      ["portier.idp.directory"] = "src/portier/idp/directory.lua",
      ["portier.idp.email_validate"] = "src/portier/idp/email_validate.lua",
      ["portier.idp.init"] = "src/portier/idp/init.lua",
      ["portier.idp.jwks"] = "src/portier/idp/jwks.lua",
      ["portier.idp.login"] = "src/portier/idp/login.lua",
      ["portier.idp.logout"] = "src/portier/idp/logout.lua",
      ["portier.idp.verify"] = "src/portier/idp/verify.lua",
   },
   install = {
     conf = {
       ["nginx/portier-idp-http.conf"] = "etc/nginx/portier-idp-http.conf",
       ["nginx/portier-idp.conf"] = "etc/nginx/portier-idp.conf",
       ["webroot/index.html"] = "webroot/index.html"
     }
   }
}
