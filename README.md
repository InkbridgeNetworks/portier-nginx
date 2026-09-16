# portier-nginx

portier-nginx provides single sign-on for nginx applications, built on the
[Portier](https://portier.github.io/) broker. The broker proves that a user
owns an email address. portier-nginx turns the proof into a signed session
token. Any nginx server in the deployment verifies the token without
contacting the broker or the Lightweight Directory Access Protocol (LDAP)
directory again.

This repository builds two LuaRocks packages (rocks):

 * **`portier-idp`**, the identity provider. The identity provider runs the
   broker login flow and looks the verified email address up in an LDAP
   directory. The lookup yields the identity and entitlements of the user.
   The identity provider then mints the session token and publishes the
   public key that verifies the token.
 * **`portier-sp`**, the service provider. The service provider verifies the
   session token on every request to a protected application, applies the
   policy of the application to the claims, and passes the application a
   `REMOTE_USER`.

[NetworkRADIUS](https://networkradius.com/) sponsors the project.

# How a login works

1. The browser asks for a protected page on a service provider. The request
   does not carry a session cookie, so the service provider answers according
   to `sp.anonymous`. The service provider either returns status 401 or
   redirects the browser to the login page of the identity provider with the
   page URL in `return_to`.
2. The user types an email address on the login page. The identity provider
   accepts the login start only from its own pages or from a service provider
   under the same site, by the `Sec-Fetch-Site` header or, for a browser
   without that header, by the `Referer`. A page on another site cannot start
   a login in the browser. The identity provider then checks the email
   address, sets a short-lived cookie that holds a nonce and the return URL,
   and sends the browser to the broker. The identity provider accepts a
   `return_to` only when the origin of the URL is one of the audiences in
   `idp.token.audience` or the identity provider itself.
3. The broker verifies the email address and posts an RS256 `id_token` back
   to the verify location of the identity provider.
4. The identity provider verifies the `id_token` against the published keys
   of the broker, matches the nonce, and looks the email address up in the
   directory. From the person entry, the identity provider reads the `uid`
   and the group memberships. From the organisation entry two levels above
   the person, the identity provider reads the support agreement state and
   the support tier. An agreement that is not marked inactive yields the
   `supported` grant. When the directory has no person entry for the email
   address, the identity provider does not mint a token.
5. The identity provider mints an ES256 session token with the claims from
   step 4. The identity provider sets the token as an `HttpOnly`, `Secure`,
   `SameSite=Lax` cookie on the shared parent domain, then redirects the
   browser to the return URL.
6. Every request to a service provider now carries the cookie. The service
   provider verifies the signature against the JSON Web Key Set (JWKS) of the
   identity provider, then checks `iss`, `aud`, `iat`, `exp`, and that the
   lifetime does not exceed `sp.max_lifetime`. The service provider then
   applies the policy of the application, strips the cookie from the
   `Cookie` header, and sets `$portier_nginx_uid`. The site passes
   `$portier_nginx_uid` to the application as `REMOTE_USER`. When the token
   holder is in a denied group and `sp.anonymous` is `pass`, the service
   provider expires the cookie and continues without an identity, so the
   holder reaches the application's own login rather than a refusal for the
   life of the token. A missing grant is refused with status 403 in every
   mode.

The identity provider asserts who the user is and what the user is entitled
to. Each service provider decides which users to admit. A customer whose
support agreement has lapsed still receives a token, but the token does not
carry the `supported` grant. A support portal can therefore admit the
customer while a ticketing system refuses the customer with a renewal
message.

# Token

    header:  { typ = "JWT", alg = "ES256", kid = <key id> }
    payload: { iss, aud = { <audience>, ... }, iat, exp,
               sub = <email>, uid, groups = { <dn>, ... },
               grants = { <grant>, ... }, support_tier }

`aud` is always a list. Both the identity provider and the service provider
check that the token header names ES256 before reading any key. Both
therefore refuse a token that names HS256 before reading a key. The identity
provider derives the key id from the public key unless `idp.token.kid` sets
the key id.

# Layout

The Lua modules are in `src/portier`.

 * **`config.lua`:** merges the built-in defaults with the `portier/conf.lua`
   of the deployment. The deployment puts `portier/conf.lua` on
   `lua_package_path`.
 * **`token.lua`:** loads the signing key, mints the session token, defines the
   claim specification, and verifies the session token.
 * **`utils.lua`:** holds the helpers that both rocks share: file reading,
   list handling, stopping nginx at init, the required-setting check, request
   argument checking, log quoting, base64url decoding, and cookie expiry.
 * **`sp/init.lua`:** builds the service provider state once per worker.
 * **`sp/jwks.lua`:** fetches and caches the JWKS of the identity provider.
 * **`sp/access.lua`:** runs the access phase for a protected location.
 * **`idp/init.lua`:** builds the identity provider state, including the
   signing key, once per worker.
 * **`idp/login.lua`:** starts the broker login flow.
 * **`idp/verify.lua`:** verifies the `id_token` that the broker posts back,
   looks the email address up in the directory, and mints the session
   cookie.
 * **`idp/directory.lua`:** looks the email address up in the directory and
   returns the identity and entitlements of the user.
 * **`idp/jwks.lua`:** publishes the public key.
 * **`idp/logout.lua`:** clears the session cookie.
 * **`idp/email_validate.lua`:** checks the syntax of an email address.

`etc/nginx/` holds the snippets that a virtual host (vhost) includes.
`portier-sp-http.conf` goes in the http block of a service provider.
`portier-idp-http.conf` and `portier-idp.conf` go in the http and server
blocks of the identity provider. `portier-example.conf` is a complete sample
that includes the identity provider snippets and the service provider
snippet.

`webroot/index.html` is the login page. A deployment may point the login
location at a branded copy.

# Requirements

Both rocks need OpenResty, or nginx with the Lua module running on LuaJIT.
The rockspecs install the Lua dependencies: `lua-resty-jwt`,
`lua-resty-openssl`, `lua-resty-http`, `lua-resty-string`, and `lua-cjson`
for both rocks, plus `lualdap` and `lua-resty-dns` for the identity
provider. `lualdap` contains C code and needs the OpenLDAP headers and a C
toolchain at install time.

# Deploy

## Both rocks

1. Run `luarocks install portier-sp` on every service provider host, and run
   `luarocks install portier-idp` on the identity provider host.
2. Write `/etc/portier/portier/conf.lua`. The file returns a table whose keys
   override the defaults in `src/portier/config.lua`. `src/portier/config.lua`
   documents every key. A deployment-specific key does not have a default,
   so `conf.lua` must set the directory servers, the cookie domain, the key
   path, the audiences, and the policy.
3. Add `/etc/portier` to `lua_package_path`, so nginx finds `conf.lua` as the
   module `portier.conf`:

       lua_package_path '/etc/portier/?.lua;;';

4. Load the service provider state at startup, so a bad key or a bad config
   stops nginx at startup rather than failing the first request:

       init_by_lua_block { require "portier.sp.init" }

   On the identity provider, require `portier.idp.init` instead. nginx
   allows one `init_by_lua_block` per http block, so the snippets do not
   include the `init_by_lua_block` directive.

## Identity provider

1. Generate a P-256 key and write the PEM file to the path that
   `idp.token.key_file` names. Make the file readable by the nginx worker
   user only:

       openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out /etc/portier/signing_key.pem

2. Write the directory bind password, as one line, to the path that
   `idp.ldap.bind_pw_file` names.
3. Include `portier-idp-http.conf` in the http block, and include
   `portier-idp.conf` in the server block that answers on the origin of the
   identity provider. Set `idp.public_origin` in `conf.lua` to the origin the
   browser sees, and `idp.cookie.domain` to the parent domain the identity
   provider shares with the service providers. nginx does not start while
   either is unset.
4. Register the origin with the broker as an allowed origin.

## Service provider

1. Include `portier-sp-http.conf` in the http block.
2. In every protected location, declare `$portier_nginx_uid` and
   `$portier_nginx_email`, run the access phase, and pass the uid to the
   application as `REMOTE_USER`:

       location / {
           set $portier_nginx_uid "";
           set $portier_nginx_email "";
           access_by_lua_block { require("portier.sp.access").run() }
           fastcgi_param REMOTE_USER $portier_nginx_uid;
           ...
       }

3. In `conf.lua`, set `sp.jwks_url` to the JWKS URL of the identity
   provider, `sp.issuer` to the origin of the identity provider,
   `sp.audience` to the audience of the application, and `sp.cookie_domain`
   to the same parent domain as `idp.cookie.domain`, so the service provider
   can expire the cookie the identity provider set. Then set the policy:
   `sp.policy.grants_required`, `sp.policy.groups_denied`, and a refusal
   message per grant in `sp.refusal_messages`.

To log a user out, send the browser to `/.portier/logout` on the identity
provider.

# Development

`test/run.sh` runs the test specifications (specs) under OpenResty in a
container and needs docker. On the first run, `test/run.sh` generates a test
signing key and a broker key.

 * **`test/token_spec.lua`:** tests the token module in-process.
 * **`test/sp_spec.sh`:** runs curl against a service provider vhost in
   `deny` mode.
 * **`test/sp_pass_spec.sh`:** runs curl against a second service provider
   vhost in `pass` mode.
 * **`test/idp_spec.sh`:** runs curl against an identity provider vhost that
   uses a broker stub and a directory stub, then presents the minted cookie
   to the service provider vhost.

`make` builds both rocks from the source tree. `make check` syntax-checks
every module.
