-- Effective portier config: built-in defaults overlaid with the deployment's
-- conf.lua, found on lua_package_path as the module `portier.conf`. conf.lua
-- returns a partial table; any key it sets wins. Sub-tables merge, scalars and
-- arrays replace. Same pattern as the cinfra-deploy rock's config.lua.
--
-- The defaults below are generic values only. Nothing deployment-specific
-- lives here: directory servers, the cookie domain, the signing key path, the
-- audience, group names and refusal messages all come from conf.lua.
--
-- The table has two halves. `idp` configures the identity provider, which
-- runs the broker login flow, looks the user up in the directory and mints
-- the session token. `sp` configures a service provider, which verifies the
-- session token on every request and applies its own policy to the claims.
-- One host may load both halves; a service provider host loads only `sp`.

local utils = require "portier.utils"

local defaults = {
    idp = {
        -- Public URL of the portier broker that verifies email ownership. The
        -- IdP is a relying party of the broker. Also the `iss` the broker's
        -- id_token must carry.
        broker_url = "https://broker.portier.io",

        -- Origin of the identity provider as the browser sees it, scheme and
        -- host: the broker client_id, the id_token audience, and the `iss` of
        -- the minted tokens. nil derives it from the request, which is right
        -- only when this nginx terminates TLS itself. Behind a proxy that
        -- terminates TLS, set it, such as "https://portier.example.org".
        public_origin = nil,

        -- Refuse an address whose domain accepts no mail, by MX lookup,
        -- before the broker is contacted. Off for a deployment with no DNS
        -- egress from the IdP host, or for a test.
        mx_check = true,

        -- Resolvers the MX lookup queries.
        nameservers = { "1.1.1.1", "1.0.0.1" },

        -- Directory lookup that turns the verified email address into an
        -- identity and its entitlements. servers, base_dn and bind_dn have no
        -- default; conf.lua supplies them.
        ldap = {
            -- LDAP URIs, tried in order.
            servers = {},
            base_dn = nil,
            bind_dn = nil,
            -- File holding the bind password, one line. Rendered by salt or
            -- served by cinfra-secretd; never inline in conf.lua.
            bind_pw_file = "/etc/portier/ldap_secret",
            -- Seconds a directory search may take before the login fails.
            timeout = 2,
            -- Attributes read from the person entry.
            attr_uid = "uid",
            attr_mail = "mail",
            attr_mail_alternate = "gosaMailAlternateAddress",
            attr_member_of = "memberOf",
            -- Attributes read from the organisation entry that owns the
            -- person. The organisation is the entry named by the third
            -- component of the person's DN.
            attr_support_active = "supportAgreementIsActive",
            -- A DN naming a supportClass entry. The tier written into the
            -- token is that entry's cn, such as Silver, Gold or Platinum.
            attr_support_class = "supportAgreementClass",
        },

        -- The session token the IdP mints after the directory lookup.
        token = {
            -- PEM file holding the ES256 private key. Rendered by salt from a
            -- sealed pillar or served by cinfra-secretd.
            key_file = "/etc/portier/signing_key.pem",
            -- Key id written to the token header and the JWKS document. nil
            -- derives it from a hash of the public key at init.
            kid = nil,
            -- Seconds a token stays valid. 18 hours, the lifetime the HMAC
            -- cookie had.
            lifetime = 64800,
            -- `iss` claim. nil uses the scheme and host the login arrived on.
            issuer = nil,
            -- `aud` claim: every service provider the token is good for.
            audience = {},
        },

        -- The cookie that carries the token to the browser.
        cookie = {
            name = "portier_session",
            -- Parent domain shared by the IdP and every service provider.
            -- No default: a cookie without a Domain reaches only the IdP host.
            domain = nil,
            path = "/",
            same_site = "Lax",
        },

        -- Where the IdP publishes its public key, relative to the IdP origin,
        -- and the max-age a service provider may cache the document for.
        jwks_path = "/.portier/jwks.json",
        jwks_max_age = 600,

        -- Seconds the browser has to complete the broker round trip. Bounds
        -- the login cookie that carries the nonce and return URL.
        login_timeout = 600,

        -- Where the browser lands after a successful login when the login
        -- request carried no return URL, or a URL that is not an audience.
        landing_url = "/",
    },

    sp = {
        -- Cookie the token arrives in. Must match idp.cookie.name, and the
        -- domain must match idp.cookie.domain so the SP can expire the cookie
        -- the IdP set. No default for the domain.
        cookie_name = "portier_session",
        cookie_domain = nil,

        -- Absolute URL of the IdP's JWKS document, https:// or file:// for an
        -- offline test, and how long a fetched document is cached in the
        -- `portier_jwks` shared dict. The site's nginx config declares the
        -- dict: `lua_shared_dict portier_jwks 1m;`.
        jwks_url = nil,
        jwks_cache_ttl = 600,
        -- Seconds a kid that is not in the key set stays remembered as
        -- missing, so a flood of tokens with made-up kids costs one fetch per
        -- window rather than one per request.
        jwks_miss_ttl = 30,

        -- Longest token lifetime, exp minus iat, the SP accepts. Caps a
        -- misconfigured identity provider. Matches idp.token.lifetime.
        max_lifetime = 64800,

        -- `iss` the token must carry, and the audiences this service provider
        -- answers to: the token's `aud` list must contain one of them. No
        -- default; conf.lua supplies them.
        issuer = nil,
        audience = {},

        -- What the access phase does with a request that carries no valid
        -- token. "deny" answers 401. "redirect" sends a browser to
        -- `login_url` with the request URL in `return_to`, so the identity
        -- provider can send the browser back after login. "pass" lets the
        -- request through with no identity set, which is what the HMAC
        -- cookie flow did, and leaves the decision to the application.
        anonymous = "deny",

        -- Login URL on the identity provider, used by "redirect". No default;
        -- conf.lua supplies it.
        login_url = nil,

        -- Claims the SP requires before the request is let through.
        policy = {
            -- Every grant listed here must appear in the token's `grants`.
            grants_required = {},
            -- A token whose `groups` names any DN listed here is refused.
            groups_denied = {},
        },

        -- Body returned with a 403 when policy refuses the token, keyed by the
        -- grant that was missing. conf.lua supplies the texts. A refusal for
        -- a denied group uses `groups_denied`.
        refusal_messages = {},

        -- nginx variables the access phase sets for the upstream. The
        -- application reads the uid as REMOTE_USER through fastcgi_param or
        -- proxy_set_header in the site's nginx config.
        var_uid = "portier_nginx_uid",
        var_email = "portier_nginx_email",
    },
}

-- conf.lua's location is resolved off lua_package_path rather than hardcoded:
-- the deployment puts its directory on the path, so no absolute path is baked
-- in. Salt renders the file for a host; the container image copies it in.
local CONF_MODULE = "portier.conf"

--- Component name that prefixes every config failure message
local COMPONENT = "portier config"

local conf_path, search_err = package.searchpath(CONF_MODULE, package.path)
if not conf_path then
    utils.fail(COMPONENT, "conf.lua not found on lua_package_path as portier.conf: " .. (search_err or ""))
end

local chunk, load_err = loadfile(conf_path)
if not chunk then
    utils.fail(COMPONENT, "cannot load " .. conf_path .. ": " .. load_err)
end

local override = chunk()
if type(override) ~= "table" then
    utils.fail(COMPONENT, conf_path .. " must return a table")
end
-- `table_merge` merges sub-tables and replaces lists. A conf.lua that sets
-- `idp.nameservers` replaces the whole default list rather than appending to
-- the default list.
utils.table_merge(defaults, override)

-- conf.lua may set `audience = "https://rt.example.org"` for one audience or
-- a list for several. `list_normalise` turns each setting below into a list,
-- so every consumer reads a list.
defaults.idp.ldap.servers = utils.list_normalise(defaults.idp.ldap.servers)
defaults.idp.token.audience = utils.list_normalise(defaults.idp.token.audience)
defaults.sp.audience = utils.list_normalise(defaults.sp.audience)
defaults.sp.policy.grants_required = utils.list_normalise(defaults.sp.policy.grants_required)
defaults.sp.policy.groups_denied = utils.list_normalise(defaults.sp.policy.groups_denied)

return defaults
