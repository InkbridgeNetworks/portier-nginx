-- Test overlay for portier.config. Both halves point at the same test key so
-- one process can mint and verify.
return {
    idp = {
        broker_url = "http://127.0.0.1:18081",
        public_origin = "http://127.0.0.1:18082",
        mx_check = false,
        landing_url = "https://rt.example.org/",
        ldap = {
            servers = { "ldap://127.0.0.1" },
            base_dn = "dc=example,dc=org",
            bind_dn = "cn=test,dc=example,dc=org",
        },
        token = {
            key_file = "/work/test/fixtures/es256-key.pem",
            lifetime = 60,
            audience = { "https://rt.example.org", "https://portal.example.org" },
        },
        cookie = { domain = "example.org" },
    },
    sp = {
        issuer = "http://127.0.0.1:18082",
        audience = "https://rt.example.org",
        cookie_domain = "example.org",
        anonymous = "pass",
        jwks_url = "file:///work/test/fixtures/jwks.json",
        login_url = "https://idp.example.org/.portier/login",
        policy = {
            grants_required = { "supported" },
            groups_denied = { "cn=employees,ou=groups,dc=example,dc=org" },
        },
        refusal_messages = {
            supported = "Your support contract has been suspended. Please contact acct@example.org for renewal.",
            groups_denied = "Staff log in to RT directly.",
        },
    },
}
