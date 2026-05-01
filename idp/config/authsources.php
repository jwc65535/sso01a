<?php
// =============================================================================
// idp/config/authsources.php — SimpleSAMLphp authentication sources
//
// Defines how the IdP authenticates users before issuing SAML assertions.
// The 'sso-ldap' source is the production auth method: it binds to OpenLDAP
// as the user (direct bind via dnpattern) to verify credentials, then fetches
// the user's attributes from their own LDAP entry.
//
// AUTHENTICATION FLOW
// ────────────────────
// 1. User submits uid + password on the IdP login form.
// 2. SSP constructs the user's DN: uid=<uid>,ou=users,<base>
// 3. SSP attempts LDAP bind as that DN with the supplied password.
//    (ACL: by anonymous auth — permits bind-for-authentication)
// 4. If bind succeeds, SSP reads the user's LDAP attributes using the
//    now-authenticated connection.
//    (ACL: by self write — alice can read her own entry after binding)
// 5. SSP releases the configured subset of attributes in the SAML assertion.
//
// SECURITY NOTES
// ───────────────
// • dnpattern bind avoids storing an LDAP admin credential in SSP config.
//   The IdP only ever authenticates AS the user — it has no broader LDAP access.
// • userPassword is never readable by SSP (ACL: by * none for reads);
//   the LDAP server performs the password check during the bind operation.
// • Binary attributes (userCertificate;binary) are listed explicitly so SSP
//   treats them as raw bytes, not UTF-8 strings. They are NOT released in the
//   SAML assertion (saml20-idp-hosted.php AttributeLimit filter strips them).
// • Username validation is enforced by the authproc filter in saml20-idp-hosted.php
//   before any attribute release.
// =============================================================================

declare(strict_types=1);

$ldapHost    = getenv('LDAP_HOST')    ?: 'ldap';
$ldapPort    = getenv('LDAP_PORT')    ?: '1389';
$ldapBaseDn  = getenv('LDAP_BASE_DN') ?: 'dc=sso,dc=local';

$config = [

    // ── LDAP authentication source ────────────────────────────────────────────
    // Key name 'sso-ldap' is referenced in saml20-idp-hosted.php as 'auth'.
    'sso-ldap' => [
        'ldap:LDAP',

        // ── Connection ────────────────────────────────────────────────────────
        // Plain LDAP on the Docker-internal ldap-net.  Switch to 'tls' and use
        // ldaps:// when the LDAP container has Vault-issued TLS certs.
        'connection_string' => sprintf('ldap://%s:%s', $ldapHost, $ldapPort),
        'encryption'        => 'none',   // PROD: 'tls' (requires LDAP TLS certs)
        'version'           => 3,
        'timeout'           => 5,
        'debug'             => false,

        // ── DN construction ───────────────────────────────────────────────────
        // Build the user's DN directly from the uid they enter.
        // SSP escapes %username% before substitution (LDAP DN safe string).
        // Requires that users log in with their uid (not email or cn).
        'dnpattern' => sprintf('uid=%%username%%,ou=users,%s', $ldapBaseDn),

        // ── Attribute retrieval ───────────────────────────────────────────────
        // null = fetch all attributes from the user's LDAP entry.
        // The authproc AttributeLimit filter in saml20-idp-hosted.php then
        // restricts which attributes are actually released in the assertion.
        'attributes'        => null,

        // Binary attributes must be listed explicitly.
        // userCertificate;binary is fetched but NOT released (stripped by
        // AttributeLimit); it's listed here so SSP doesn't corrupt the DER bytes.
        'attributes.binary' => ['userCertificate;binary'],

        // Attribute to use as the friendly username for display (not the NameID).
        'username_organization_method' => 'none',
    ],

];
