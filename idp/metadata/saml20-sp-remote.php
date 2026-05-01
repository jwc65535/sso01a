<?php
// =============================================================================
// idp/metadata/saml20-sp-remote.php — Shibboleth SP trusted metadata
//
// Tells the IdP which Service Providers are trusted to receive SAML assertions.
// Only SPs listed here will have their AuthnRequests accepted.
//
// SP SIGNING CERTIFICATE
// ───────────────────────
// The 'certData' field below holds the Shibboleth SP's own signing/encryption
// certificate (base64-encoded DER, no PEM headers).
//
// How to populate it:
//   1. Bring up the full stack: make up
//   2. Run: make sp-cert-extract
//      (extracts /etc/shibboleth/keys/sp-signing.crt from the running SP container)
//   3. Paste the output as the value of 'certData' below.
//   4. Set 'validate.authnrequest' => true (a few lines down).
//   5. Reload the IdP: docker compose restart idp
//
// Until certData is populated, the IdP will accept unsigned AuthnRequests
// ('validate.authnrequest' => false).  Set to true once the cert is in place.
//
// ATTRIBUTE RELEASE TO THIS SP
// ─────────────────────────────
// The attributes whitelisted in saml20-idp-hosted.php authproc step 40 are
// released.  No additional SP-specific filtering is configured here — all
// whitelisted attributes go to this SP.  Add per-SP attribute limits below
// if the deployment needs stricter attribute release.
// =============================================================================

declare(strict_types=1);

$spEntityId = getenv('SP_ENTITY_ID')  ?: 'https://sp.sso.local/shibboleth';
$spAcsUrl   = getenv('SP_ACS_URL')    ?: 'https://sp.sso.local/Shibboleth.sso/SAML2/POST';

$metadata[$spEntityId] = [

    // ── Assertion Consumer Service ─────────────────────────────────────────────
    'AssertionConsumerService' => [
        [
            'Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => $spAcsUrl,
            'index'    => 1,
            'isDefault' => true,
        ],
    ],

    // ── SP signing certificate ─────────────────────────────────────────────────
    // Base64-encoded DER (no PEM headers).  Populated in Prompt 8 once the
    // Shibboleth SP generates its cert.
    // 'certData' => 'MIIC...base64DER...==',

    // Whether to require and validate signatures on AuthnRequests from this SP.
    // Set to true once 'certData' is populated; leave false during bootstrap.
    'validate.authnrequest' => false,

    // ── Response signing ───────────────────────────────────────────────────────
    // The IdP signs individual assertions (not the outer response envelope).
    // Shibboleth SP validates the assertion signature.
    'sign.response'  => false,   // outer response envelope
    'sign.assertion' => true,    // assertion is signed (required)

    // ── Encryption ────────────────────────────────────────────────────────────
    // PROD: set to true and add 'sharedKey' or the SP's encryption cert.
    'assertion.encryption' => false,

    // ── NameID ────────────────────────────────────────────────────────────────
    'NameIDPolicy' => [
        'Format'      => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'AllowCreate' => true,
    ],

    // ── Attribute delivery ─────────────────────────────────────────────────────
    // Deliver attributes in the assertion (not via AttributeQuery back-channel).
    'simplesaml.attributes' => true,

    // Use URI (urn:oid:...) format for attribute names in the assertion.
    // Shibboleth SP maps these to environment variables via attribute-map.xml.
    'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',

    // ── Session ────────────────────────────────────────────────────────────────
    'saml20.sign.response'             => true,
    'saml20.hok.assertion'             => false,

];
