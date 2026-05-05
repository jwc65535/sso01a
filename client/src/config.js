// config.js — runtime configuration
//
// When the SPA is served from https://sp.sso.local (production / full-stack dev),
// API calls are same-origin: apiBase = '/api'
// Cookie auth (HttpOnly SameSite=Strict) works automatically.
//
// When the SPA is served from http://localhost:3000 (UI-only dev with the
// standalone nginx container), API calls are cross-origin.  Cookie auth
// does NOT work in this mode (SameSite=Strict blocks cross-origin sending).
// The app falls back to storing the Bearer token in sessionStorage.
// Full SAML auth only works from sp.sso.local; localhost:3000 is for layout
// and component development only.

window.APP_CONFIG = (function () {
  const onSP = window.location.hostname === (window.SP_HOSTNAME || 'sp.sso.local');

  return {
    // Base path for all /api/* calls.  Same-origin when on the SP.
    apiBase: onSP ? '/api' : 'https://sp.sso.local/api',

    // Full URL used to trigger a Shibboleth login and redirect back here.
    loginUrl: 'https://sp.sso.local/Shibboleth.sso/Login',

    // Whether cookie auth is available.  False when cross-origin (localhost:3000).
    cookieAuth: onSP,

    // Session storage key for the Bearer token (used only when cookieAuth = false).
    tokenKey: 'sso_access_token',

    // Session storage key tracking the last issued cert serial (informational).
    certSerialKey: 'sso_cert_serial',
  };
})();
