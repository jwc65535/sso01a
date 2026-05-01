// fingerprint.js — FingerprintJS open-source v4 wrapper
//
// Loaded after the FingerprintJS IIFE script tag in index.html, which sets
// window.FingerprintJS.  This module caches the visitorId in sessionStorage
// so successive calls within the same tab don't re-run the signal collection.
//
// PRIVACY NOTE: the open-source visitor ID changes on browser or OS upgrades,
// private-mode sessions, and cookie clears.  It is used here only for device
// binding in the JWT cnf claim — not for tracking.  The ID is never sent to
// any third-party server; it goes only to the backend /api/token endpoint.

(function () {
  const CACHE_KEY = 'fpjs_visitor_id';

  let _promise = null;

  // get() resolves with { visitorId, components } from FingerprintJS.
  // The result is cached for the lifetime of the browser tab.
  async function get() {
    const cached = sessionStorage.getItem(CACHE_KEY);
    if (cached) {
      return { visitorId: cached };
    }

    if (!window.FingerprintJS) {
      console.warn('FingerprintJS not loaded — using fallback fingerprint');
      const fallback = 'fp-unavailable-' + Math.random().toString(36).slice(2);
      return { visitorId: fallback };
    }

    if (!_promise) {
      _promise = window.FingerprintJS.load({ monitoring: false })
        .then(fp => fp.get())
        .then(result => {
          sessionStorage.setItem(CACHE_KEY, result.visitorId);
          return result;
        })
        .catch(err => {
          console.warn('FingerprintJS error:', err);
          _promise = null;
          return { visitorId: 'fp-error-' + Date.now() };
        });
    }

    return _promise;
  }

  // clear() removes the cached visitor ID (e.g. on logout, to force re-collection).
  function clear() {
    sessionStorage.removeItem(CACHE_KEY);
    _promise = null;
  }

  window.Fingerprint = { get, clear };
})();
