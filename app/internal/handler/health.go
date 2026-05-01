package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// Health handles GET /healthz.
// No authentication; used by Docker healthchecks and load-balancer probes.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
