package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"auth-base/internal/google"
)

func main() {
	loadDotEnv()

	port := getEnv("PORT", "4000")
	frontendURL := getEnv("FRONTEND_URL", "http://localhost:5173")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /auth/google", handleGoogleAuth)

	handler := corsMiddleware(frontendURL, mux)

	log.Printf("Server running on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	defer r.Body.Close()

	var req struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Credential == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing credential"})
		return
	}

	clientID := getEnv("GOOGLE_CLIENT_ID", "")
	if clientID == "" {
		log.Println("GOOGLE_CLIENT_ID not set")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server misconfigured"})
		return
	}

	user, err := google.VerifyIDToken(req.Credential, clientID)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func corsMiddleware(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var dotEnvLoaded bool

func loadDotEnv() {
	if dotEnvLoaded {
		return
	}
	dotEnvLoaded = true

	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
