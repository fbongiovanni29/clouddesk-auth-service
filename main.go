package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── configuration ──────────────────────────────────────────────────────────────

var secretKey []byte

func init() {
	key := os.Getenv("AUTH_SECRET_KEY")
	if key == "" {
		key = "clouddesk-demo-secret-change-me"
	}
	secretKey = []byte(key)
}

// ── in-memory session store ────────────────────────────────────────────────────

var (
	sessions   = make(map[string]string) // token → username
	sessionsMu sync.RWMutex
)

// ── hardcoded user store ───────────────────────────────────────────────────────

var users = map[string]string{
	"admin": "clouddesk",
}

// ── JWT helpers ────────────────────────────────────────────────────────────────

type claims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

func createToken(username string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("entropy: %w", err)
	}
	c := claims{
		Sub: username,
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Jti: base64.RawURLEncoding.EncodeToString(jti),
	}
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := header + "." + payload
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig, nil
}

func verifyToken(token string) (*claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return nil, fmt.Errorf("invalid signature")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}
	var c claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, fmt.Errorf("invalid claims")
	}
	if time.Now().Unix() > c.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &c, nil
}

// ── handlers ───────────────────────────────────────────────────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	expected, ok := users[req.Username]
	if !ok || expected != req.Password {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, err := createToken(req.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
		return
	}
	sessionsMu.Lock()
	sessions[token] = req.Username
	sessionsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sessionsMu.RLock()
	username, active := sessions[req.Token]
	sessionsMu.RUnlock()
	if !active {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "username": ""})
		return
	}
	if _, err := verifyToken(req.Token); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "username": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true, "username": username})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sessionsMu.Lock()
	delete(sessions, req.Token)
	sessionsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// ── router & main ──────────────────────────────────────────────────────────────

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", methodOnly(http.MethodPost, handleLogin))
	mux.HandleFunc("/auth/verify", methodOnly(http.MethodPost, handleVerify))
	mux.HandleFunc("/auth/logout", methodOnly(http.MethodPost, handleLogout))
	mux.HandleFunc("/healthz", methodOnly(http.MethodGet, handleHealthz))
	return mux
}

func methodOnly(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func main() {
	log.Println("clouddesk-auth-service listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", newMux()))
}
