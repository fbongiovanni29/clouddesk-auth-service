package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setup() {
	sessionsMu.Lock()
	sessions = make(map[string]string)
	sessionsMu.Unlock()
}

func TestHealthz(t *testing.T) {
	setup()
	mux := newMux()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestLoginSuccess(t *testing.T) {
	setup()
	mux := newMux()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "clouddesk"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Fatal("expected token in response")
	}
}

func TestLoginBadCredentials(t *testing.T) {
	setup()
	mux := newMux()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestFullTokenLifecycle(t *testing.T) {
	setup()
	mux := newMux()

	// 1. Login → get token
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "clouddesk"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %s", w.Body.String())
	}
	var loginResp map[string]string
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp["token"]

	// 2. Verify → valid
	body, _ = json.Marshal(map[string]string{"token": token})
	req = httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify failed: %s", w.Body.String())
	}
	var verifyResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&verifyResp)
	if verifyResp["valid"] != true {
		t.Fatalf("expected valid=true, got %v", verifyResp)
	}
	if verifyResp["username"] != "admin" {
		t.Fatalf("expected username=admin, got %v", verifyResp["username"])
	}

	// 3. Logout
	body, _ = json.Marshal(map[string]string{"token": token})
	req = httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("logout failed: %s", w.Body.String())
	}

	// 4. Verify after logout → invalid
	body, _ = json.Marshal(map[string]string{"token": token})
	req = httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid=false, got %d", w.Code)
	}
	var afterLogout map[string]interface{}
	json.NewDecoder(w.Body).Decode(&afterLogout)
	if afterLogout["valid"] != false {
		t.Fatalf("expected valid=false after logout, got %v", afterLogout)
	}
}

func TestMethodEnforcement(t *testing.T) {
	setup()
	mux := newMux()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
