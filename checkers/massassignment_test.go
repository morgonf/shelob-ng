package checkers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMassAssignment_HighWhenFieldsReflected verifies that a HIGH finding is
// issued when the server returns the injected poison fields in its response.
func TestMassAssignment_HighWhenFieldsReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		// Echo back whatever was sent, including poison fields.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	chk := MassAssignment{}
	body, _ := json.Marshal(map[string]interface{}{"username": "alice", "email": "a@b.com"})
	entry := makeEntry("POST", "/users")
	entry.Body = body

	req, _ := http.NewRequest("POST", srv.URL+"/users", nil)
	req.Header.Set("Content-Type", "application/json")
	resp := makeRespWithCode(201)

	cctx := CheckContext{Client: srv.Client()}
	findings := chk.Check(context.Background(), cctx, entry, req, resp, nil)

	if len(findings) == 0 {
		t.Fatal("expected a finding when server reflects poison fields")
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %q", findings[0].Severity)
	}
	if findings[0].Checker != "MassAssignment" {
		t.Errorf("wrong checker name: %q", findings[0].Checker)
	}
}

// TestMassAssignment_MediumWhenFieldsAcceptedSilently verifies MEDIUM finding
// when the server accepts the probe (2xx) but doesn't reflect the poison fields.
func TestMassAssignment_MediumWhenFieldsAcceptedSilently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Returns 201 but only with "id" — does not echo the poison fields.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"id":42,"message":"created"}`))
	}))
	defer srv.Close()

	chk := MassAssignment{}
	body, _ := json.Marshal(map[string]interface{}{"username": "alice"})
	entry := makeEntry("POST", "/users")
	entry.Body = body

	req, _ := http.NewRequest("POST", srv.URL+"/users", nil)
	req.Header.Set("Content-Type", "application/json")
	resp := makeRespWithCode(201)

	cctx := CheckContext{Client: srv.Client()}
	findings := chk.Check(context.Background(), cctx, entry, req, resp, nil)

	if len(findings) == 0 {
		t.Fatal("expected MEDIUM finding when server accepts poison fields silently")
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %q", findings[0].Severity)
	}
}

// TestMassAssignment_NoFindingWhenServerRejects verifies no finding when the
// server returns 422 (field validation rejected the extra fields).
func TestMassAssignment_NoFindingWhenServerRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(422)
	}))
	defer srv.Close()

	chk := MassAssignment{}
	body, _ := json.Marshal(map[string]interface{}{"username": "alice"})
	entry := makeEntry("POST", "/users")
	entry.Body = body

	req, _ := http.NewRequest("POST", srv.URL+"/users", nil)
	req.Header.Set("Content-Type", "application/json")
	resp := makeRespWithCode(201)

	cctx := CheckContext{Client: srv.Client()}
	findings := chk.Check(context.Background(), cctx, entry, req, resp, nil)

	if len(findings) > 0 {
		t.Errorf("expected no finding when server returns 422, got: %+v", findings)
	}
}

// TestMassAssignment_SkipsGET verifies the checker only fires on state-changing methods.
func TestMassAssignment_SkipsGET(t *testing.T) {
	chk := MassAssignment{}
	entry := makeEntry("GET", "/users")
	req, _ := http.NewRequest("GET", "http://localhost/users", nil)
	req.Header.Set("Content-Type", "application/json")
	resp := makeRespWithCode(200)

	findings := chk.Check(context.Background(), CheckContext{Client: &http.Client{}}, entry, req, resp, nil)
	if len(findings) > 0 {
		t.Errorf("MassAssignment should skip GET requests")
	}
}

// TestMassAssignment_SkipsNonJSON verifies no finding when Content-Type is not JSON.
func TestMassAssignment_SkipsNonJSON(t *testing.T) {
	chk := MassAssignment{}
	entry := makeEntry("POST", "/upload")
	req, _ := http.NewRequest("POST", "http://localhost/upload", nil)
	req.Header.Set("Content-Type", "multipart/form-data")
	resp := makeRespWithCode(201)

	findings := chk.Check(context.Background(), CheckContext{Client: &http.Client{}}, entry, req, resp, nil)
	if len(findings) > 0 {
		t.Errorf("MassAssignment should skip non-JSON requests")
	}
}

// TestDeepGet verifies nested field lookup.
func TestDeepGet(t *testing.T) {
	obj := map[string]interface{}{
		"user": map[string]interface{}{
			"role": "admin",
		},
	}
	val, found := deepGet(obj, "role")
	if !found {
		t.Error("deepGet should find nested 'role'")
	}
	if val != "admin" {
		t.Errorf("expected 'admin', got %v", val)
	}
}
