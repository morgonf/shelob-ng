package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// UserItem supports both username-based and email-based login endpoints.
// The json tags determine which field is sent; populate whichever the target uses.
type UserItem struct {
	// Used by email-based APIs (e.g. OWASP Juice Shop /rest/user/login)
	Email string `json:"email,omitempty"`
	// Used by username-based APIs (e.g. /api/v3/user/login)
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

func CreateUser(username, password, url string) []*http.Cookie {
	return CreateUserWithLoginEndpoint(username, password, url, "/api/v3/user/login")
}

func CreateUserWithLoginEndpoint(username, password, url, loginEndpoint string) []*http.Cookie {
	// Heuristic: if the login endpoint looks like a juice-shop style path,
	// use "email" field. Otherwise fall back to "username".
	if strings.Contains(loginEndpoint, "/rest/") || strings.Contains(loginEndpoint, "/login") {
		testUser := UserItem{Email: username, Password: password}
		return testUser.getCookies(url, loginEndpoint)
	}
	testUser := UserItem{Username: username, Password: password}
	return testUser.getCookies(url, loginEndpoint)
}

func (testUser *UserItem) getCookies(url, loginEndpoint string) []*http.Cookie {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	payload, err := json.Marshal(testUser)
	if err != nil {
		log.Error("auth.go\tFailed to create json: ", err)
		return nil
	}

	loginURL := url + loginEndpoint
	httpRequest, err := http.NewRequest("POST", loginURL, bytes.NewReader(payload))
	if err != nil {
		log.Error("auth.go\tFailed to create http request: ", err)
		return nil
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		log.Warn("auth.go\tFailed to make http request for authentication: ", err)
		return []*http.Cookie{}
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Warn("[---] No cookies ;(\t", response.Status)
		return []*http.Cookie{}
	}

	// First try standard Set-Cookie headers (most APIs).
	cookies := response.Cookies()
	if len(cookies) > 0 {
		log.Info("[+++] Cookies are stored")
		return cookies
	}

	// Fallback: extract JWT from JSON body and return it as a synthetic cookie.
	// Handles APIs like OWASP Juice Shop that return {"authentication":{"token":"<jwt>"}}.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Warn("[---] Could not read login response body")
		return []*http.Cookie{}
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		log.Warn("[---] Login response is not JSON")
		return []*http.Cookie{}
	}

	// Walk common JWT locations: top-level "token", "access_token",
	// or nested under "authentication" or "data".
	token := extractToken(parsed)
	if token == "" {
		log.Warn("[---] No token found in login response")
		return []*http.Cookie{}
	}

	log.Info("[+++] JWT extracted from response body, using as session cookie")
	return []*http.Cookie{
		{Name: "token", Value: token},
	}
}

// extractToken walks common JSON shapes to find a JWT string.
func extractToken(m map[string]interface{}) string {
	// Direct fields
	for _, key := range []string{"token", "access_token", "accessToken", "jwt"} {
		if v, ok := m[key].(string); ok && v != "" {
			return v
		}
	}
	// Nested under "authentication" (Juice Shop), "data", "result"
	for _, wrapper := range []string{"authentication", "data", "result", "auth"} {
		if sub, ok := m[wrapper].(map[string]interface{}); ok {
			if tok := extractToken(sub); tok != "" {
				return tok
			}
		}
	}
	return ""
}
