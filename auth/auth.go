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
	cookies, _ := Login(username, password, url, loginEndpoint)
	return cookies
}

// Login authenticates and returns session cookies and a JWT token.
//
// Two login body formats are tried in order to support different APIs:
//   1. {"username": ...}  — standard REST APIs (VAmPI, Petstore, most APIs)
//   2. {"email": ...}     — email-based APIs (Juice Shop /rest/user/login)
//
// For endpoints under /rest/ the order is reversed (email first) since
// Juice Shop is the canonical email-based target.
// The first format that returns 200 with a token or cookie is used.
func Login(username, password, url, loginEndpoint string) (cookies []*http.Cookie, token string) {
	candidates := []UserItem{
		{Username: username, Password: password},
		{Email: username, Password: password},
	}
	// Juice Shop and similar /rest/ APIs use email as the login field.
	if strings.Contains(loginEndpoint, "/rest/") {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}
	for _, candidate := range candidates {
		if c, t := candidate.login(url, loginEndpoint); len(c) > 0 || t != "" {
			return c, t
		}
	}
	return []*http.Cookie{}, ""
}

func (testUser UserItem) login(url, loginEndpoint string) (cookies []*http.Cookie, token string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	payload, err := json.Marshal(testUser)
	if err != nil {
		log.Error("auth.go\tFailed to create json: ", err)
		return nil, ""
	}

	loginURL := url + loginEndpoint
	httpRequest, err := http.NewRequest("POST", loginURL, bytes.NewReader(payload))
	if err != nil {
		log.Error("auth.go\tFailed to create http request: ", err)
		return nil, ""
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		log.Warn("auth.go\tFailed to make http request for authentication: ", err)
		return []*http.Cookie{}, ""
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Warn("[---] No cookies ;(\t", response.Status)
		return []*http.Cookie{}, ""
	}

	// Read the full body once — needed both for cookie fallback and token extraction.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Warn("[---] Could not read login response body")
		return []*http.Cookie{}, ""
	}

	// Try to extract a JWT from the JSON body for targets that return it there.
	var parsed map[string]interface{}
	var rawToken string
	if json.Unmarshal(body, &parsed) == nil {
		rawToken = extractToken(parsed)
	}

	// Prefer standard Set-Cookie headers (most APIs).
	setCookies := response.Cookies()
	if len(setCookies) > 0 {
		log.Info("[+++] Cookies are stored")
		return setCookies, rawToken
	}

	// Fallback: synthesise a cookie from the body token so cookie-based endpoints work.
	if rawToken == "" {
		log.Warn("[---] No token found in login response")
		return []*http.Cookie{}, ""
	}

	log.Info("[+++] JWT extracted from response body, using as session cookie")
	return []*http.Cookie{{Name: "token", Value: rawToken}}, rawToken
}

// extractToken walks common JSON shapes to find a JWT string.
func extractToken(m map[string]interface{}) string {
	// Direct fields — auth_token is used by VAmPI; token/access_token by most others.
	for _, key := range []string{"token", "auth_token", "access_token", "accessToken", "jwt"} {
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
