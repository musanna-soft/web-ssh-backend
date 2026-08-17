package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
	"web-ssh-backend/internal/musanna"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Login now goes through musanna-platform (OIDC Authorization Code + PKCE)
// instead of Google.
//
// WHY. Every musanna product authenticates against one identity provider; a
// second one meant a second account, a second password-reset path and a second
// place to revoke access when somebody leaves. Google also could not tell us
// anything about the person's organisation, which is what the rest of the
// platform is built around.
//
// WHAT DID NOT CHANGE. The session is still ours: the platform's token is used
// once, at login, to learn who the caller is; everything afterwards runs on the
// JWT this service signs. That keeps the SSH/SFTP WebSocket handshakes (which
// carry the token in a query parameter, where an Authorization header is not
// available) working exactly as before.
var (
	oauthConfig *oauth2.Config
	authority   string
	jwtSecret   []byte
)

// Env keys. This is a CONFIDENTIAL client — the code exchange happens
// server-side — so MUSANNA_CLIENT_SECRET is a real secret and belongs in the
// deployment's secret store, not in the image.
const (
	envAuthority    = "MUSANNA_AUTHORITY"
	envClientID     = "MUSANNA_CLIENT_ID"
	envClientSecret = "MUSANNA_CLIENT_SECRET"
	envRedirectURL  = "MUSANNA_REDIRECT_URL"
)

func Init() {
	authority = strings.TrimRight(os.Getenv(envAuthority), "/")
	if authority == "" {
		authority = "https://platform.musanna.uz"
	}

	clientID := os.Getenv(envClientID)
	if clientID == "" {
		clientID = "webssh"
	}

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv(envClientSecret),
		RedirectURL:  os.Getenv(envRedirectURL),
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authority + "/connect/authorize",
			TokenURL: authority + "/connect/token",
		},
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// In production, this should be a fatal error or a persistent secret
		fmt.Println("WARNING: JWT_SECRET not set, generating random secret")
		jwtSecret = make([]byte, 32)
		rand.Read(jwtSecret)
	} else {
		jwtSecret = []byte(secret)
	}
}

// HandleLogin starts the Authorization Code + PKCE flow.
//
// PKCE is used even though this client has a secret: the verifier binds the
// authorization code to THIS browser session, so a code that leaks through the
// redirect (a referer header, a proxy log, a shoulder-surfed URL) still cannot
// be redeemed by anybody else.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomString(16)
	verifier := randomString(48)

	setFlowCookie(w, r, "oauthstate", state)
	setFlowCookie(w, r, "oauthverifier", verifier)

	challenge := base64.RawURLEncoding.EncodeToString(sha256Sum(verifier))
	u := oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

// HandleCallback completes the flow: verify state, exchange the code, read the
// platform's userinfo, upsert the local user and hand the frontend our own JWT.
func HandleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("oauthstate")
	if err != nil || r.FormValue("state") != stateCookie.Value {
		http.Error(w, "invalid oauth state", http.StatusUnauthorized)
		return
	}

	verifierCookie, err := r.Cookie("oauthverifier")
	if err != nil || verifierCookie.Value == "" {
		http.Error(w, "missing pkce verifier", http.StatusUnauthorized)
		return
	}

	// One-shot cookies: leaving them behind would let a later request replay
	// the same state/verifier pair.
	clearFlowCookie(w, r, "oauthstate")
	clearFlowCookie(w, r, "oauthverifier")

	token, err := oauthConfig.Exchange(context.Background(), r.FormValue("code"),
		oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value))
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, err := getUserInfo(token.AccessToken)
	if err != nil {
		http.Error(w, "failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if userInfo.Sub == "" {
		http.Error(w, "platform returned no subject", http.StatusInternalServerError)
		return
	}

	// A PLAN IS REQUIRED. Without one the app is closed — and it is closed
	// HERE, at the door, not three screens later: letting somebody in and then
	// refusing every action looks like a broken product rather than a decision.
	//
	// The platform token is only in hand at this moment, which is exactly why
	// the check lives in the callback.
	entitlement, err := musanna.Check(authority, token.AccessToken)
	if err != nil {
		// The platform was unreachable. Refusing is the honest answer: we
		// cannot tell a paying customer from a non-paying one right now, and
		// guessing "paid" would give away the product.
		http.Error(w, "could not verify your plan: "+err.Error(), http.StatusBadGateway)
		return
	}
	if !entitlement.Entitled {
		redirectToPlanPicker(w, r)
		return
	}

	// Match on the platform subject, never on the e-mail: an address can be
	// reassigned to a different person, the subject cannot.
	user := models.User{
		PlatformSub: userInfo.Sub,
		Email:       userInfo.Email,
		Name:        userInfo.Name,
		AvatarURL:   userInfo.Picture,
	}
	if err := db.DB.Where(models.User{PlatformSub: user.PlatformSub}).FirstOrCreate(&user).Error; err != nil {
		http.Error(w, "failed to save user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Refresh the cached plan on every login — this is the moment an upgrade
	// made in the console actually reaches the app.
	user.PlanCode = entitlement.PlanCode
	user.ServerLimit = entitlement.Servers
	if err := db.DB.Model(&user).
		Updates(map[string]any{"plan_code": user.PlanCode, "server_limit": user.ServerLimit}).
		Error; err != nil {
		http.Error(w, "failed to save plan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jwtToken, err := generateJWT(user)
	if err != nil {
		http.Error(w, "failed to generate token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:5173"
	}
	// Support comma-separated URLs for multiple origins
	origins := strings.Split(frontendURL, ",")
	http.Redirect(w, r, fmt.Sprintf("%s/auth/callback?token=%s", origins[0], jwtToken), http.StatusTemporaryRedirect)
}

// redirectToPlanPicker sends the person to the console, where plans live.
//
// A dead end would be the alternative: "you have no plan" with nowhere to go.
// The console is also where the free plan is one click away, so most people
// come straight back.
func redirectToPlanPicker(w http.ResponseWriter, r *http.Request) {
	console := strings.TrimRight(os.Getenv("MUSANNA_CONSOLE_URL"), "/")
	if console == "" {
		console = "https://console.musanna.uz"
	}
	http.Redirect(w, r, console+"/discovery", http.StatusTemporaryRedirect)
}

func setFlowCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearFlowCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// isHTTPS also honours the proxy header: behind the ingress the request reaches
// this process as plain HTTP, and marking the cookie insecure there would let
// the browser send it back over an unencrypted hop.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// PlatformUserInfo is the subset of the platform's /connect/userinfo response
// this service stores.
type PlatformUserInfo struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func getUserInfo(accessToken string) (*PlatformUserInfo, error) {
	req, err := http.NewRequest("GET", authority+"/connect/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned http %d", resp.StatusCode)
	}

	var userInfo PlatformUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed decoding user info: %s", err.Error())
	}
	return &userInfo, nil
}

func generateJWT(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 days
	})

	return token.SignedString(jwtSecret)
}

// Middleware
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			ctx := context.WithValue(r.Context(), "user_id", claims["user_id"])
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		}
	})
}
