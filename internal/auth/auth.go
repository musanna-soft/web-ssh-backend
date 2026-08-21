package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"
	"time"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
	"web-ssh-backend/internal/musanna"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
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
		// `platform.me` — MAJBURIY va u shu ro'yxatning eng muhim elementi.
		//
		// Tarifni tekshirish `POST /api/integration/authorize` orqali boradi va platformada
		// u `SelfApp` siyosati bilan yopilgan: cookie yoki `platform.api`/`platform.me`
		// scope'li bearer. Bu scope so'ralmasa token to'g'ri bo'ladi-yu, o'sha endpoint 403
		// qaytaradi — ya'ni TARIFI BOR odam ham kira olmaydi va xato "tarifingiz yo'q"
		// emas, tushunarsiz 403 bo'lib ko'rinadi.
		Scopes: []string{"openid", "profile", "email", "platform.me"},
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
		failLogin(w, r, http.StatusUnauthorized, "Kirish so'rovi eskirgan", "Sahifa uzoq turib qolgan yoki qayta yuklangan. Qaytadan kiring.", "")
		return
	}

	verifierCookie, err := r.Cookie("oauthverifier")
	if err != nil || verifierCookie.Value == "" {
		failLogin(w, r, http.StatusUnauthorized, "Kirish so'rovi eskirgan", "Sahifa uzoq turib qolgan yoki qayta yuklangan. Qaytadan kiring.", "")
		return
	}

	// One-shot cookies: leaving them behind would let a later request replay
	// the same state/verifier pair.
	clearFlowCookie(w, r, "oauthstate")
	clearFlowCookie(w, r, "oauthverifier")

	token, err := oauthConfig.Exchange(context.Background(), r.FormValue("code"),
		oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value))
	if err != nil {
		failLogin(w, r, http.StatusInternalServerError, "Kirishni yakunlab bo'lmadi", "Musanna bilan almashinuv uzildi.", err.Error())
		return
	}

	userInfo, err := getUserInfo(token.AccessToken)
	if err != nil {
		failLogin(w, r, http.StatusInternalServerError, "Kirishni yakunlab bo'lmadi", "Musanna hisobingiz ma'lumotini olib bo'lmadi.", err.Error())
		return
	}
	if userInfo.Sub == "" {
		failLogin(w, r, http.StatusInternalServerError, "Kirishni yakunlab bo'lmadi", "Musanna hisobingiz ma'lumotini olib bo'lmadi.", "platform returned no subject")
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
		//
		// 403 IS NOT THAT CASE. It means our token may not ask the question —
		// a configuration fault on OUR side (the `platform.me` scope), not the
		// person's. Reporting it as "could not verify your plan" sent a PAYING
		// customer away with an error they could do nothing about, so the two
		// are told apart and only one of them blames the network.
		if errors.Is(err, musanna.ErrNotPermitted) {
			failLogin(w, r, http.StatusBadGateway,
				"Tarifni tekshirib bo'lmadi",
				"Ilova platformadan tarif haqida so'ray olmadi — bu sozlama xatosi, hisobingizda muammo yo'q.",
				err.Error())
			return
		}

		failLogin(w, r, http.StatusBadGateway,
			"Tarifni tekshirib bo'lmadi",
			"Musanna hozir javob bermayapti. Birozdan keyin qayta urinib ko'ring.",
			err.Error())
		return
	}
	if !entitlement.Entitled {
		redirectToPlanPicker(w, r)
		return
	}

	// Match on the platform subject, never on the e-mail: an address can be
	// reassigned to a different person, the subject cannot.
	user, err := adoptOrCreate(userInfo)
	if err != nil {
		failLogin(w, r, http.StatusInternalServerError, "Hisobni saqlab bo'lmadi", "Ma'lumotlar bazasi javob bermadi.", err.Error())
		return
	}

	// Refresh the cached plan on every login — this is the moment an upgrade
	// made in the console actually reaches the app.
	user.PlanCode = entitlement.PlanCode
	user.ServerLimit = entitlement.Servers
	if err := db.DB.Model(user).
		Updates(map[string]any{"plan_code": user.PlanCode, "server_limit": user.ServerLimit}).
		Error; err != nil {
		failLogin(w, r, http.StatusInternalServerError, "Tarifni saqlab bo'lmadi", "Ma'lumotlar bazasi javob bermadi.", err.Error())
		return
	}

	jwtToken, err := generateJWT(*user)
	if err != nil {
		failLogin(w, r, http.StatusInternalServerError, "Seans ochib bo'lmadi", "Ichki xatolik.", err.Error())
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
// failLogin renders a human-readable failure page instead of a bare line of
// text.
//
// Everything here happens on a URL the person never typed: the OIDC callback.
// `http.Error` writes plain text on a blank page, so what they saw when the
// plan check failed was one raw sentence — no title, no explanation, no way
// back, and no clue whether the fault was theirs. The technical detail is kept
// (it is what makes a bug report useful) but demoted below the human sentence.
func failLogin(w http.ResponseWriter, r *http.Request, status int, title, message, detail string) {
	frontend := frontendOrigin()

	var extra string
	if detail != "" {
		extra = "<pre>" + html.EscapeString(detail) + "</pre>"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="uz"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0f14;color:#e6edf3;
      font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
 main{max-width:34rem;padding:2rem;text-align:center}
 h1{margin:0 0 .5rem;font-size:1.35rem}
 p{margin:0 0 1.5rem;color:#9aa7b4}
 a{display:inline-block;padding:.6rem 1.2rem;border-radius:.5rem;background:#2f81f7;color:#fff;text-decoration:none}
 pre{margin-top:1.5rem;padding:.75rem;border-radius:.5rem;background:#111820;color:#7d8792;
     font-size:.75rem;text-align:left;white-space:pre-wrap;word-break:break-word}
</style>
<main><h1>%s</h1><p>%s</p><a href="%s">Qaytish</a>%s</main>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(message), frontend, extra)
}

// frontendOrigin is the first entry of FRONTEND_URL — the person's way back.
func frontendOrigin() string {
	frontend := os.Getenv("FRONTEND_URL")
	if frontend == "" {
		frontend = "http://localhost:5173"
	}
	return strings.Split(frontend, ",")[0]
}

// adoptOrCreate finds the person's row, or makes one.
//
// MIGRATION LIVES HERE. Before login moved to musanna, everybody signed in with Google and
// the row was keyed off `google_id`; those 28 rows carry the servers, folders and SSH
// credentials people actually use. Only ONE of them has a musanna account today, so keying
// purely off the platform subject would have greeted 27 people with an empty app and left
// their servers stranded in a row nothing points at.
//
// So the lookup is two-step:
//
//  1. by platform subject — the normal path once somebody has signed in here before;
//  2. by E-MAIL, and if that hits, the row is ADOPTED: the subject is written onto it and
//     everything hanging off it (servers, folders, MFA) stays attached.
//
// Email is the only bridge available: the platform subject did not exist when those rows
// were written, and matching on name would be guesswork. It is also why the login screen
// tells people to register with the SAME address.
//
// The email comparison is case-insensitive: Google hands back whatever case the person
// typed, the platform normalises separately, and `Bob@x.uz` vs `bob@x.uz` would have
// created a second, empty account for the same human.
func adoptOrCreate(info *PlatformUserInfo) (*models.User, error) {
	var user models.User

	err := db.DB.Where("platform_sub = ?", info.Sub).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if info.Email != "" {
		err = db.DB.Where("lower(email) = lower(?)", info.Email).First(&user).Error
		if err == nil {
			// Eski yozuv topildi — uni O'ZLASHTIRAMIZ. `platform_sub` yozilgach, keyingi
			// kirishlar birinchi qadamdan o'tadi va bu shox boshqa ishlamaydi.
			user.PlatformSub = info.Sub
			user.Name = info.Name
			user.AvatarURL = info.Picture
			if err := db.DB.Model(&user).Updates(map[string]any{
				"platform_sub": user.PlatformSub,
				"name":         user.Name,
				"avatar_url":   user.AvatarURL,
			}).Error; err != nil {
				return nil, err
			}
			return &user, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	user = models.User{
		PlatformSub: info.Sub,
		Email:       info.Email,
		Name:        info.Name,
		AvatarURL:   info.Picture,
	}
	if err := db.DB.Create(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

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
