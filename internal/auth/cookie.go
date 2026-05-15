package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mfaCookieName — the HttpOnly session cookie set after a Mini App
// successfully exchanges initData for a session. Carries (user_id, surface,
// exp) signed with MFA_COOKIE_KEY.
const mfaCookieName = "mfa_session"

// mfaCookieTTL — how long the Mini App's session cookie lives. Short on
// purpose: this only proves "you successfully verified initData recently"
// and is required for every /api/mfa/* call from the bot surface.
const mfaCookieTTL = 15 * time.Minute

var (
	cookieKeyOnce sync.Once
	cookieKey     []byte
	cookieKeyErr  error
)

// loadCookieKey reads MFA_COOKIE_KEY (32 bytes hex) once and caches.
// Returns an error if missing or malformed; cookie operations then fail
// closed.
func loadCookieKey() ([]byte, error) {
	cookieKeyOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("MFA_COOKIE_KEY"))
		if raw == "" {
			cookieKeyErr = errors.New("MFA_COOKIE_KEY is not set")
			return
		}
		key, err := hex.DecodeString(raw)
		if err != nil {
			cookieKeyErr = fmt.Errorf("MFA_COOKIE_KEY must be hex: %w", err)
			return
		}
		if len(key) < 32 {
			cookieKeyErr = errors.New("MFA_COOKIE_KEY must decode to at least 32 bytes")
			return
		}
		cookieKey = key
	})
	return cookieKey, cookieKeyErr
}

// signCookieValue produces "uid.surface.tg.exp.sig" where sig is a hex-encoded
// HMAC-SHA256 over the first four fields. tg is the Telegram user id (or 0
// for the web surface). Lightweight stand-in for a JWT.
func signCookieValue(userID uint, surface string, telegramID int64, exp time.Time) (string, error) {
	key, err := loadCookieKey()
	if err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%d.%s.%d.%d", userID, surface, telegramID, exp.Unix())
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

func verifyCookieValue(value string) (userID uint, surface string, telegramID int64, exp time.Time, err error) {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		err = errors.New("malformed cookie")
		return
	}
	payload := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
	key, kerr := loadCookieKey()
	if kerr != nil {
		err = kerr
		return
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[4])) {
		err = errors.New("cookie signature mismatch")
		return
	}
	uid64, perr := strconv.ParseUint(parts[0], 10, 64)
	if perr != nil {
		err = errors.New("bad uid")
		return
	}
	tg64, perr := strconv.ParseInt(parts[2], 10, 64)
	if perr != nil {
		err = errors.New("bad telegram_id")
		return
	}
	expTs, perr := strconv.ParseInt(parts[3], 10, 64)
	if perr != nil {
		err = errors.New("bad exp")
		return
	}
	exp = time.Unix(expTs, 0)
	if time.Now().After(exp) {
		err = errors.New("cookie expired")
		return
	}
	userID = uint(uid64)
	surface = parts[1]
	telegramID = tg64
	return
}

func setMFASessionCookie(w http.ResponseWriter, userID uint, surface string, telegramID int64) error {
	exp := time.Now().Add(mfaCookieTTL)
	value, err := signCookieValue(userID, surface, telegramID, exp)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    value,
		Path:     "/api/mfa/",
		Expires:  exp,
		MaxAge:   int(mfaCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   cookieSecure(),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func clearMFASessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    "",
		Path:     "/api/mfa/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure(),
		SameSite: http.SameSiteStrictMode,
	})
}

func readMFASessionCookie(r *http.Request) (userID uint, surface string, telegramID int64, err error) {
	c, cerr := r.Cookie(mfaCookieName)
	if cerr != nil {
		err = cerr
		return
	}
	uid, sur, tg, _, verr := verifyCookieValue(c.Value)
	if verr != nil {
		err = verr
		return
	}
	return uid, sur, tg, nil
}

// cookieSecure mirrors the heuristic used elsewhere in auth.go — Secure
// flag flips on when GOOGLE_REDIRECT_URL is https://. In production this
// is always true; in dev (http://localhost) Telegram requires HTTPS anyway
// for Mini Apps, so the env should already be https://.
func cookieSecure() bool {
	return strings.HasPrefix(strings.ToLower(os.Getenv("GOOGLE_REDIRECT_URL")), "https://")
}

// randomNonce returns base64-url-encoded 16 random bytes. Used internally
// by WebAuthn challenge generation (slice 3) and by recovery code rotation.
func randomNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
