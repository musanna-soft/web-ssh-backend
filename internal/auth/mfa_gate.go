package auth

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
)

const (
	SurfaceWeb = "web"
	SurfaceBot = "bot"

	defaultSessionTTL = 30 * time.Minute
)

// MFARequired reports whether MFA enforcement is turned on via env.
// Default OFF — flipping this on with no enrolled users is safe because
// the gate exempts the enrollment endpoints themselves.
func MFARequired() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MFA_REQUIRED")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// SessionTTL returns how long a DeviceSession lasts after a successful unlock.
// Configurable via MFA_SESSION_TTL (Go duration syntax: "30m", "1h", "15m").
func SessionTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("MFA_SESSION_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return defaultSessionTTL
}

// GraceUntil returns the configured grace window deadline (zero time when
// not set / unparseable). Users who are not yet enrolled are allowed
// through with a warning header until this moment passes.
//
// MFA_GRACE_UNTIL accepts RFC3339 ("2026-06-01T00:00:00Z") or a bare date
// ("2026-06-01" — interpreted as UTC midnight).
func GraceUntil() time.Time {
	raw := strings.TrimSpace(os.Getenv("MFA_GRACE_UNTIL"))
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t
	}
	return time.Time{}
}

// inGracePeriod reports whether an unenrolled user should be allowed
// through with a warning instead of a 403.
func inGracePeriod() bool {
	g := GraceUntil()
	return !g.IsZero() && time.Now().Before(g)
}

// activeCacheEntry — tiny in-memory cache to avoid hitting the DB on every
// authenticated request. TTL is short (5s) so a /lock takes effect promptly.
type activeCacheEntry struct {
	active   bool
	cachedAt time.Time
}

var (
	activeCacheMu sync.Mutex
	activeCache   = map[string]activeCacheEntry{}
)

const activeCacheTTL = 5 * time.Second

func activeCacheKey(userID uint, surface string) string {
	return surface + ":" + uintToStr(userID)
}

func uintToStr(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// IsActive reports whether the given user has an unexpired DeviceSession for
// the given surface ("web" or "bot"). Cheap-cached for 5 seconds.
func IsActive(userID uint, surface string) bool {
	key := activeCacheKey(userID, surface)

	activeCacheMu.Lock()
	if e, ok := activeCache[key]; ok && time.Since(e.cachedAt) < activeCacheTTL {
		activeCacheMu.Unlock()
		return e.active
	}
	activeCacheMu.Unlock()

	var count int64
	if err := db.DB.Model(&models.DeviceSession{}).
		Where("user_id = ? AND surface = ? AND expires_at > ?", userID, surface, time.Now()).
		Count(&count).Error; err != nil {
		// On DB error, fail closed only if MFA is required.
		return false
	}
	active := count > 0

	activeCacheMu.Lock()
	activeCache[key] = activeCacheEntry{active: active, cachedAt: time.Now()}
	activeCacheMu.Unlock()

	return active
}

// InvalidateActiveCache clears the cache for a (userID, surface) tuple. Call
// after writing a new DeviceSession or running /lock.
func InvalidateActiveCache(userID uint, surface string) {
	key := activeCacheKey(userID, surface)
	activeCacheMu.Lock()
	delete(activeCache, key)
	activeCacheMu.Unlock()
}

// mfaExemptPrefixes — request paths that must work even without an active
// DeviceSession. Enrollment, unlock, identity-only endpoints.
var mfaExemptPrefixes = []string{
	"/api/mfa/",
	"/api/me",
}

func isExempt(path string) bool {
	for _, p := range mfaExemptPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// MFAGate is HTTP middleware chained AFTER AuthMiddleware. It checks for an
// active DeviceSession for the web surface. On miss, it returns 403 with a
// machine-readable JSON body so the frontend can redirect to /mfa/unlock.
//
// Slice 0: this is wired but a no-op when MFA_REQUIRED is off. Real enforcement
// arrives in Slice 1 once the /api/mfa/* endpoints exist.
func MFAGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !MFARequired() {
			next.ServeHTTP(w, r)
			return
		}
		if isExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		uid, ok := userIDFromContext(r)
		if !ok {
			// AuthMiddleware should have set this; if not, treat as unauth.
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if IsActive(uid, SurfaceWeb) {
			next.ServeHTTP(w, r)
			return
		}

		// Grace window — let unenrolled legacy users keep working with a
		// soft warning header that the frontend can surface as a banner.
		// Enrolled users (who already chose to set MFA up) get the hard
		// gate regardless, since they've opted in.
		if inGracePeriod() {
			var enr models.MFAEnrollment
			if err := db.DB.Where("user_id = ?", uid).First(&enr).Error; err != nil || !enr.Enrolled {
				w.Header().Set("X-MFA-Warning", "grace")
				w.Header().Set("X-MFA-Grace-Until", GraceUntil().Format(time.RFC3339))
				next.ServeHTTP(w, r)
				return
			}
		}

		writeMFARequired(w, uid)
	})
}

// userIDFromContext extracts the user_id placed by AuthMiddleware.
// The middleware stores it as a jwt.MapClaims float64; normalize to uint.
func userIDFromContext(r *http.Request) (uint, bool) {
	raw := r.Context().Value("user_id")
	if raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case uint:
		return v, true
	case int:
		return uint(v), true
	case int64:
		return uint(v), true
	case uint64:
		return uint(v), true
	case float64:
		return uint(v), true
	}
	return 0, false
}

// writeMFARequired sends the standard 403 payload that the frontend reads
// to decide whether to show enrollment or unlock UI.
func writeMFARequired(w http.ResponseWriter, userID uint) {
	enrolled := false
	var enr models.MFAEnrollment
	if err := db.DB.Where("user_id = ?", userID).First(&enr).Error; err == nil {
		enrolled = enr.Enrolled
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-MFA-Required", "1")
	w.WriteHeader(http.StatusForbidden)
	// Hand-rolled to avoid importing encoding/json just for this in slice 0.
	body := `{"error":"mfa_required","enrolled":` + boolStr(enrolled) + `,"unlock_url":"/mfa/unlock"}`
	_, _ = w.Write([]byte(body))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// StartMFASweeper runs in a goroutine and periodically deletes expired
// DeviceSession rows so the table doesn't grow unbounded. Mirrors the
// pattern of auth.StartGC in link.go (Telegram bot project).
func StartMFASweeper() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			if db.DB == nil {
				continue
			}
			db.DB.Where("expires_at < ?", time.Now()).Delete(&models.DeviceSession{})
		}
	}()
}
