package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"web-ssh-backend/internal/db"
)

// telegramUserLink mirrors the schema the remofy-bot project AutoMigrates
// as models.TelegramUser. We READ-ONLY from this table here; the bot
// owns writes. Keep this struct's column tags in sync with the bot's model.
type telegramUserLink struct {
	ID         uint
	TelegramID int64
	UserID     uint
	Username   string
}

func (telegramUserLink) TableName() string { return "telegram_users" }

// initDataInput is the JSON body the Mini App sends to /api/mfa/verify-telegram.
type initDataInput struct {
	InitData string `json:"init_data"`
}

// VerifyTelegramAndMint exchanges a valid Telegram Mini App initData blob for
// a short-lived signed cookie that carries the resolved web-ssh user_id.
// Mounted at /api/mfa/verify-telegram (no other auth required — initData
// itself is the proof).
//
// Flow:
//  1. HMAC-verify initData against TELEGRAM_BOT_TOKEN
//  2. Look up telegram_users WHERE telegram_id = initData.user.id
//  3. If linked → set HttpOnly mfa_session cookie carrying user_id (15 min)
//  4. If unlinked → 409 telling the Mini App to send the user back to /start
func VerifyTelegramAndMint(w http.ResponseWriter, r *http.Request) {
	var in initDataInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	tgUser, err := VerifyTelegramInitData(in.InitData, botToken)
	if err != nil {
		http.Error(w, "invalid initData: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var link telegramUserLink
	if err := db.DB.Where("telegram_id = ?", tgUser.ID).First(&link).Error; err != nil {
		// Not linked yet — Mini App should redirect user to /start in the bot.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":       "not_linked",
			"telegram_id": tgUser.ID,
			"hint":        "open the bot and run /start to link your Google account first",
		})
		return
	}

	if err := setMFASessionCookie(w, link.UserID, SurfaceBot, tgUser.ID); err != nil {
		http.Error(w, "failed to mint session", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"user_id":       link.UserID,
		"telegram_id":   tgUser.ID,
		"telegram_user": tgUser.Username,
	})
}

// RequireMFASessionCookie is the middleware that gates /api/mfa/*
// endpoints under the bot surface. It reads the mfa_session cookie,
// verifies its HMAC, and injects user_id and surface into the context.
//
// On miss → 401, which the Mini App should treat as "call verify-telegram
// again with a fresh initData".
func RequireMFASessionCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, surface, tg, err := readMFASessionCookie(r)
		if err != nil {
			http.Error(w, "missing or invalid mfa_session: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", uid)
		ctx = context.WithValue(ctx, "mfa_surface", surface)
		ctx = context.WithValue(ctx, "mfa_telegram_id", tg)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TelegramIDFromContext extracts the Telegram user id stored in the
// mfa_session cookie. Returns 0 for non-bot surfaces.
func TelegramIDFromContext(r *http.Request) int64 {
	if v, ok := r.Context().Value("mfa_telegram_id").(int64); ok {
		return v
	}
	return 0
}

// surfaceFromContext returns "web" or "bot" based on which middleware set up
// the request. AuthMiddleware (JWT) implies web; RequireMFASessionCookie
// stores the surface explicitly.
func surfaceFromContext(r *http.Request) string {
	if s, ok := r.Context().Value("mfa_surface").(string); ok && s != "" {
		return s
	}
	return SurfaceWeb
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// errNotLinked is returned when the resolved Telegram user has no matching
// telegram_users row. Exported for handler-level error matching.
var errNotLinked = errors.New("telegram user not linked")
