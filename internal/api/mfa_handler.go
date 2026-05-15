package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"web-ssh-backend/internal/auth"
	"web-ssh-backend/internal/crypto"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// recoveryCodeCount — how many one-time backup codes are minted at enrollment
// or via /api/mfa/recovery/regenerate. 10 matches GitHub/Google/Bitwarden.
const recoveryCodeCount = 10

// ===== Helpers =====

func mfaUserID(r *http.Request) (uint, bool) {
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

func mfaSurface(r *http.Request) string {
	if s, ok := r.Context().Value("mfa_surface").(string); ok && s != "" {
		return s
	}
	return auth.SurfaceWeb
}

// mfaTelegramID returns the Telegram user id stored in the bot-surface
// session cookie, or 0 for the web surface. Used to scope DeviceSession
// rows per-Telegram-account so multi-account Telegram clients don't
// silently inherit each other's unlocks.
func mfaTelegramID(r *http.Request) int64 {
	return auth.TelegramIDFromContext(r)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func userEmail(userID uint) string {
	var u models.User
	if err := db.DB.Select("email").First(&u, userID).Error; err != nil {
		return ""
	}
	return u.Email
}

// ===== /api/mfa/status =====

// GetMFAStatus returns whether the caller is enrolled, how many trusted
// devices they have, whether they currently have an active session on this
// surface, and how many unused recovery codes remain.
func GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)

	var enrolment models.MFAEnrollment
	enrolled := false
	if err := db.DB.Where("user_id = ?", uid).First(&enrolment).Error; err == nil {
		enrolled = enrolment.Enrolled
	}

	var devCount int64
	db.DB.Model(&models.WebAuthnCredential{}).Where("user_id = ?", uid).Count(&devCount)

	sessionQuery := db.DB.Model(&models.DeviceSession{}).
		Where("user_id = ? AND surface = ? AND expires_at > ?", uid, surface, time.Now())
	if surface == auth.SurfaceBot {
		sessionQuery = sessionQuery.Where("telegram_id = ?", tgID)
	}
	var sessionCount int64
	sessionQuery.
		Count(&sessionCount)

	var recoveryRemaining int64
	db.DB.Model(&models.RecoveryCode{}).
		Where("user_id = ? AND used_at IS NULL", uid).
		Count(&recoveryRemaining)

	writeJSON(w, http.StatusOK, map[string]any{
		"enrolled":           enrolled,
		"devices":            devCount,
		"active":             sessionCount > 0,
		"surface":            surface,
		"recovery_remaining": recoveryRemaining,
		"mfa_required":       auth.MFARequired(),
	})
}

// ===== /api/mfa/totp/setup =====

type totpSetupResponse struct {
	Secret    string `json:"secret"`
	OtpAuth   string `json:"otpauth_url"`
	QRDataURL string `json:"qr_data_url"`
}

// PostTOTPSetup generates a fresh TOTP secret for the user. Refuses if the
// user is already enrolled — rotation goes through /api/mfa/recovery/regenerate
// + reset flow, not silent re-enrollment.
func PostTOTPSetup(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var existing models.MFAEnrollment
	err := db.DB.Where("user_id = ?", uid).First(&existing).Error
	if err == nil && existing.Enrolled {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "already_enrolled",
			"hint":  "use /api/mfa/reset to rotate",
		})
		return
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	email := userEmail(uid)
	if email == "" {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	secret, otpauthURL, qrURL, err := auth.GenerateTOTPSecret(email)
	if err != nil {
		http.Error(w, "failed to generate totp", http.StatusInternalServerError)
		return
	}

	encSecret, err := crypto.Encrypt(secret)
	if err != nil {
		http.Error(w, "encrypt failed", http.StatusInternalServerError)
		return
	}

	if existing.ID != 0 {
		existing.TotpSecretEnc = encSecret
		existing.Enrolled = false
		if err := db.DB.Save(&existing).Error; err != nil {
			http.Error(w, "db save", http.StatusInternalServerError)
			return
		}
	} else {
		row := models.MFAEnrollment{
			UserID:        uid,
			TotpSecretEnc: encSecret,
			Enrolled:      false,
		}
		if err := db.DB.Create(&row).Error; err != nil {
			http.Error(w, "db create", http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, http.StatusOK, totpSetupResponse{
		Secret:    secret,
		OtpAuth:   otpauthURL,
		QRDataURL: qrURL,
	})
}

// ===== /api/mfa/totp/verify =====

type totpVerifyInput struct {
	Code string `json:"code"`
}

type totpVerifyResponse struct {
	Enrolled       bool     `json:"enrolled"`
	RecoveryCodes  []string `json:"recovery_codes,omitempty"`
	SessionMinutes int      `json:"session_minutes,omitempty"`
}

// PostTOTPVerify finalizes enrollment when called for a not-yet-enrolled user
// (returns 10 plaintext recovery codes — shown ONCE), and otherwise issues a
// DeviceSession on the caller's surface (slice 1 "unlock via TOTP" fallback;
// in slice 2+ WebAuthn becomes the preferred unlock path).
func PostTOTPVerify(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)

	var in totpVerifyInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	var enr models.MFAEnrollment
	if err := db.DB.Where("user_id = ?", uid).First(&enr).Error; err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "not_setup"})
		return
	}

	secret, err := crypto.Decrypt(enr.TotpSecretEnc)
	if err != nil {
		http.Error(w, "decrypt failed", http.StatusInternalServerError)
		return
	}

	if !auth.VerifyTOTPCode(secret, in.Code) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad_code"})
		return
	}

	resp := totpVerifyResponse{
		SessionMinutes: int(auth.SessionTTL() / time.Minute),
	}

	if !enr.Enrolled {
		enr.Enrolled = true
		enr.EnrolledAt = time.Now()
		if err := db.DB.Save(&enr).Error; err != nil {
			http.Error(w, "db save", http.StatusInternalServerError)
			return
		}

		codes, hashErr := mintRecoveryCodes(uid)
		if hashErr != nil {
			http.Error(w, "recovery mint failed", http.StatusInternalServerError)
			return
		}
		resp.Enrolled = true
		resp.RecoveryCodes = codes
	} else {
		resp.Enrolled = true
	}

	if err := writeSession(uid, surface, mfaTelegramID(r), "totp"); err != nil {
		http.Error(w, "session write", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ===== /api/mfa/recovery/use =====

type recoveryUseInput struct {
	Code string `json:"code"`
}

// PostRecoveryUse accepts a backup code, marks it used, and unlocks the
// current surface. Falls back when phone is lost or all WebAuthn devices
// are revoked.
func PostRecoveryUse(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)

	var in recoveryUseInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	normalized := auth.NormalizeRecoveryCode(in.Code)
	if normalized == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty_code"})
		return
	}

	var rows []models.RecoveryCode
	if err := db.DB.Where("user_id = ? AND used_at IS NULL", uid).Find(&rows).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	var match *models.RecoveryCode
	for i := range rows {
		if bcrypt.CompareHashAndPassword([]byte(rows[i].CodeHash), []byte(normalized)) == nil {
			match = &rows[i]
			break
		}
	}
	if match == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad_code"})
		return
	}

	now := time.Now()
	match.UsedAt = &now
	if err := db.DB.Save(match).Error; err != nil {
		http.Error(w, "db save", http.StatusInternalServerError)
		return
	}

	if err := writeSession(uid, surface, mfaTelegramID(r), "recovery"); err != nil {
		http.Error(w, "session write", http.StatusInternalServerError)
		return
	}

	var remaining int64
	db.DB.Model(&models.RecoveryCode{}).
		Where("user_id = ? AND used_at IS NULL", uid).
		Count(&remaining)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"recovery_remaining": remaining,
	})
}

// ===== /api/mfa/recovery/regenerate =====

// PostRecoveryRegenerate wipes existing codes and mints 10 fresh ones.
// Returns the plaintext set exactly once. Requires the caller to already
// have an active DeviceSession on their surface — protects against a thief
// who steals a session blob but isn't biometrically verified yet.
func PostRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)

	if !auth.IsActive(uid, surface, tgID) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required"})
		return
	}

	if err := db.DB.Where("user_id = ?", uid).Delete(&models.RecoveryCode{}).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	codes, err := mintRecoveryCodes(uid)
	if err != nil {
		http.Error(w, "mint failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": codes,
	})
}

// ===== /api/mfa/lock =====

// PostMFALock deletes the caller's DeviceSession for the current surface
// without touching the other surface. Both surfaces lock independently.
func PostMFALock(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)

	// On the bot surface scope the delete to the specific Telegram account
	// so locking from one account doesn't kick the others.
	q := db.DB.Where("user_id = ? AND surface = ?", uid, surface)
	if surface == auth.SurfaceBot {
		q = q.Where("telegram_id = ?", tgID)
	}
	if err := q.Delete(&models.DeviceSession{}).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	auth.InvalidateActiveCache(uid, surface, tgID)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ===== /api/mfa/reset =====

// PostMFAReset wipes the caller's TOTP secret, all WebAuthn credentials,
// all recovery codes, and all DeviceSessions, returning them to the
// "never enrolled" state. Requires an active session on the current
// surface so a stolen JWT or initData blob cannot trigger it.
//
// After reset the next gated request returns 403 mfa_required with
// enrolled=false and the user goes through /mfa/setup again from scratch.
func PostMFAReset(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	if !auth.IsActive(uid, surface, mfaTelegramID(r)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required"})
		return
	}

	// Delete in dependency order — none of these have FKs to each other
	// but doing them in one transaction keeps the UI's status checks
	// from briefly observing a half-reset state.
	tx := db.DB.Begin()
	if err := tx.Where("user_id = ?", uid).Delete(&models.RecoveryCode{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err := tx.Where("user_id = ?", uid).Delete(&models.WebAuthnCredential{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err := tx.Where("user_id = ?", uid).Delete(&models.DeviceSession{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err := tx.Where("user_id = ?", uid).Delete(&models.MFAEnrollment{}).Error; err != nil {
		tx.Rollback()
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit().Error; err != nil {
		http.Error(w, "db commit", http.StatusInternalServerError)
		return
	}
	// Reset wipes every DeviceSession row across surfaces and Telegram
	// accounts, so blow the cache for the calling identity. Other rows
	// that may have lived in the cache for the same user (different
	// Telegram accounts) will expire on the 5s TTL.
	auth.InvalidateActiveCache(uid, auth.SurfaceWeb, 0)
	auth.InvalidateActiveCache(uid, auth.SurfaceBot, mfaTelegramID(r))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ===== /api/mfa/devices =====

type deviceListEntry struct {
	ID         uint      `json:"id"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// GetMFADevices returns the caller's registered WebAuthn credentials.
// Slice 1 may return an empty list (no devices registered yet).
func GetMFADevices(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var creds []models.WebAuthnCredential
	if err := db.DB.Where("user_id = ?", uid).Order("created_at DESC").Find(&creds).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	out := make([]deviceListEntry, 0, len(creds))
	for _, c := range creds {
		out = append(out, deviceListEntry{
			ID:         c.ID,
			Label:      c.Label,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// DeleteMFADevice revokes a registered WebAuthn credential. Requires an
// active session — otherwise an attacker with a stolen JWT could lock out
// the legitimate owner by deleting all their credentials.
func DeleteMFADevice(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	if !auth.IsActive(uid, surface, mfaTelegramID(r)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required"})
		return
	}

	idStr := mux.Vars(r)["id"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	if err := db.DB.Where("user_id = ? AND id = ?", uid, id).
		Delete(&models.WebAuthnCredential{}).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ===== Internal helpers =====

// mintRecoveryCodes generates a fresh set of 10 codes, hashes them, persists
// the hashes, and returns the plaintext for one-time display to the user.
func mintRecoveryCodes(userID uint) ([]string, error) {
	codes, err := auth.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}

	rows := make([]models.RecoveryCode, 0, len(codes))
	for _, c := range codes {
		normalized := auth.NormalizeRecoveryCode(c)
		hash, herr := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
		if herr != nil {
			return nil, herr
		}
		rows = append(rows, models.RecoveryCode{
			UserID:   userID,
			CodeHash: string(hash),
		})
	}

	if err := db.DB.Create(&rows).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

func writeSession(userID uint, surface string, telegramID int64, deviceLabel string) error {
	// Single active session per (user, surface, telegram_id). For the web
	// surface telegramID is always 0 — there is no per-account split.
	q := db.DB.Where("user_id = ? AND surface = ?", userID, surface)
	if surface == auth.SurfaceBot {
		q = q.Where("telegram_id = ?", telegramID)
	}
	if err := q.Delete(&models.DeviceSession{}).Error; err != nil {
		return err
	}
	row := models.DeviceSession{
		UserID:      userID,
		Surface:     surface,
		TelegramID:  telegramID,
		ExpiresAt:   time.Now().Add(auth.SessionTTL()),
		DeviceLabel: deviceLabel,
	}
	if err := db.DB.Create(&row).Error; err != nil {
		return err
	}
	auth.InvalidateActiveCache(userID, surface, telegramID)
	return nil
}
