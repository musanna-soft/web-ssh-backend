package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"web-ssh-backend/internal/auth"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// PIN policy: 4-8 digits. Server enforces digit-only + length; clients
// should also validate before submitting.
var pinRegex = regexp.MustCompile(`^\d{4,8}$`)

const (
	// pinMaxAttempts wrong tries before a lockout window kicks in.
	pinMaxAttempts = 5
	// pinLockoutWindow how long a locked-out device must wait before its
	// counter is allowed to reset and accept attempts again.
	pinLockoutWindow = 5 * time.Minute
)

// ===== GET /api/mfa/pin/devices =====

type pinDeviceEntry struct {
	ID         uint      `json:"id"`
	Label      string    `json:"label"`
	TelegramID int64     `json:"telegram_id"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// GetPinDevices lists all PIN-protected device bindings for the caller.
// On the web surface every binding is shown (cross-account view); on the
// bot surface the list is scoped to the current Telegram account so a
// second account can't enumerate the first one's PINs.
func GetPinDevices(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)

	q := db.DB.Where("user_id = ?", uid)
	if surface == auth.SurfaceBot {
		q = q.Where("telegram_id = ?", tgID)
	}

	var rows []models.DevicePin
	if err := q.Order("created_at DESC").Find(&rows).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	out := make([]pinDeviceEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, pinDeviceEntry{
			ID:         r.ID,
			Label:      r.Label,
			TelegramID: r.TelegramID,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// ===== /api/mfa/pin/register =====

type pinRegisterInput struct {
	Pin   string `json:"pin"`
	Label string `json:"label,omitempty"`
}

type pinRegisterResponse struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
}

// PostPinRegister creates a new PIN-protected device binding for the
// caller. Requires an active session on the caller's surface so a stolen
// Telegram session alone can't enrol a fresh PIN. Returns a server-
// generated DeviceID the client stashes in localStorage and presents on
// subsequent unlocks alongside the PIN.
func PostPinRegister(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)
	if surface != auth.SurfaceBot || tgID == 0 {
		// PINs are scoped to a specific Telegram install. We don't expose
		// them on the web surface — passkeys are stronger and the browser
		// already has its own auth.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "pin_bot_only"})
		return
	}
	if !auth.IsActive(uid, surface, tgID) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required"})
		return
	}

	var in pinRegisterInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !pinRegex.MatchString(in.Pin) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_pin"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Pin), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "hash failed", http.StatusInternalServerError)
		return
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, "random failed", http.StatusInternalServerError)
		return
	}
	deviceID := hex.EncodeToString(raw[:])

	label := in.Label
	if label == "" {
		label = "Telegram PIN"
	}

	row := models.DevicePin{
		UserID:     uid,
		TelegramID: tgID,
		DeviceID:   deviceID,
		PinHash:    string(hash),
		Label:      label,
	}
	if err := db.DB.Create(&row).Error; err != nil {
		http.Error(w, "db create", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, pinRegisterResponse{
		DeviceID: deviceID,
		Label:    label,
	})
}

// ===== /api/mfa/pin/unlock =====

type pinUnlockInput struct {
	DeviceID string `json:"device_id"`
	Pin      string `json:"pin"`
}

// PostPinUnlock verifies a (device_id, pin) tuple and on success issues a
// DeviceSession identical to the one TOTP unlock produces. Implements a
// per-device lockout to stop someone with localStorage access from brute-
// forcing the PIN.
func PostPinUnlock(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	tgID := mfaTelegramID(r)
	if surface != auth.SurfaceBot || tgID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "pin_bot_only"})
		return
	}

	var in pinUnlockInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if in.DeviceID == "" || !pinRegex.MatchString(in.Pin) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_input"})
		return
	}

	var row models.DevicePin
	err := db.DB.
		Where("device_id = ? AND user_id = ? AND telegram_id = ?", in.DeviceID, uid, tgID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unknown_device"})
		return
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Lockout check.
	if row.LockedUntil != nil && time.Now().Before(*row.LockedUntil) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "locked",
			"retry_seconds": int(time.Until(*row.LockedUntil).Seconds()),
		})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(row.PinHash), []byte(in.Pin)) != nil {
		row.FailedAttempts++
		if row.FailedAttempts >= pinMaxAttempts {
			until := time.Now().Add(pinLockoutWindow)
			row.LockedUntil = &until
			row.FailedAttempts = 0
		}
		_ = db.DB.Save(&row).Error
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":    "bad_pin",
			"attempts": row.FailedAttempts,
		})
		return
	}

	// Success: reset rate-limit state, refresh LastUsedAt, issue session.
	row.FailedAttempts = 0
	row.LockedUntil = nil
	row.LastUsedAt = time.Now()
	if err := db.DB.Save(&row).Error; err != nil {
		http.Error(w, "db save", http.StatusInternalServerError)
		return
	}

	if err := writeSession(uid, surface, tgID, "pin:"+row.Label); err != nil {
		http.Error(w, "session write", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"label": row.Label,
	})
}

// ===== DELETE /api/mfa/pin/devices/{id} =====

// DeletePinDevice removes a PIN-protected device binding. Requires an
// active session so a stolen cookie can't lock out the user by deleting
// all their PINs.
func DeletePinDevice(w http.ResponseWriter, r *http.Request) {
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

	idStr := mux.Vars(r)["id"]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	if err := db.DB.Where("user_id = ? AND id = ?", uid, id).
		Delete(&models.DevicePin{}).Error; err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
