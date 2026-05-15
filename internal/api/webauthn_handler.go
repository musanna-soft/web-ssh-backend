package api

import (
	"encoding/json"
	"io"
	"net/http"

	"web-ssh-backend/internal/auth"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
)

// PostWebAuthnRegisterBegin starts a registration ceremony for a user who
// already has a TOTP-enrolled account and currently has an active session.
// Without an active session we'd be letting a JWT-only attacker register
// their own device — defence in depth.
func PostWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)
	if !auth.IsActive(uid, surface) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "mfa_required"})
		return
	}

	opts, handle, err := auth.BeginRegister(uid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"options": opts,
		"handle":  handle,
	})
}

type webauthnFinishInput struct {
	Handle string          `json:"handle"`
	Body   json.RawMessage `json:"body"`
	Label  string          `json:"label,omitempty"`
}

// PostWebAuthnRegisterFinish validates the attestation and saves the credential.
func PostWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var in webauthnFinishInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	row, err := auth.FinishRegister(uid, in.Handle, in.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Let the user label the device immediately if they provided one.
	if in.Label != "" {
		row.Label = in.Label
		_ = updateCredentialLabel(row.ID, in.Label)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"device_id": row.ID,
		"label":     row.Label,
	})
}

// PostWebAuthnLoginBegin returns the assertion options. The Mini App then
// invokes navigator.credentials.get(options) and POSTs the result to
// /api/mfa/webauthn/login/finish.
func PostWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	opts, handle, err := auth.BeginLogin(uid)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"options": opts,
		"handle":  handle,
	})
}

// PostWebAuthnLoginFinish validates the assertion and, on success, issues a
// fresh DeviceSession for the caller's surface.
func PostWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	uid, ok := mfaUserID(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	surface := mfaSurface(r)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var in webauthnFinishInput
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	row, err := auth.FinishLogin(uid, in.Handle, in.Body)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	if err := writeSession(uid, surface, "webauthn:"+row.Label); err != nil {
		http.Error(w, "session write", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"device_id": row.ID,
		"label":     row.Label,
	})
}

// updateCredentialLabel — small helper so callers can rename a freshly
// registered credential without a separate round-trip.
func updateCredentialLabel(credID uint, label string) error {
	return db.DB.Model(&models.WebAuthnCredential{}).
		Where("id = ?", credID).
		Update("label", label).Error
}
