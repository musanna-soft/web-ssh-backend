package auth

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// challengeTTL — how long a registration/login ceremony can stay open before
// it expires. Five minutes matches the Telegram initData freshness window.
const challengeTTL = 5 * time.Minute

var (
	rpOnce sync.Once
	rp     *webauthn.WebAuthn
	rpErr  error

	sessionsMu sync.Mutex
	// sessions key is a random string returned to the client; the value
	// holds everything go-webauthn needs to call FinishRegistration or
	// FinishLogin. Cleared on success or expiry sweep.
	sessions = map[string]*pendingCeremony{}
)

type pendingCeremony struct {
	userID    uint
	session   webauthn.SessionData
	kind      string // "register" or "login"
	createdAt time.Time
}

// RP returns the lazily-built WebAuthn Relying Party, derived from
// PUBLIC_BASE_URL. The RP ID is the hostname (no scheme, no port),
// and the RP Origin is the full origin. Both ends MUST agree.
func RP() (*webauthn.WebAuthn, error) {
	rpOnce.Do(func() {
		rawURL := strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/")
		if rawURL == "" {
			rpErr = errors.New("PUBLIC_BASE_URL is not set")
			return
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			rpErr = fmt.Errorf("PUBLIC_BASE_URL: %w", err)
			return
		}
		cfg := &webauthn.Config{
			RPID:          u.Hostname(),
			RPDisplayName: "Remofy",
			RPOrigins:     []string{rawURL},
		}
		rp, rpErr = webauthn.New(cfg)
	})
	return rp, rpErr
}

// webauthnUser adapts our models.User into the webauthn.User interface that
// go-webauthn expects. Credentials are loaded fresh from the DB on each
// ceremony — there is no in-memory user cache.
type webauthnUser struct {
	id    uint
	email string
	creds []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("user-%d", u.id))
}
func (u *webauthnUser) WebAuthnName() string       { return u.email }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.email }
func (u *webauthnUser) WebAuthnIcon() string        { return "" }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

func loadWebAuthnUser(userID uint) (*webauthnUser, error) {
	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("user: %w", err)
	}
	var rows []models.WebAuthnCredential
	if err := db.DB.Where("user_id = ?", userID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("creds: %w", err)
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		creds = append(creds, webauthn.Credential{
			ID:        r.CredentialID,
			PublicKey: r.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: r.SignCount,
			},
		})
	}
	return &webauthnUser{id: user.ID, email: user.Email, creds: creds}, nil
}

// putSession stashes a pending registration/login. Returns the client-side
// handle.
func putSession(kind string, userID uint, sd webauthn.SessionData) string {
	handle := randomNonce()
	sessionsMu.Lock()
	sessions[handle] = &pendingCeremony{
		userID:    userID,
		session:   sd,
		kind:      kind,
		createdAt: time.Now(),
	}
	sessionsMu.Unlock()
	return handle
}

func popSession(handle, kind string) (*pendingCeremony, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	p, ok := sessions[handle]
	if !ok {
		return nil, errors.New("session not found")
	}
	delete(sessions, handle)
	if p.kind != kind {
		return nil, errors.New("session kind mismatch")
	}
	if time.Since(p.createdAt) > challengeTTL {
		return nil, errors.New("session expired")
	}
	return p, nil
}

// StartWebAuthnSweeper periodically removes expired ceremony sessions so
// the in-memory map can't grow unbounded under load.
func StartWebAuthnSweeper() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			sessionsMu.Lock()
			for h, s := range sessions {
				if time.Since(s.createdAt) > challengeTTL {
					delete(sessions, h)
				}
			}
			sessionsMu.Unlock()
		}
	}()
}

// BeginRegister produces the JSON the browser hands to navigator.credentials.create.
func BeginRegister(userID uint) (options *protocol.CredentialCreation, handle string, err error) {
	web, err := RP()
	if err != nil {
		return nil, "", err
	}
	u, err := loadWebAuthnUser(userID)
	if err != nil {
		return nil, "", err
	}
	opts, sd, err := web.BeginRegistration(u)
	if err != nil {
		return nil, "", err
	}
	handle = putSession("register", userID, *sd)
	return opts, handle, nil
}

// FinishRegister validates the client's attestation response and persists
// the new credential row. Returns the friendly label echo for the caller.
func FinishRegister(userID uint, handle string, body []byte) (*models.WebAuthnCredential, error) {
	web, err := RP()
	if err != nil {
		return nil, err
	}
	pending, err := popSession(handle, "register")
	if err != nil {
		return nil, err
	}
	if pending.userID != userID {
		return nil, errors.New("user mismatch")
	}
	u, err := loadWebAuthnUser(userID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}
	cred, err := web.CreateCredential(u, pending.session, parsed)
	if err != nil {
		return nil, fmt.Errorf("create credential: %w", err)
	}

	row := models.WebAuthnCredential{
		UserID:       userID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Label:        defaultLabel(parsed),
		LastUsedAt:   time.Now(),
	}
	if err := db.DB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("db create: %w", err)
	}
	return &row, nil
}

// BeginLogin returns the assertion options for navigator.credentials.get.
// Caller must have already passed identity verification (JWT or
// initData-derived cookie) — this call merely starts the WebAuthn ceremony.
func BeginLogin(userID uint) (*protocol.CredentialAssertion, string, error) {
	web, err := RP()
	if err != nil {
		return nil, "", err
	}
	u, err := loadWebAuthnUser(userID)
	if err != nil {
		return nil, "", err
	}
	if len(u.creds) == 0 {
		return nil, "", errors.New("no credentials registered")
	}
	opts, sd, err := web.BeginLogin(u)
	if err != nil {
		return nil, "", err
	}
	handle := putSession("login", userID, *sd)
	return opts, handle, nil
}

// FinishLogin validates the assertion. On success, updates the matched
// credential's SignCount + LastUsedAt and returns the credential row.
func FinishLogin(userID uint, handle string, body []byte) (*models.WebAuthnCredential, error) {
	web, err := RP()
	if err != nil {
		return nil, err
	}
	pending, err := popSession(handle, "login")
	if err != nil {
		return nil, err
	}
	if pending.userID != userID {
		return nil, errors.New("user mismatch")
	}
	u, err := loadWebAuthnUser(userID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse assertion: %w", err)
	}
	cred, err := web.ValidateLogin(u, pending.session, parsed)
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	var row models.WebAuthnCredential
	if err := db.DB.Where("user_id = ? AND credential_id = ?", userID, cred.ID).First(&row).Error; err != nil {
		return nil, fmt.Errorf("locate row: %w", err)
	}
	row.SignCount = cred.Authenticator.SignCount
	row.LastUsedAt = time.Now()
	if err := db.DB.Save(&row).Error; err != nil {
		return nil, fmt.Errorf("update row: %w", err)
	}
	return &row, nil
}

func defaultLabel(parsed *protocol.ParsedCredentialCreationData) string {
	if parsed == nil {
		return "passkey"
	}
	if t := parsed.Response.AttestationObject.AuthData.AttData.AAGUID; len(t) > 0 {
		// AAGUID is rarely human-readable; we just acknowledge it exists.
		// The frontend can rename later via /api/mfa/devices/{id}.
		return "passkey"
	}
	return "passkey"
}
