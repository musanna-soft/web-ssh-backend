package models

import "time"

// MFAEnrollment — per-user TOTP secret. Created once via /api/mfa/totp/setup,
// finalized via /api/mfa/totp/verify (sets Enrolled=true). Reset requires
// an active DeviceSession plus a fresh WebAuthn assertion.
type MFAEnrollment struct {
	ID            uint   `gorm:"primaryKey" json:"id"`
	UserID        uint   `gorm:"uniqueIndex;not null" json:"user_id"`
	User          User   `gorm:"foreignKey:UserID" json:"-"`
	TotpSecretEnc string `gorm:"not null" json:"-"` // crypto.Encrypt(secret)
	Enrolled      bool   `gorm:"not null;default:false" json:"enrolled"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// WebAuthnCredential — a registered passkey/platform authenticator (FaceID,
// Touch ID, Windows Hello, Android biometrics). One user can register many.
type WebAuthnCredential struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       uint      `gorm:"index;not null" json:"user_id"`
	User         User      `gorm:"foreignKey:UserID" json:"-"`
	CredentialID []byte    `gorm:"uniqueIndex;not null" json:"-"`
	PublicKey    []byte    `gorm:"not null" json:"-"`
	SignCount    uint32    `gorm:"not null;default:0" json:"-"`
	Label        string    `json:"label"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// DeviceSession — a 30-minute (configurable) active window granted after a
// successful WebAuthn assertion (or TOTP unlock during slice 1).
//
// Scope keys:
//   - UserID + Surface = "web": one session per web-ssh user; the
//     stateless browser frontend doesn't have a more granular identity.
//   - UserID + Surface = "bot" + TelegramID: one session per Telegram
//     account. When a user has multiple Telegram accounts linked to the
//     same web-ssh user (e.g. multi-account in one Telegram app), each
//     must unlock independently — otherwise unlocking on account A
//     would silently grant bot access from account B.
type DeviceSession struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	UserID      uint      `gorm:"index;not null" json:"user_id"`
	User        User      `gorm:"foreignKey:UserID" json:"-"`
	Surface     string    `gorm:"not null;size:16;index" json:"surface"` // "web" or "bot"
	TelegramID  int64     `gorm:"index;not null;default:0" json:"telegram_id"`
	ExpiresAt   time.Time `gorm:"index;not null" json:"expires_at"`
	DeviceLabel string    `json:"device_label"`
	CreatedAt   time.Time `json:"created_at"`
}

// DevicePin — a 4-6 digit local passcode bound to a single Telegram client
// install. Modelled on Telegram Wallet's PIN: server stores only the
// bcrypt hash, the Mini App holds a random DeviceID in localStorage that
// proves which row to look up on unlock. Bound to (UserID, TelegramID)
// so a second Telegram account in the same client can't reuse the PIN.
//
// Rate-limit: FailedAttempts is bumped on each wrong submission; once it
// hits 5 the LockedUntil window blocks further attempts for 5 minutes.
// A successful unlock resets the counter.
type DevicePin struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	UserID         uint       `gorm:"index;not null" json:"user_id"`
	User           User       `gorm:"foreignKey:UserID" json:"-"`
	TelegramID     int64      `gorm:"index;not null" json:"telegram_id"`
	DeviceID       string     `gorm:"uniqueIndex;not null;size:64" json:"-"`
	PinHash        string     `gorm:"not null" json:"-"`
	Label          string     `json:"label"`
	FailedAttempts int        `gorm:"not null;default:0" json:"-"`
	LockedUntil    *time.Time `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     time.Time  `json:"last_used_at"`
}

// RecoveryCode — one-time-use backup code (10 generated at enrollment).
// Shown to the user exactly once in plaintext; only the bcrypt hash is
// stored. When the user later submits a code at /api/mfa/recovery/use, the
// row is matched by hash, UsedAt is set, and a DeviceSession is issued.
//
// Regenerating codes (/api/mfa/recovery/regenerate) deletes ALL prior rows
// and creates a fresh set of 10 — preserves the "any unused code is valid"
// invariant.
type RecoveryCode struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	UserID    uint       `gorm:"index;not null" json:"user_id"`
	User      User       `gorm:"foreignKey:UserID" json:"-"`
	CodeHash  string     `gorm:"not null" json:"-"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
