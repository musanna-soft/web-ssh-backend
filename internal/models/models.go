package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a registered user.
type User struct {
	ID uint `gorm:"primaryKey" json:"id"`

	// PlatformSub is the musanna-platform `sub` claim — who the person is over
	// there. It replaced GoogleID when login moved to the platform IdP. The
	// subject is stable across e-mail changes, and unlike the Google id it is
	// issued by the same system that owns organisations, roles and MFA.
	PlatformSub string `gorm:"column:platform_sub;uniqueIndex;not null" json:"platform_sub"`

	Email     string `gorm:"uniqueIndex;not null" json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`

	// PlanCode and ServerLimit are a CACHE of the platform's answer, refreshed
	// at every login. web-ssh only holds the platform token during the login
	// exchange, so re-asking on each request is not possible without storing
	// that token — and storing somebody's platform credential to check their
	// own plan is a worse trade than a slightly stale limit.
	//
	// The staleness window is one login. An upgrade takes effect when the
	// person signs in again, which is also when they come back from the
	// console anyway.
	PlanCode string `gorm:"column:plan_code" json:"plan_code"`

	// ServerLimit is how many servers the plan allows. Zero means the plan did
	// not state a limit, and that is read as UNLIMITED — an absent limit is not
	// a zero limit.
	ServerLimit int64 `gorm:"column:server_limit" json:"server_limit"`

	Servers   []Server       `gorm:"foreignKey:UserID" json:"servers,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// Folder represents a group of servers.
type Folder struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	UserID    uint           `gorm:"index;not null" json:"user_id"`
	Name      string         `gorm:"not null" json:"name"`
	Servers   []Server       `gorm:"foreignKey:FolderID" json:"servers,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// Server represents a remote server configuration.
type Server struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	UserID          uint           `gorm:"index;not null" json:"user_id"`
	FolderID        *uint          `gorm:"index" json:"folder_id"` // Nullable
	Name            string         `gorm:"not null" json:"name"`
	Host            string         `gorm:"not null" json:"host"`
	Port            int            `gorm:"default:22" json:"port"`
	Username        string         `gorm:"not null" json:"username"`
	AuthType        string         `gorm:"not null" json:"auth_type"` // "password" or "key"
	EncryptedSecret string         `gorm:"not null" json:"-"`         // Encrypted password or private key
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}
