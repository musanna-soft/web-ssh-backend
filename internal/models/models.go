package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a registered user.
type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	GoogleID  string         `gorm:"uniqueIndex;not null" json:"google_id"`
	Email     string         `gorm:"uniqueIndex;not null" json:"email"`
	Name      string         `json:"name"`
	AvatarURL string         `json:"avatar_url"`
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
