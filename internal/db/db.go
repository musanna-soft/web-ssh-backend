package db

import (
	"log"
	"os"
	"time"

	"web-ssh-backend/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init initializes the database connection and performs auto-migration.
func Init() {
	var err error
	dsn := os.Getenv("DB_PATH")
	if dsn == "" {
		log.Fatalf("DB_PATH environment variable is not set")
	}

	// Quieter logger — MFA code paths intentionally use First() to probe
	// for rows, so "record not found" is the expected non-error outcome.
	gormLogger := logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLogger})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection established")

	// Auto Migrate - Order matters! Migrate referenced tables first
	// Folder must be migrated before Server because Server has a foreign key to Folder
	err = DB.AutoMigrate(
		&models.User{},
		&models.Folder{},
		&models.Server{},
		&models.MFAEnrollment{},
		&models.WebAuthnCredential{},
		&models.DeviceSession{},
		&models.RecoveryCode{},
		&models.DevicePin{},
	)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Partial unique index on the platform subject.
	//
	// It cannot be a plain unique index: rows created before login moved to musanna carry
	// an empty subject, and there are 28 of them. `WHERE platform_sub <> ''` leaves those
	// alone while still guaranteeing that one musanna account maps to at most one row here.
	//
	// The rows fill in as people sign in: the first login matches by e-mail and writes the
	// subject onto the existing row, so nobody loses their servers.
	if err := DB.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_platform_sub
		ON users (platform_sub) WHERE platform_sub <> ''
	`).Error; err != nil {
		log.Fatalf("Failed to create platform_sub index: %v", err)
	}

	log.Println("Database migration completed")
}
