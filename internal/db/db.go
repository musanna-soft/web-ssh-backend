package db

import (
	"log"
	"os"

	"web-ssh-backend/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

// Init initializes the database connection and performs auto-migration.
func Init() {
	var err error
	dsn := os.Getenv("DB_PATH")
	if dsn == "" {
		log.Fatalf("DB_PATH environment variable is not set")
	}

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection established")

	// Auto Migrate - Order matters! Migrate referenced tables first
	// Folder must be migrated before Server because Server has a foreign key to Folder
	err = DB.AutoMigrate(&models.User{}, &models.Folder{}, &models.Server{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database migration completed")
}
