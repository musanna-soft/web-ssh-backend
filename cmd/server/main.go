package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"web-ssh-backend/internal/api"
	"web-ssh-backend/internal/auth"
	"web-ssh-backend/internal/crypto"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/sftp"
	"web-ssh-backend/internal/ssh"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		dsn := os.Getenv("DB_PATH")
		if dsn == "" {
			log.Println("No .env file found")
		}
	}

	// Initialize subsystems
	db.Init()
	auth.Init()
	crypto.Init()

	r := mux.NewRouter()

	// Auth Routes
	r.HandleFunc("/auth/google/login", auth.HandleGoogleLogin).Methods("GET")
	r.HandleFunc("/auth/google/callback", auth.HandleGoogleCallback).Methods("GET")

	// API Routes (Protected)
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.Use(auth.AuthMiddleware)
	apiRouter.HandleFunc("/servers", api.GetServers).Methods("GET")
	apiRouter.HandleFunc("/servers", api.CreateServer).Methods("POST")
	apiRouter.HandleFunc("/servers", api.UpdateServer).Methods("PUT")
	apiRouter.HandleFunc("/servers", api.DeleteServer).Methods("DELETE")
	apiRouter.HandleFunc("/me", api.GetCurrentUser).Methods("GET")

	apiRouter.HandleFunc("/folders", api.GetFolders).Methods("GET")
	apiRouter.HandleFunc("/folders", api.CreateFolder).Methods("POST")
	apiRouter.HandleFunc("/folders", api.DeleteFolder).Methods("DELETE")

	// WebSocket Route (Protected by Token in Query Param)
	r.HandleFunc("/ws/ssh", ssh.HandleSSHWebSocket)
	r.HandleFunc("/ws/sftp", sftp.HandleSFTPWebSocket)

	// SFTP API Routes (Protected)
	apiRouter.HandleFunc("/sftp/download", sftp.HandleDownload).Methods("GET")
	apiRouter.HandleFunc("/sftp/upload", sftp.HandleUpload).Methods("POST")
	apiRouter.HandleFunc("/sftp/content", sftp.HandleSaveFileContent).Methods("POST")
	apiRouter.HandleFunc("/sftp/zip", sftp.HandleDownloadZip).Methods("GET")
	apiRouter.HandleFunc("/sftp/move", sftp.HandleMoveFile).Methods("POST")
	apiRouter.HandleFunc("/sftp/copy", sftp.HandleCopyFile).Methods("POST")
	apiRouter.HandleFunc("/transfer", sftp.HandleTransfer).Methods("POST")

	// CORS Setup - Use FRONTEND_URL for allowed origins
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:5173"
	}
	// Support comma-separated URLs for multiple origins
	origins := strings.Split(frontendURL, ",")

	c := cors.New(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
