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
	"web-ssh-backend/internal/miniapp"
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
	auth.StartMFASweeper()
	auth.StartWebAuthnSweeper()

	r := mux.NewRouter()

	// Auth Routes
	r.HandleFunc("/auth/google/login", auth.HandleGoogleLogin).Methods("GET")
	r.HandleFunc("/auth/google/callback", auth.HandleGoogleCallback).Methods("GET")

	// MFA bootstrap (Telegram Mini App entry point — no JWT, initData is the proof)
	r.HandleFunc("/api/mfa/verify-telegram", auth.VerifyTelegramAndMint).Methods("POST")

	// Mini App static assets (HTML/JS embedded into the binary)
	r.PathPrefix("/mfa/bot/").Handler(miniapp.Handler())

	// MFA routes for the Telegram bot surface — require the mfa_session cookie
	// minted by /api/mfa/verify-telegram. These do NOT pass through the JWT
	// AuthMiddleware because Mini App users are identified via initData only.
	botMFARouter := r.PathPrefix("/api/mfa/bot").Subrouter()
	botMFARouter.Use(auth.RequireMFASessionCookie)
	registerMFARoutes(botMFARouter, "bot")

	// API Routes (Protected)
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.Use(auth.AuthMiddleware)
	apiRouter.Use(auth.MFAGate)

	// MFA routes for the web surface — under /api so the JWT middleware
	// applies. The MFAGate above exempts /api/mfa/* paths.
	webMFARouter := apiRouter.PathPrefix("/mfa").Subrouter()
	registerMFARoutes(webMFARouter, "web")
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
		// Without ExposedHeaders the browser strips the X-MFA-* headers,
		// so the frontend can't see when it's in the grace period.
		ExposedHeaders:   []string{"X-MFA-Required", "X-MFA-Warning", "X-MFA-Grace-Until"},
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

// registerMFARoutes wires the /mfa/* endpoints onto the given subrouter.
// Called twice — once under /api (web surface, JWT-authenticated) and once
// under /api/mfa/bot (Telegram surface, cookie-authenticated). The handlers
// themselves read the surface from request context, so the same code paths
// serve both call sites.
func registerMFARoutes(r *mux.Router, _ string) {
	r.HandleFunc("/status", api.GetMFAStatus).Methods("GET", "POST")
	r.HandleFunc("/totp/setup", api.PostTOTPSetup).Methods("POST")
	r.HandleFunc("/totp/verify", api.PostTOTPVerify).Methods("POST")
	r.HandleFunc("/recovery/use", api.PostRecoveryUse).Methods("POST")
	r.HandleFunc("/recovery/regenerate", api.PostRecoveryRegenerate).Methods("POST")
	r.HandleFunc("/lock", api.PostMFALock).Methods("POST")
	r.HandleFunc("/devices", api.GetMFADevices).Methods("GET")
	r.HandleFunc("/devices/{id}", api.DeleteMFADevice).Methods("DELETE")
	r.HandleFunc("/webauthn/register/begin", api.PostWebAuthnRegisterBegin).Methods("POST")
	r.HandleFunc("/webauthn/register/finish", api.PostWebAuthnRegisterFinish).Methods("POST")
	r.HandleFunc("/webauthn/login/begin", api.PostWebAuthnLoginBegin).Methods("POST")
	r.HandleFunc("/webauthn/login/finish", api.PostWebAuthnLoginFinish).Methods("POST")
}
