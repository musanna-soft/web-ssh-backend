package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"web-ssh-backend/internal/crypto"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"

	"gorm.io/gorm"
)

func GetServers(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64) // JWT claims are float64

	var servers []models.Server
	if err := db.DB.Where("user_id = ?", uint(userID)).Find(&servers).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

func CreateServer(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)

	var req struct {
		Name     string `json:"name"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		AuthType string `json:"auth_type"`
		Secret   string `json:"secret"` // Password or Key
		FolderID *uint  `json:"folder_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	encryptedSecret, err := crypto.Encrypt(req.Secret)
	if err != nil {
		http.Error(w, "Failed to encrypt secret", http.StatusInternalServerError)
		return
	}

	server := models.Server{
		UserID:          uint(userID),
		FolderID:        req.FolderID,
		Name:            req.Name,
		Host:            req.Host,
		Port:            req.Port,
		Username:        req.Username,
		AuthType:        req.AuthType,
		EncryptedSecret: encryptedSecret,
	}

	if err := db.DB.Create(&server).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

func UpdateServer(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)
	serverID := r.URL.Query().Get("id")

	var server models.Server
	if err := db.DB.Where("id = ? AND user_id = ?", serverID, uint(userID)).First(&server).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "Server not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var req struct {
		Name     string `json:"name"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		AuthType string `json:"auth_type"`
		Secret   string `json:"secret"`
		FolderID *uint  `json:"folder_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	server.Name = req.Name
	server.Host = req.Host
	server.Port = req.Port
	server.Username = req.Username
	server.AuthType = req.AuthType
	server.FolderID = req.FolderID

	if req.Secret != "" {
		encryptedSecret, err := crypto.Encrypt(req.Secret)
		if err != nil {
			http.Error(w, "Failed to encrypt secret", http.StatusInternalServerError)
			return
		}
		server.EncryptedSecret = encryptedSecret
	}

	if err := db.DB.Save(&server).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server)
}

func DeleteServer(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)
	serverIDStr := r.URL.Query().Get("id")

	serverID, err := strconv.Atoi(serverIDStr)
	if err != nil {
		http.Error(w, "Invalid server ID", http.StatusBadRequest)
		return
	}

	if err := db.DB.Where("id = ? AND user_id = ?", serverID, uint(userID)).Delete(&models.Server{}).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
