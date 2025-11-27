package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
)

func GetFolders(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)

	var folders []models.Folder
	// Preload servers to show count or list if needed, but for now just folders
	if err := db.DB.Where("user_id = ?", uint(userID)).Find(&folders).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(folders)
}

func CreateFolder(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	folder := models.Folder{
		UserID: uint(userID),
		Name:   req.Name,
	}

	if err := db.DB.Create(&folder).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(folder)
}

func DeleteFolder(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)
	folderIDStr := r.URL.Query().Get("id")

	folderID, err := strconv.Atoi(folderIDStr)
	if err != nil {
		http.Error(w, "Invalid folder ID", http.StatusBadRequest)
		return
	}

	// Optional: Check if folder has servers? Or just set their FolderID to null?
	// GORM might handle this if foreign key constraints are set, but SQLite is loose.
	// Let's manually set servers' FolderID to null for safety before deleting folder.
	db.DB.Model(&models.Server{}).Where("folder_id = ?", folderID).Update("folder_id", nil)

	if err := db.DB.Where("id = ? AND user_id = ?", folderID, uint(userID)).Delete(&models.Folder{}).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
