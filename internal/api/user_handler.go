package api

import (
	"encoding/json"
	"net/http"

	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"
)

func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(float64)

	var user models.User
	if err := db.DB.First(&user, uint(userID)).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
