package sftp

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

func HandleGetFileContent(w http.ResponseWriter, r *http.Request) {
	serverIDStr := r.URL.Query().Get("server_id")
	path := r.URL.Query().Get("path")
	serverID, _ := strconv.Atoi(serverIDStr)

	sshClient, sftpClient, err := connectSFTP(uint(serverID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sftpClient.Close()
	defer sshClient.Close()

	file, err := sftpClient.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer file.Close()

	// Check for binary file
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && err != io.EOF {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// List of known text extensions to always allow (unless they contain null bytes)
	textExtensions := map[string]bool{
		".env": true, ".json": true, ".yaml": true, ".yml": true, ".xml": true,
		".md": true, ".txt": true, ".js": true, ".ts": true, ".vue": true,
		".go": true, ".py": true, ".html": true, ".css": true, ".sh": true,
		".gitignore": true, ".dockerfile": true,
	}

	fileName := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(fileName))
	// Special case for files like ".env" where Ext might be empty or just ".env"
	if ext == "" {
		ext = strings.ToLower(fileName)
	}

	isKnownText := textExtensions[ext] || strings.HasPrefix(fileName, ".env")

	// Heuristic 1: Check for null bytes (strong indicator of binary)
	isBinary := false
	for _, b := range header[:n] {
		if b == 0 {
			isBinary = true
			break
		}
	}

	// If it's a known text extension, we trust it's text unless it has null bytes (which would be weird for text)
	// If it's NOT a known extension, we rely on the null byte check.
	// Actually, if it IS a known text extension, we should probably allow it even if it has null bytes (some encodings?),
	// but let's be safe and still block if it looks VERY binary.
	// For now, let's say if it's known text, we allow it unless it's overwhelmingly binary?
	// Or just allow it. Let's allow it if it's known text, but maybe warn?
	// The user specifically mentioned .env files.

	if isBinary && !isKnownText {
		http.Error(w, "Cannot edit binary file. Please download it.", http.StatusBadRequest)
		return
	}

	// Reset file pointer
	if _, err := file.Seek(0, 0); err != nil {
		http.Error(w, "Failed to seek file", http.StatusInternalServerError)
		return
	}

	// Limit file size for editing? Let's say 1MB for now to avoid freezing browser
	const maxFileSize = 1 * 1024 * 1024
	content, err := io.ReadAll(io.LimitReader(file, maxFileSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

func HandleSaveFileContent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID int    `json:"server_id"`
		Path     string `json:"path"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sshClient, sftpClient, err := connectSFTP(uint(req.ServerID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sftpClient.Close()
	defer sshClient.Close()

	file, err := sftpClient.Create(req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	if _, err := file.Write([]byte(req.Content)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
