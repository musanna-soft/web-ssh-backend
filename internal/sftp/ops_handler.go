package sftp

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
)

type FileOpRequest struct {
	ServerID int    `json:"server_id"`
	SrcPath  string `json:"src_path"`
	DestPath string `json:"dest_path"`
}

func HandleMoveFile(w http.ResponseWriter, r *http.Request) {
	var req FileOpRequest
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

	// Rename handles move
	// Ensure destination is the full path including filename
	// If DestPath is a directory, we should append the filename
	info, err := sftpClient.Stat(req.DestPath)
	if err == nil && info.IsDir() {
		req.DestPath = filepath.Join(req.DestPath, filepath.Base(req.SrcPath))
	}

	if err := sftpClient.Rename(req.SrcPath, req.DestPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func HandleCopyFile(w http.ResponseWriter, r *http.Request) {
	var req FileOpRequest
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

	// Open source
	srcFile, err := sftpClient.Open(req.SrcPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer srcFile.Close()

	// Determine dest path
	info, err := sftpClient.Stat(req.DestPath)
	if err == nil && info.IsDir() {
		req.DestPath = filepath.Join(req.DestPath, filepath.Base(req.SrcPath))
	}

	// Create dest
	dstFile, err := sftpClient.Create(req.DestPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dstFile.Close()

	// Copy
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
