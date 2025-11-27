package sftp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
)

type TransferRequest struct {
	SourceServerID uint   `json:"source_server_id"`
	SourcePath     string `json:"source_path"`
	DestServerID   uint   `json:"dest_server_id"`
	DestPath       string `json:"dest_path"`
}

const MaxTransferSize = 400 * 1024 * 1024 // 400MB

func HandleTransfer(w http.ResponseWriter, r *http.Request) {
	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 1. Connect to Source Server
	srcSSH, srcSFTP, err := connectSFTP(req.SourceServerID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to source server: %v", err), http.StatusInternalServerError)
		return
	}
	defer srcSFTP.Close()
	defer srcSSH.Close()

	// 2. Open Source File
	srcFile, err := srcSFTP.Open(req.SourcePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open source file: %v", err), http.StatusNotFound)
		return
	}
	defer srcFile.Close()

	// 3. Check File Size
	fileInfo, err := srcFile.Stat()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stat source file: %v", err), http.StatusInternalServerError)
		return
	}
	if fileInfo.Size() > MaxTransferSize {
		http.Error(w, fmt.Sprintf("File too large. Limit is 400MB. File size: %d bytes", fileInfo.Size()), http.StatusBadRequest)
		return
	}

	// 4. Connect to Destination Server
	destSSH, destSFTP, err := connectSFTP(req.DestServerID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to destination server: %v", err), http.StatusInternalServerError)
		return
	}
	defer destSFTP.Close()
	defer destSSH.Close()

	// 5. Create Destination File
	// Ensure destination directory exists? For now assume user provides valid path or we just write to the path.
	// If DestPath is a directory, we should append the filename.
	destPath := req.DestPath
	destInfo, err := destSFTP.Stat(destPath)
	if err == nil && destInfo.IsDir() {
		destPath = filepath.Join(destPath, filepath.Base(req.SourcePath))
	}

	destFile, err := destSFTP.Create(destPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create destination file: %v", err), http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	// 6. Stream Data
	// Use LimitReader just in case, though we checked Stat
	limitReader := io.LimitReader(srcFile, MaxTransferSize)

	copied, err := io.Copy(destFile, limitReader)
	if err != nil {
		http.Error(w, fmt.Sprintf("Transfer failed during copy: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"bytes":  copied,
	})
}
