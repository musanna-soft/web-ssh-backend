package sftp

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

func HandleDownloadZip(w http.ResponseWriter, r *http.Request) {
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

	info, err := sftpClient.Stat(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if !info.IsDir() {
		http.Error(w, "Path is not a directory", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", filepath.Base(path)))
	w.Header().Set("Content-Type", "application/zip")

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	walker := sftpClient.Walk(path)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			continue
		}

		fileInfo := walker.Stat()
		filePath := walker.Path()

		// Create relative path for zip
		relPath, err := filepath.Rel(filepath.Dir(path), filePath)
		if err != nil {
			continue
		}

		// Ensure forward slashes for zip compatibility
		relPath = strings.ReplaceAll(relPath, "\\", "/")

		if fileInfo.IsDir() {
			if !strings.HasSuffix(relPath, "/") {
				relPath += "/"
			}
			_, err = zipWriter.Create(relPath)
			if err != nil {
				continue
			}
		} else {
			header, err := zip.FileInfoHeader(fileInfo)
			if err != nil {
				continue
			}
			header.Name = relPath
			header.Method = zip.Deflate

			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				continue
			}

			file, err := sftpClient.Open(filePath)
			if err != nil {
				continue
			}

			_, err = io.Copy(writer, file)
			file.Close()
			if err != nil {
				continue
			}
		}
	}
}
