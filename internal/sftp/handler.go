package sftp

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"

	"web-ssh-backend/internal/crypto"
	"web-ssh-backend/internal/db"
	"web-ssh-backend/internal/models"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type SFTPMessage struct {
	Action string `json:"action"` // "ls", "mkdir", "rm", "mv"
	Path   string `json:"path"`
	Dest   string `json:"dest,omitempty"` // For mv
}

type FileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	Mode  string `json:"mode"`
}

func connectSFTP(serverID uint) (*ssh.Client, *sftp.Client, error) {
	var server models.Server
	if err := db.DB.First(&server, serverID).Error; err != nil {
		return nil, nil, err
	}

	secret, err := crypto.Decrypt(server.EncryptedSecret)
	if err != nil {
		return nil, nil, err
	}

	authMethod := ssh.Password(secret)
	if server.AuthType == "key" {
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, nil, err
		}
		authMethod = ssh.PublicKeys(signer)
	}

	config := &ssh.ClientConfig{
		User:            server.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", server.Host, server.Port), config)
	if err != nil {
		return nil, nil, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, nil, err
	}

	return sshClient, sftpClient, nil
}

func HandleSFTPWebSocket(w http.ResponseWriter, r *http.Request) {
	// Token validation should be done via middleware or query param check similar to SSH
	// For brevity, assuming valid token passed in query and validated (omitted here)

	serverIDStr := r.URL.Query().Get("server_id")
	serverID, _ := strconv.Atoi(serverIDStr)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	sshClient, sftpClient, err := connectSFTP(uint(serverID))
	if err != nil {
		ws.WriteJSON(map[string]string{"error": err.Error()})
		return
	}
	defer sftpClient.Close()
	defer sshClient.Close()

	for {
		var msg SFTPMessage
		if err := ws.ReadJSON(&msg); err != nil {
			break
		}

		switch msg.Action {
		case "ls":
			path := msg.Path
			if path == "" || path == "." {
				// Try to get absolute path of current directory (usually home)
				realPath, err := sftpClient.RealPath(".")
				if err == nil && realPath != "" {
					path = realPath
				} else {
					// Fallback to Getwd
					wd, err := sftpClient.Getwd()
					if err == nil {
						path = wd
					}
				}
			}

			files, err := sftpClient.ReadDir(path)
			if err != nil {
				ws.WriteJSON(map[string]string{"error": err.Error()})
				continue
			}
			var fileList []FileInfo
			for _, f := range files {
				fileList = append(fileList, FileInfo{
					Name:  f.Name(),
					Size:  f.Size(),
					IsDir: f.IsDir(),
					Mode:  f.Mode().String(),
				})
			}
			ws.WriteJSON(map[string]interface{}{"action": "ls", "path": path, "files": fileList})

		case "mkdir":
			err := sftpClient.Mkdir(msg.Path)
			if err != nil {
				ws.WriteJSON(map[string]string{"error": err.Error()})
			} else {
				ws.WriteJSON(map[string]string{"status": "ok", "action": "mkdir"})
			}

		case "rm":
			// Simple rm, for recursive need more logic
			err := sftpClient.Remove(msg.Path)
			if err != nil {
				// Try RemoveDirectory if it fails?
				err = sftpClient.RemoveDirectory(msg.Path)
			}
			if err != nil {
				ws.WriteJSON(map[string]string{"error": err.Error()})
			} else {
				ws.WriteJSON(map[string]string{"status": "ok", "action": "rm"})
			}
		}
	}
}

func HandleDownload(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(path)))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, file)
}

func HandleUpload(w http.ResponseWriter, r *http.Request) {
	// Parse Multipart
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	serverIDStr := r.FormValue("server_id")
	destPath := r.FormValue("path")
	serverID, _ := strconv.Atoi(serverIDStr)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	sshClient, sftpClient, err := connectSFTP(uint(serverID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sftpClient.Close()
	defer sshClient.Close()

	remotePath := filepath.Join(destPath, header.Filename)
	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
