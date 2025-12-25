package sftp

import (
	"context"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

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
		Timeout:         30 * time.Second,
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

func connectSFTPWithKeepalive(ctx context.Context, serverID uint) (*ssh.Client, *sftp.Client, error) {
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
		Timeout:         30 * time.Second,
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)

	// SSH keepalive (application-level) to survive server-side idle timeouts.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					log.Printf("SFTP SSH keepalive failed: %v", err)
					return
				}
			}
		}
	}()

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

	// WebSocket keepalive (server-side pings) to prevent idle disconnects.
	const (
		writeWait      = 10 * time.Second
		pongWait       = 60 * time.Second
		pingPeriod     = (pongWait * 9) / 10
		maxMessageSize = 8192
	)

	ws.SetReadLimit(maxMessageSize)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-pingTicker.C:
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sshClient, sftpClient, err := connectSFTPWithKeepalive(ctx, uint(serverID))
	if err != nil {
		ws.WriteJSON(map[string]string{"error": err.Error()})
		close(done)
		return
	}
	defer sftpClient.Close()
	defer sshClient.Close()

	for {
		var msg SFTPMessage
		if err := ws.ReadJSON(&msg); err != nil {
			close(done)
			break
		}

		switch msg.Action {
		case "ping":
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			_ = ws.WriteJSON(map[string]string{"action": "pong"})
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
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			ws.WriteJSON(map[string]interface{}{"action": "ls", "path": path, "files": fileList})

		case "mkdir":
			err := sftpClient.Mkdir(msg.Path)
			if err != nil {
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				ws.WriteJSON(map[string]string{"error": err.Error()})
			} else {
				ws.SetWriteDeadline(time.Now().Add(writeWait))
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
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				ws.WriteJSON(map[string]string{"error": err.Error()})
			} else {
				ws.SetWriteDeadline(time.Now().Add(writeWait))
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

	var size int64
	if info, err := file.Stat(); err == nil {
		size = info.Size()
		if size >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		}
	}

	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		head := make([]byte, 512)
		n, _ := file.Read(head)
		// Reset offset so GET streams from start.
		if _, err := file.Seek(0, 0); err != nil {
			// Fallback: re-open if Seek isn't supported.
			_ = file.Close()
			file, err = sftpClient.Open(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			defer file.Close()
		}
		contentType = http.DetectContentType(head[:n])
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(path)))
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = io.Copy(w, file)
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
