# Web SSH Backend

This is the backend component of the Web SSH application, written in Go (Golang). It handles WebSocket connections and manages SSH sessions.

## Features

- **Dual Keepalive Mechanism**: Prevents connection timeouts at both WebSocket and SSH levels
  - **WebSocket Keepalive**:
    - Server sends ping every 54 seconds
    - 60-second timeout for pong responses
    - Prevents WebSocket connection drops during inactive terminal sessions
  - **SSH Keepalive**:
    - Sends keepalive requests to SSH server every 30 seconds
    - Prevents SSH server-side timeout
    - Uses OpenSSH-compatible keepalive protocol
- **SSH Session Management**: Secure SSH connections with support for password and key-based authentication
- **Google OAuth Integration**: Secure user authentication
- **End-to-End Encryption**: Server credentials are encrypted at rest

## 1. Configuration (.env)

Before running the application, you need to configure the environment variables.

1.  Copy the example configuration file:
    ```bash
    cp .env.example .env
    ```

2.  Edit the `.env` file and set the required variables:
    -   `PORT`: Server port (default: 8080)
    -   `DB_PATH`: Postgres connection string
    -   `GOOGLE_CLIENT_ID`: Google OAuth Client ID
    -   `GOOGLE_CLIENT_SECRET`: Google OAuth Client Secret
    -   `GOOGLE_REDIRECT_URL`: OAuth callback URL (http(s)://<host>:<port>/auth/google/callback)
    -   `JWT_SECRET`: Secret key for JWT signing
    -   `ENCRYPTION_KEY`: 32-byte key for data encryption
    -   `FRONTEND_URL`: URL of the frontend application (for CORS)

## 2. Running with Docker

The project is fully containerized. Follow these steps to run it with Docker:

### Build the Image

```bash
docker build -t web-ssh-backend .
```

### Run the Container

```bash
docker run -d -p 8080:8080 --env-file .env web-ssh-backend
```

This will start the application on port 8080 (or the port specified in your `.env` file).

## 3. Development

To run the application locally for development:

```bash
go mod download
go run ./cmd/server/main.go
```
