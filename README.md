# Remofy Backend

This is the backend component of the Remofy application, written in Go (Golang). It handles WebSocket connections and manages SSH sessions.

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
- **Multi-factor authentication** (TOTP + WebAuthn passkeys + recovery codes): every authenticated request can be gated behind a 30-minute biometric-unlock window. Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password, Bitwarden, Aegis — anything that speaks RFC 6238. See **[SECURITY.md](SECURITY.md)** for the full threat model.
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
    -   `MFA_REQUIRED` (`true`/`false`): turn on the device-biometric gate
    -   `MFA_SESSION_TTL` (e.g. `30m`): how long a successful unlock lasts
    -   `MFA_COOKIE_KEY`: 32 random bytes hex-encoded (`openssl rand -hex 32`)
    -   `TELEGRAM_BOT_TOKEN`: required for the bot Mini App to verify `initData`
    -   `MFA_GRACE_UNTIL` (optional, RFC3339): grace window for legacy users


## MFA setup

Once `MFA_REQUIRED=true` is set and the server is restarted:

1. Any authenticated API call returns `403` with the body
   `{"error":"mfa_required","enrolled":false,"unlock_url":"/mfa/unlock"}`.
   The React frontend reads `X-MFA-Required: 1` and renders the setup wizard.
2. The setup wizard calls `POST /api/mfa/totp/setup` to receive a QR code +
   base32 secret, then `POST /api/mfa/totp/verify` with the user's first
   6-digit code. The verify response includes 10 **plaintext recovery codes
   shown exactly once** — the user must save them.
3. The wizard then offers `POST /api/mfa/webauthn/register/begin` and
   `finish` to bind the current device's platform authenticator
   (FaceID / Touch ID / Windows Hello / Android biometrics).
4. After enrollment the user receives a `DeviceSession` valid for
   `MFA_SESSION_TTL`. Subsequent requests pass without prompts.
5. After the session expires (or after `POST /api/mfa/lock`), the next
   request returns `403` again; the wizard's unlock flow uses
   `navigator.credentials.get` when a credential exists, falling back to
   TOTP, falling back further to recovery codes.

The Telegram Mini App at `/mfa/bot/` performs the same flow for bot users —
no frontend deployment needed beyond the bundled HTML+JS.

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
