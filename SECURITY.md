# Security Policy

This document describes the threat model of Remofy (`web-ssh-backend` and the
companion `remofy-bot` Telegram client) and how to report vulnerabilities
responsibly.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for suspected security problems.
Instead, email the maintainers privately so a fix can ship before disclosure.
We aim to acknowledge reports within 72 hours.

## Threat model — what Remofy protects against

| Attack | Defence |
|---|---|
| Bulk DB dump leak (DB file copied without the running server) | Server credentials, TOTP secrets, OAuth state — all AES-GCM encrypted at rest with `ENCRYPTION_KEY` (32 bytes). The leaked DB alone yields no plaintext credentials. |
| Stolen Google session / JWT | After MFA is enrolled, every API call still passes through `MFAGate`. Without an active `DeviceSession` (proving recent biometric/TOTP verification on a registered device) the JWT is useless beyond `/api/me` and the MFA-setup paths. |
| Stolen Telegram account | Same gate applies to the Telegram Mini App: Mini App access needs a current `initData` HMAC, *and* the bot's gate independently checks for an unlocked `DeviceSession` on the `bot` surface. |
| Brute-forced TOTP | RFC 6238 with the standard ±30 s drift window. We deliberately do not widen the skew. Bcrypt-hashed recovery codes prevent offline brute force of the DB. |
| Compromised passkey on one device | WebAuthn credentials are tied to the registering device; revoking a single credential through `/api/mfa/devices/{id}` does not affect the others. Sign counter monotonicity catches cloned credentials. |
| CSRF on `/api/mfa/*` | Web surface relies on `Authorization: Bearer` (custom header) which is itself CSRF-immune. Bot surface uses a `SameSite=Strict; HttpOnly; Secure` cookie limited to `/api/mfa/`. |
| Replay of an old Telegram `initData` blob | We enforce a 5-minute freshness window on `auth_date` even though Telegram itself doesn't expire it. |
| Replay of an old WebAuthn challenge | Challenges are single-use, server-side, with a 5-minute TTL. The challenge map is swept by a background goroutine. |

## What Remofy does NOT protect against

These are accepted trade-offs of the architecture, not bugs. We document
them so operators can pick complementary controls (LUKS/BitLocker,
firewalled networks, hardened host OS) instead of assuming the application
defends against them.

- **Full host compromise.** If an attacker has read access to the running
  process or the live filesystem (`.env`, the Postgres data directory, and
  the process memory), they can recover `ENCRYPTION_KEY` and decrypt every
  stored secret. This is the same trust boundary that Vaultwarden, Authelia
  and most self-hostable apps live within. Mitigate by running on a
  dedicated, disk-encrypted host with limited shell access.
- **Malicious Postgres operator.** Anyone with database superuser access
  could rewrite rows (e.g. flip `mfa_enrollments.enrolled = false` and
  re-enrol from a different device). Restrict DB credentials to the
  application user.
- **Phishing of Google identity.** A successful phishing of a user's Google
  OAuth flow does not bypass MFA — but it does grant the attacker `/start`
  and `/api/me`, which can reveal the user's email. MFA is the layer that
  stops execution; do not weaken Google's account-recovery posture either.
- **Lost recovery codes AND lost devices AND lost TOTP.** This is by design
  unrecoverable from the application's perspective. Operators may choose
  to support out-of-band reset (e.g. an admin SQL deletion of the user's
  MFA rows), but the application itself will not offer one.
- **Side-channel attacks on the local authenticator.** Biometric coercion,
  shoulder-surfing of TOTP, or malware on the user's device are outside
  the application's defensive perimeter.

## Cryptographic primitives

- **At-rest encryption:** AES-256-GCM with a per-record random nonce.
  Key is the raw bytes of `ENCRYPTION_KEY` (or zero-padded to 32 bytes if
  shorter; **set it to exactly 32 random bytes for production**).
- **Recovery codes:** bcrypt with the library's default cost (10).
  Codes are 12 lowercase hex chars formatted `xxxx-xxxx-xxxx`.
- **Mini App session cookie:** HMAC-SHA256 over `userID.surface.exp`
  using `MFA_COOKIE_KEY` (32 random bytes hex-encoded).
- **Telegram `initData` verification:** the two-layer
  `HMAC(HMAC("WebAppData", bot_token), data_check_string)` algorithm
  documented at https://core.telegram.org/bots/webapps .
- **WebAuthn:** delegated to `github.com/go-webauthn/webauthn`.
  RP ID is the hostname of `PUBLIC_BASE_URL`; RP Origin is the full URL.

## Operational recommendations

1. Run the server only over HTTPS in production. `Secure` cookie flags
   activate when `GOOGLE_REDIRECT_URL` starts with `https://`.
2. Generate `ENCRYPTION_KEY`, `JWT_SECRET`, and `MFA_COOKIE_KEY` with
   `openssl rand -hex 32` and store them outside source control.
3. Configure `MFA_GRACE_UNTIL` when first enabling `MFA_REQUIRED=true` so
   existing users have a transition window to enroll.
4. Encrypt the host's disk (LUKS, BitLocker, native cloud-provider
   encryption) — defends against unattended-disk theft.
5. Limit database credentials to the application user; do not give the
   application a superuser role.
6. Treat the Mini App URL (`/mfa/bot/`) as security-sensitive. Telegram
   already requires HTTPS to render it, but make sure the route is not
   cached by any intermediary.
