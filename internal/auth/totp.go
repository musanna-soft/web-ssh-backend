package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

// totpIssuer is the label shown inside any authenticator app. Configurable
// only at compile time on purpose — changing it for an enrolled user would
// require re-enrollment, which is a deliberate action.
const totpIssuer = "Remofy"

// GenerateTOTPSecret creates a fresh TOTP secret keyed to the user's account
// label and returns:
//   - the raw base32 secret (caller encrypts before persisting)
//   - the otpauth:// URL (in case the frontend wants to render its own QR)
//   - a PNG of the QR code rendered at 256x256, base64-encoded as a data URL
//
// Parameters follow RFC 6238 defaults (SHA1, 6 digits, 30s period). This
// matches what Microsoft Authenticator, Google Authenticator, Authy, 1Password,
// Bitwarden, Aegis and every other major authenticator app expects.
func GenerateTOTPSecret(accountEmail string) (secret, otpauthURL, qrDataURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: accountEmail,
		SecretSize:  20, // 160 bits — RFC 4226 recommended minimum
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("generate totp: %w", err)
	}

	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return "", "", "", fmt.Errorf("encode qr: %w", err)
	}

	return key.Secret(), key.URL(), "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// VerifyTOTPCode checks a 6-digit user-submitted code against a stored secret.
// Accepts the current 30s window plus one window of skew on either side
// (default in pquerna/otp), which covers typical clock drift.
func VerifyTOTPCode(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	return totp.Validate(code, secret)
}

// GenerateRecoveryCodes returns n one-time codes in the format "xxxx-xxxx-xxxx"
// (12 hex chars, dashes for legibility). Caller is responsible for storing
// bcrypt hashes (NEVER the plaintext) and showing the plaintext to the user
// exactly once.
//
// 10 codes is the convention shared by GitHub, Google, Bitwarden, 1Password.
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		return nil, errors.New("n must be > 0")
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		var raw [6]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		// 12 hex chars, grouped 4-4-4 for readability.
		hex := fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
			raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
		var buf bytes.Buffer
		buf.WriteString(hex[0:4])
		buf.WriteByte('-')
		buf.WriteString(hex[4:8])
		buf.WriteByte('-')
		buf.WriteString(hex[8:12])
		out[i] = buf.String()
	}
	return out, nil
}

// NormalizeRecoveryCode strips spaces, dashes, and lowercases so user input
// like "ABCD-EFGH 1234" matches the stored canonical "abcdefgh1234". The
// hash is computed against the normalized form.
func NormalizeRecoveryCode(in string) string {
	in = strings.ToLower(in)
	in = strings.ReplaceAll(in, "-", "")
	in = strings.ReplaceAll(in, " ", "")
	return strings.TrimSpace(in)
}
