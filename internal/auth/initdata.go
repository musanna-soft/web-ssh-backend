package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// initDataMaxAge — how long a Telegram WebApp initData payload is accepted
// after the auth_date it carries. Telegram itself doesn't enforce expiry;
// we add 5 minutes to limit replay value of a leaked initData blob.
const initDataMaxAge = 5 * time.Minute

// TelegramInitDataUser is the subset of fields we read from the parsed
// `user` JSON in initData. The Telegram WebApp SDK provides this server-side
// after a Mini App opens.
type TelegramInitDataUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// VerifyTelegramInitData validates the HMAC-SHA256 signature on a raw
// Telegram WebApp initData string against the bot token, per the algorithm
// at https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app .
//
//	secret_key      = HMAC_SHA256(bot_token, key="WebAppData")
//	data_check_str  = sort(initData fields except "hash") joined with "\n"
//	expected_hash   = HMAC_SHA256(data_check_str, secret_key)
//	valid           = expected_hash == initData.hash
//
// Returns the embedded Telegram user on success.
func VerifyTelegramInitData(initData, botToken string) (*TelegramInitDataUser, error) {
	if initData == "" {
		return nil, errors.New("empty initData")
	}
	if botToken == "" {
		return nil, errors.New("bot token not configured")
	}

	values, err := url.ParseQuery(initData)
	if err != nil {
		return nil, errors.New("invalid initData query string")
	}

	receivedHash := values.Get("hash")
	if receivedHash == "" {
		return nil, errors.New("missing hash field")
	}
	values.Del("hash")

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(values.Get(k))
	}
	dataCheck := sb.String()

	mac1 := hmac.New(sha256.New, []byte("WebAppData"))
	mac1.Write([]byte(botToken))
	secretKey := mac1.Sum(nil)

	mac2 := hmac.New(sha256.New, secretKey)
	mac2.Write([]byte(dataCheck))
	expected := hex.EncodeToString(mac2.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(receivedHash)) {
		return nil, errors.New("hash mismatch")
	}

	if authDateStr := values.Get("auth_date"); authDateStr != "" {
		ts, err := strconv.ParseInt(authDateStr, 10, 64)
		if err == nil {
			age := time.Since(time.Unix(ts, 0))
			if age > initDataMaxAge {
				return nil, errors.New("initData expired")
			}
		}
	}

	userJSON := values.Get("user")
	if userJSON == "" {
		return nil, errors.New("missing user field")
	}
	var u TelegramInitDataUser
	if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
		return nil, errors.New("invalid user json")
	}
	if u.ID == 0 {
		return nil, errors.New("missing telegram user id")
	}
	return &u, nil
}
