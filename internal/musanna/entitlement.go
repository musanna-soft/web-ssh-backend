// Package musanna asks the platform whether the person in front of us has paid
// for web-ssh, and what their plan lets them do.
//
// WHY THIS EXISTS. web-ssh is sold by plan: Free gives one server, Pro gives
// twenty. Without a plan the app must not work at all — logging somebody in and
// then showing them an empty, unusable screen is worse than refusing the login,
// because it looks like a bug rather than a decision.
//
// WHERE THE ANSWER COMES FROM. POST {authority}/api/integration/authorize with
// the person's platform access token. That single endpoint answers "who is this,
// what are they entitled to, and under which limits" — the same answer the rest
// of the ecosystem uses, so web-ssh cannot drift from it.
package musanna

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AppCode is this app's code in the platform catalogue. It must match the
// `webssh` row there — the catalogue is what the plans hang off.
const AppCode = "webssh"

// ServersLimitKey is the resource limit web-ssh understands. The platform
// carries limits as an opaque map on purpose: it has no idea what a "server" is
// and does not need to, which is why a new limit never needs a platform change.
const ServersLimitKey = "servers"

// Entitlement is the slice of the platform's answer this app acts on.
type Entitlement struct {
	// Entitled reports whether a live plan exists. False means: no plan, or an
	// expired one. Either way the app is closed.
	Entitled bool

	// PlanCode is shown in the UI so the person knows what they are on.
	PlanCode string

	// Servers is how many servers the plan allows. Zero means "not stated by
	// the plan" and is treated as UNLIMITED, matching the platform's own rule
	// for quotas: an absent limit is not a zero limit.
	Servers int64
}

type authorizeResponse struct {
	Entitlement struct {
		IsEntitled bool             `json:"isEntitled"`
		PlanCode   string           `json:"planCode"`
		Limits     map[string]int64 `json:"limits"`
	} `json:"entitlement"`
}

// Check asks the platform about the holder of accessToken.
//
// A network failure is an ERROR, not a silent "not entitled": denying access
// because the platform hiccuped would lock paying customers out of their
// servers. The caller decides what to do — and at login the right answer is to
// fail the login with a visible message rather than let somebody in unpaid.
func Check(authority, accessToken string) (Entitlement, error) {
	payload, err := json.Marshal(map[string]any{"appCode": AppCode})
	if err != nil {
		return Entitlement{}, err
	}

	url := strings.TrimRight(authority, "/") + "/api/integration/authorize"
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return Entitlement{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Entitlement{}, fmt.Errorf("authorize request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Entitlement{}, fmt.Errorf("authorize returned http %d", resp.StatusCode)
	}

	var body authorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Entitlement{}, fmt.Errorf("decode authorize response: %w", err)
	}

	return Entitlement{
		Entitled: body.Entitlement.IsEntitled,
		PlanCode: body.Entitlement.PlanCode,
		Servers:  body.Entitlement.Limits[ServersLimitKey],
	}, nil
}
