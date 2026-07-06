// Package aup models acceptance of the Acceptable-Use Policy.
package aup

import "time"

// Acceptance records that an actor accepted a specific AUP version.
type Acceptance struct {
	Version    string    `json:"version"`
	Actor      string    `json:"actor"`
	AcceptedAt time.Time `json:"accepted_at"`
}
