// Package idgen provides Clock and IDGenerator implementations for the platform.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SystemClock implements ports.Clock using the wall clock (UTC).
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

var _ ports.Clock = SystemClock{}

// RandomID implements ports.IDGenerator using 128-bit crypto-random hex tokens.
type RandomID struct{}

func (RandomID) NewID() shared.ID {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return shared.ID(hex.EncodeToString(b))
}

var _ ports.IDGenerator = RandomID{}
