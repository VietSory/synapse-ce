package memory

import (
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
	"testing"
)

func TestTicketStoreConformance(t *testing.T) {
	f := storetest.Fixture{Tenant: "ticket-j01-a", Other: "ticket-j01-b", Integration: "ticket-integration-a",
		Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	store := NewTicketStore()
	storetest.Run(t, store, f)
	storetest.ConcurrentReplay(t, store, f)
}
