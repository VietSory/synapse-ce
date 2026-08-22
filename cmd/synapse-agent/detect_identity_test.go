package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
)

func TestDetectionIdentityIgnoresMutableDisplayName(t *testing.T) {
	cred := fleetclient.Credential{AgentID: "agent-canonical"}
	want := shared.ID(cred.AgentID)

	var firstHost, firstAgent shared.ID
	for i, displayName := range []string{"sensor-before-rename", "sensor-after-rename"} {
		r := &runner{cfg: config{name: displayName}}
		if r.cfg.name != displayName {
			t.Fatalf("display-name fixture=%q want=%q", r.cfg.name, displayName)
		}

		host, agent, ok := detectionIdentity(cred)
		if !ok {
			t.Fatal("enrolled canonical AgentID was rejected")
		}
		if host != want || agent != want {
			t.Fatalf("display name %q changed data-plane identity: host=%q agent=%q want=%q", displayName, host, agent, want)
		}
		if i == 0 {
			firstHost, firstAgent = host, agent
			continue
		}
		if host != firstHost || agent != firstAgent {
			t.Fatalf("renaming display name changed identity: before=(%q,%q) after=(%q,%q)", firstHost, firstAgent, host, agent)
		}
	}
}

func TestDetectionIdentityFailsClosedWithoutEnrolledAgentID(t *testing.T) {
	host, agent, ok := detectionIdentity(fleetclient.Credential{})
	if ok || !host.IsZero() || !agent.IsZero() {
		t.Fatalf("missing enrolled AgentID must fail closed: host=%q agent=%q ok=%t", host, agent, ok)
	}
}
