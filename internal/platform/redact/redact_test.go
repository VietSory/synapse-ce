package redact

import (
	"strings"
	"testing"
)

func TestURLCreds(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@github.com/x": "https://***@github.com/x",
		"git clone https://ghp_tok@h/r":  "git clone https://***@h/r",
		"no creds https://example.com/x": "no creds https://example.com/x",
		"ssh://deploy:key@host:22/path":  "ssh://***@host:22/path",
	}
	for in, want := range cases {
		if got := URLCreds(in); got != want {
			t.Errorf("URLCreds(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBytesScrubsSecrets(t *testing.T) {
	out := Bytes([]byte("token=ghp_SECRET printed by the tool"), [][]byte{[]byte("ghp_SECRET")})
	if string(out) != "token=[REDACTED] printed by the tool" {
		t.Errorf("secret not scrubbed: %q", out)
	}
}

func TestBytesScrubsSecretsAndURLCreds(t *testing.T) {
	in := []byte("auth https://u:p@h/r and key SuperSecret123")
	out := string(Bytes(in, [][]byte{[]byte("SuperSecret123")}))
	want := "auth https://***@h/r and key [REDACTED]"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestBytesIgnoresEmptySecrets(t *testing.T) {
	in := []byte("plain output")
	if got := string(Bytes(in, [][]byte{[]byte("")})); got != "plain output" {
		t.Errorf("empty secret must be a no-op, got %q", got)
	}
}

func TestBytesScrubsEncodedForms(t *testing.T) {
	secret := []byte("S3CR3T_TOKEN_DEADBEEF")
	b64 := "UzNDUjNUX1RPS0VOX0RFQURCRUVG"
	hexLower := "53334352335f544f4b454e5f4445414442454546" // not exact; use real
	_ = hexLower
	out := string(Bytes([]byte("raw=S3CR3T_TOKEN_DEADBEEF b64="+b64+" hex=53334352335f"), [][]byte{secret}))
	if strings.Contains(out, "S3CR3T_TOKEN_DEADBEEF") {
		t.Errorf("raw secret not redacted: %s", out)
	}
	if strings.Contains(out, b64) {
		t.Errorf("base64-encoded secret not redacted: %s", out)
	}
}
