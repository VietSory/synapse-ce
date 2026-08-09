package sourcepolicy

import "testing"

func TestRetainPathFailsClosedForCredentialShapedFiles(t *testing.T) {
	for _, path := range []string{
		".env", ".env.production", "config/.env.local", ".netrc", ".npmrc", ".pypirc",
		".git-credentials", "credentials.json", "secrets/credentials.json",
		"id_rsa", "ssh/id_ed25519", "certs/server.pem", "certs/server.key", "certs/client.p12", "keystore/app.jks",
		"../escape.go", "/absolute.go", "C:/absolute.go",
	} {
		if RetainPath(path) {
			t.Fatalf("RetainPath(%q)=true, want false", path)
		}
	}
	for _, path := range []string{"main.go", "src/app.ts", "config/example.env", "docs/key-management.md", "keys/public.pub"} {
		if !RetainPath(path) {
			t.Fatalf("RetainPath(%q)=false, want true", path)
		}
	}
}
