package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kcrypto "github.com/kankipro/klink/internal/crypto"
)

func testSubscription(t *testing.T) string {
	t.Helper()
	client, _ := kcrypto.GenerateKey()
	server, _ := kcrypto.GenerateKey()
	return `{"klink_version":1,"name":"pin","client_private_key":"` + client.PrivateBase64() +
		`","client_public_key":"` + client.PublicBase64() + `","server_public_key":"` + server.PublicBase64() +
		`","transports":[{"network":"tcp","endpoint":"127.0.0.1:443"}],"obfuscation":"random",` +
		`"rekey_interval_seconds":900,"rekey_packets":1048576,"session_id_bits":128}`
}

// A panel without a domain uses a self-signed certificate; the link carries its
// fingerprint and only that exact certificate is accepted.
func TestFetchSubscriptionWithPinnedSelfSignedCertificate(t *testing.T) {
	body := testSubscription(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin := base64.RawURLEncoding.EncodeToString(sum[:])
	ctx := context.Background()

	if _, err := FetchSubscription(ctx, srv.URL+"/sub/x"); err == nil {
		t.Fatal("self-signed certificate accepted without a pin")
	}
	if got, err := FetchSubscription(ctx, srv.URL+"/sub/x#pin="+pin); err != nil || !strings.Contains(got, `"name":"pin"`) {
		t.Fatalf("pinned fetch failed: %v", err)
	}
	wrong := sha256.Sum256([]byte("other certificate"))
	if _, err := FetchSubscription(ctx, srv.URL+"/sub/x#pin="+base64.RawURLEncoding.EncodeToString(wrong[:])); err == nil {
		t.Fatal("certificate with a different fingerprint accepted")
	}
}
