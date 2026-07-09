package security

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"golang.org/x/oauth2"
)

func TestGenerateUserToken(t *testing.T) {
	cases := []struct {
		SigningKey    []byte
		EncryptionKey []byte
		name          string
		username      string
	}{
		{
			SigningKey:    []byte("5aa3a1568fe8421cd7e127d5ace28d2d"),
			EncryptionKey: []byte("d3ecd7e565e56e37e2f2e95b584d8c0c"),
			name:          "sign_and_encrypt",
			username:      "test_sign_and_encrypt",
		},
		{
			SigningKey:    nil,
			EncryptionKey: []byte("d3ecd7e565e56e37e2f2e95b584d8c0c"),
			name:          "encrypt_only",
			username:      "test_encrypt_only",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SigningKey = tc.SigningKey
			UserEncryptionKey = tc.EncryptionKey
			token, err := GenerateUserToken(context.Background(), tc.username)
			if err != nil {
				t.Fatalf("GenerateUserToken failed: %s", err)
			}
			claims, err := UserInfo(context.Background(), token)
			if err != nil {
				t.Fatalf("UserInfo failed: %s", err)
			}
			if claims.Subject != tc.username {
				t.Fatalf("Expected %s, got %s", tc.username, claims.Subject)
			}
		})
	}

}

func TestPAACookie(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	EncryptionKey = []byte("d3ecd7e565e56e37e2f2e95b584d8c0c")

	username := "test_paa_cookie"
	attr_client_ip := "127.0.0.1"
	attr_access_token := "aabbcc"

	id := identity.NewUser()
	id.SetUserName(username)
	id.SetAttribute(identity.AttrClientIp, attr_client_ip)
	id.SetAttribute(identity.AttrAccessToken, attr_access_token)

	ctx := context.Background()
	ctx = context.WithValue(ctx, identity.CTXKey, id)

	_, err := GeneratePAAToken(ctx, "test_paa_cookie", "host.does.not.exist")
	if err != nil {
		t.Fatalf("GeneratePAAToken failed: %s", err)
	}
	/*ok, err := CheckPAACookie(ctx, token)
	if err != nil {
		t.Fatalf("CheckPAACookie failed: %s", err)
	}
	if !ok {
		t.Fatalf("CheckPAACookie failed")
	}*/
}

// paaPayload returns the decoded JSON payload of a signed JWT (compact
// serialization: header.payload.signature). The PAA cookie is a JWS over
// HS256, so the payload is base64url-decodable plaintext.
func paaPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWS compact (3 parts), got %d in %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(raw)
}

// TestPAACookieDoesNotEmbedAccessToken asserts that the PAA cookie does not
// carry the IdP access token in its payload. The access token is a bearer
// credential for other OIDC-protected resources; embedding it in a cookie
// that travels in the .rdp file (or any access log) leaks it well beyond
// the gateway.
func TestPAACookieDoesNotEmbedAccessToken(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	const accessToken = "redacted-idp-access-token-1234567890abcdef"

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	id.SetAttribute(identity.AttrAccessToken, accessToken)
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}
	payload := paaPayload(t, token)
	if strings.Contains(payload, accessToken) {
		t.Errorf("PAA cookie embeds the IdP access token in plaintext\npayload: %s", payload)
	}
}

// TestPAACookieHasAudienceClaim asserts that the PAA cookie declares its
// audience. Without `aud`, any JWS the rdpgw signing key produces (a future
// non-PAA token, a maintainer-tool token, ...) would be indistinguishable
// from a PAA cookie at the gateway endpoint.
func TestPAACookieHasAudienceClaim(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	id.SetAttribute(identity.AttrAccessToken, "irrelevant")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}
	payload := paaPayload(t, token)
	if !strings.Contains(payload, `"aud"`) {
		t.Errorf("PAA cookie has no aud claim\npayload: %s", payload)
	}
}

// newCheckCtx builds a context for CheckPAACookie the same way
// TestCheckPAACookieIsSelfContained does: a fresh identity/tunnel pair
// scoped to the given client IP, with VerifyClientIP left as the caller
// set it.
func newCheckCtx(clientIp string) (context.Context, *protocol.Tunnel) {
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, clientIp)
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)
	tun := &protocol.Tunnel{User: id}
	ctx = context.WithValue(ctx, protocol.CtxTunnel, tun)
	return ctx, tun
}

// closeTunnel simulates a tunnel tearing down: sets LastSeen to mark when
// it was last genuinely active (real code does this on every Read(); tests
// set it directly), then fires the same hook RemoveTunnel fires in the
// real gateway.
func closeTunnel(tun *protocol.Tunnel, lastSeen time.Time) {
	tun.LastSeen = lastSeen
	RecordTunnelClosed(tun)
}

// fakeClock swaps the security package's clock for one the test can advance
// by hand. JWT exp claims have one-second resolution, so realistic expiry
// behaviour can't be tested with sub-second ExpiryTime values and sleeps;
// instead these tests use minute-scale durations against a fake clock.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// setupReconnectTest points the package globals at test values and restores
// them (and the reconnect cache, and the real clock) when the test ends, so
// mutations don't leak into other tests in this package.
func setupReconnectTest(t *testing.T, expiry, window time.Duration) *fakeClock {
	t.Helper()
	origSigning, origVerify := SigningKey, VerifyClientIP
	origExpiry, origWindow, origNow := ExpiryTime, ReconnectWindow, timeNow
	t.Cleanup(func() {
		SigningKey, VerifyClientIP = origSigning, origVerify
		ExpiryTime, ReconnectWindow, timeNow = origExpiry, origWindow, origNow
		closedTunnelActivity.Flush()
	})

	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	VerifyClientIP = false
	ExpiryTime = expiry
	ReconnectWindow = window
	closedTunnelActivity.Flush()

	clock := &fakeClock{now: time.Now()}
	timeNow = func() time.Time { return clock.now }
	return clock
}

// TestCheckPAACookieReconnectWindowDisabledByDefault asserts the previous,
// strict behaviour is unchanged when PAAReconnectWindow is left at its
// zero-value default: an expired token is rejected outright, even if the
// tunnel it authenticated was active right up until it closed.
func TestCheckPAACookieReconnectWindowDisabledByDefault(t *testing.T) {
	clock := setupReconnectTest(t, 5*time.Minute, 0)

	issueCtx, _ := newCheckCtx("10.0.0.1")
	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	checkCtx, tun := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx, token); err != nil || !ok {
		t.Fatalf("first use should succeed: ok=%v err=%v", ok, err)
	}
	closeTunnel(tun, clock.now) // active right up to close

	clock.Advance(6 * time.Minute) // past ExpiryTime

	checkCtx2, _ := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx2, token); err == nil || ok {
		t.Fatalf("expired token should be rejected when ReconnectWindow=0: ok=%v err=%v", ok, err)
	}
}

// TestCheckPAACookieReconnectAfterLongStableSession is the scenario this
// feature exists for: a session that ran healthily for a long time (no
// reconnects at all, so nothing ever touched CheckPAACookie again after
// the first connect) blips right at the end. The reconnect window must be
// judged against how recently the tunnel was genuinely active when it
// closed, not against how long ago the original connect happened -
// otherwise a long, healthy session would be *less* protected than a
// flaky one that kept reconnecting.
func TestCheckPAACookieReconnectAfterLongStableSession(t *testing.T) {
	clock := setupReconnectTest(t, 5*time.Minute, 30*time.Minute)

	issueCtx, _ := newCheckCtx("10.0.0.1")
	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	checkCtx, tun := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx, token); err != nil || !ok {
		t.Fatalf("first use should succeed: ok=%v err=%v", ok, err)
	}

	// The tunnel stays open and genuinely active for well longer than
	// ExpiryTime, exactly as a long, stable RDP session would - nobody
	// calls CheckPAACookie again during this stretch because no new
	// tunnel is being created; the client is just talking to the one it
	// already has.
	clock.Advance(2 * time.Hour)

	// The blip finally happens: the tunnel closes now, with LastSeen
	// reflecting that it was genuinely active right up to this moment -
	// not the original connect time from two hours ago.
	closeTunnel(tun, clock.now)

	// Reconnect arrives shortly after that true last activity - well
	// within ReconnectWindow of it - even though it's long past
	// ExpiryTime and long past the original connect.
	clock.Advance(2 * time.Minute)
	checkCtx2, tun2 := newCheckCtx("10.0.0.1")
	ok, err := CheckPAACookie(checkCtx2, token)
	if err != nil || !ok {
		t.Fatalf("reconnect shortly after a long stable session should succeed: ok=%v err=%v", ok, err)
	}
	if tun2.User.UserName() != "alice" {
		t.Fatalf("tunnel.User = %q, want %q", tun2.User.UserName(), "alice")
	}
}

// TestCheckPAACookieRejectsNeverUsedExpiredToken asserts that a stale
// token that was never successfully used before is rejected outright, even
// with a reconnect window configured. This is the security property that
// makes the reconnect window safe to enable: it only extends tokens that
// have already proven themselves against a real, observed tunnel, not any
// expired token that shows up.
func TestCheckPAACookieRejectsNeverUsedExpiredToken(t *testing.T) {
	clock := setupReconnectTest(t, 5*time.Minute, 30*time.Minute)

	issueCtx, _ := newCheckCtx("10.0.0.1")
	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	clock.Advance(6 * time.Minute) // let it expire without ever being used

	checkCtx, _ := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx, token); err == nil || ok {
		t.Fatalf("never-used expired token should be rejected: ok=%v err=%v", ok, err)
	}
}

// TestCheckPAACookieRejectsAfterReconnectWindowExceeded asserts that once
// ReconnectWindow has elapsed since the tunnel's last real activity, the
// token is rejected - the grace period does not extend a session forever,
// it just needs a reconnect attempt to actually arrive within the window
// of the last time the tunnel was genuinely alive.
func TestCheckPAACookieRejectsAfterReconnectWindowExceeded(t *testing.T) {
	clock := setupReconnectTest(t, 5*time.Minute, 30*time.Minute)

	issueCtx, _ := newCheckCtx("10.0.0.1")
	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	checkCtx, tun := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx, token); err != nil || !ok {
		t.Fatalf("first use should succeed: ok=%v err=%v", ok, err)
	}
	closeTunnel(tun, clock.now) // last activity is effectively "now"

	clock.Advance(45 * time.Minute) // past ReconnectWindow since that last activity

	checkCtx2, _ := newCheckCtx("10.0.0.1")
	if ok, err := CheckPAACookie(checkCtx2, token); err == nil || ok {
		t.Fatalf("token should be rejected once the reconnect window has elapsed since last activity: ok=%v err=%v", ok, err)
	}
}

// TestCheckPAACookieIsSelfContained asserts that validating a PAA cookie
// does not require a live IdP. Today CheckPAACookie calls
// OIDCProvider.UserInfo with the embedded access token to look up the
// subject; both the network roundtrip and the dependency on a still-live
// access token are unnecessary because the gateway already signed Subject
// itself at issue time.
func TestCheckPAACookieIsSelfContained(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	OIDCProvider = nil
	Oauth2Config = oauth2.Config{}
	VerifyClientIP = false

	issueId := identity.NewUser()
	issueId.SetUserName("alice")
	issueId.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	issueId.SetAttribute(identity.AttrAccessToken, "irrelevant")
	issueCtx := context.WithValue(context.Background(), identity.CTXKey, issueId)

	token, err := GeneratePAAToken(issueCtx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	checkId := identity.NewUser()
	checkId.SetUserName("alice")
	checkId.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	checkCtx := context.WithValue(context.Background(), identity.CTXKey, checkId)
	tun := &protocol.Tunnel{User: checkId}
	checkCtx = context.WithValue(checkCtx, protocol.CtxTunnel, tun)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckPAACookie panicked without a live IdP (expected: trust the signed Subject): %v", r)
		}
	}()

	ok, err := CheckPAACookie(checkCtx, token)
	if err != nil {
		t.Errorf("CheckPAACookie returned error: %v", err)
	}
	if !ok {
		t.Errorf("CheckPAACookie returned ok=false for a valid cookie")
	}
	if tun.User.UserName() != "alice" {
		t.Errorf("tunnel.User = %q, want %q", tun.User.UserName(), "alice")
	}
}
