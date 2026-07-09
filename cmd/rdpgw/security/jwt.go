package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
)

const paaAudience = "rdpgw-paa"

var (
	SigningKey        []byte
	EncryptionKey     []byte
	UserSigningKey    []byte
	UserEncryptionKey []byte
	QuerySigningKey   []byte
	OIDCProvider      *oidc.Provider
	Oauth2Config      oauth2.Config
)

// ExpiryTime is how long the PAA token embedded in the .rdp file remains
// valid. The client resends this same token on every tunnel create,
// including reconnects after a brief network interruption, so it must be
// long enough to cover expected reconnect gaps. Configurable via
// security.paatokenlifetime (minutes). Defaults to 5 minutes.
var ExpiryTime time.Duration = 5 * time.Minute

// ReconnectWindow is a grace period, on top of ExpiryTime, during which a
// PAA token that has ALREADY been used to successfully open a tunnel at
// least once may be reused again even after its nominal expiry. This lets
// a client reconnect after a brief network interruption without needing a
// fresh .rdp file, while a token that is expired and was never used
// successfully (e.g. a stale, unused, or stolen .rdp file) is still
// rejected outright - it never entered the reconnect cache in the first
// place. Configurable via security.paareconnectwindow (minutes). Zero
// (the default) disables this and preserves the old strict-expiry
// behaviour.
var ReconnectWindow time.Duration = 0

// closedTunnelActivity tracks, per PAA-token hash, the last real activity
// (Tunnel.LastSeen) recorded when a tunnel authenticated by that token
// closed. It is populated by RecordTunnelClosed - wired to
// protocol.OnTunnelClosed in main.go - which fires at the moment a tunnel
// tears down, not on any timer. CheckPAACookie consults this (plus
// protocol.TunnelLastSeenByHash for the rarer still-open case) when a
// token is presented past its nominal expiry, so the reconnect grace
// window is anchored to how recently the session was genuinely alive,
// not to how recently a reconnect happened to occur. This matters: a
// session that ran healthily for an hour with zero reconnects should get
// the same grace on a blip as one that just reconnected a minute ago -
// anchoring to "last reconnect" instead would unfairly penalise the
// stable session. Only written/read when ReconnectWindow > 0. The go-cache
// TTL on each entry is set to ExpiryTime+ReconnectWindow at write time so
// stale entries are swept automatically.
var closedTunnelActivity = cache.New(5*time.Minute, 10*time.Minute)

var VerifyClientIP bool = true

// timeNow is the clock used for issuing and checking PAA token expiry.
// Tests replace it with a fake so expiry behaviour can be exercised with
// realistic minute-scale durations - JWT exp claims only have one-second
// resolution, so sub-second ExpiryTime values truncate to "already
// expired" - and without sleeping.
var timeNow = time.Now

// hashToken returns a hex-encoded SHA-256 hash of a PAA token. Tunnels
// remember which token authenticated them by this hash (Tunnel.PAATokenHash)
// rather than the raw token, so reconnect-window bookkeeping doesn't keep a
// second, longer-lived copy of bearer-token-equivalent material around.
func hashToken(tokenString string) string {
	sum := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(sum[:])
}

// RecordTunnelClosed is wired to protocol.OnTunnelClosed (see main.go). It
// fires exactly once, at the moment a tunnel tears down, and remembers
// that tunnel's last real activity against the PAA token that
// authenticated it - the signal CheckPAACookie later uses to judge whether
// a reconnect with the same, by-then-expired token is still within the
// reconnect grace window.
func RecordTunnelClosed(t *protocol.Tunnel) {
	if ReconnectWindow <= 0 || t == nil || t.PAATokenHash == "" {
		return
	}
	closedTunnelActivity.Set(t.PAATokenHash, t.LastSeen, ExpiryTime+ReconnectWindow)
}

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	ClientIP     string `json:"clientIp"`
}

func CheckSession(next protocol.CheckHostFunc) protocol.CheckHostFunc {
	return func(ctx context.Context, host string) (bool, error) {
		tunnel := getTunnel(ctx)
		if tunnel == nil {
			return false, errors.New("no valid session info found in context")
		}

		if tunnel.TargetServer != host {
			log.Printf("Client specified host %s does not match token host %s", host, tunnel.TargetServer)
			return false, nil
		}

		// use identity from context rather then set by tunnel
		id := identity.FromCtx(ctx)
		if VerifyClientIP && tunnel.RemoteAddr != id.GetAttribute(identity.AttrClientIp) {
			log.Printf("Current client ip address %s does not match token client ip %s",
				id.GetAttribute(identity.AttrClientIp), tunnel.RemoteAddr)
			return false, nil
		}
		return next(ctx, host)
	}
}

func CheckPAACookie(ctx context.Context, tokenString string) (bool, error) {
	if tokenString == "" {
		log.Printf("no token to parse")
		return false, errors.New("no token to parse")
	}

	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		log.Printf("cannot parse token due to: %t", err)
		return false, err
	}

	// check if the signing algo matches what we expect
	for _, header := range token.Headers {
		if header.Algorithm != string(jose.HS256) {
			return false, fmt.Errorf("unexpected signing method: %v", header.Algorithm)
		}
	}

	standard := jwt.Claims{}
	custom := customClaims{}

	// Claims automagically checks the signature...
	err = token.Claims(SigningKey, &standard, &custom)
	if err != nil {
		log.Printf("token signature validation failed due to %tunnel", err)
		return false, err
	}

	// Check issuer/audience ourselves rather than via standard.Validate, so
	// that a token past its nominal expiry can still be considered for the
	// reconnect grace window below instead of being hard-rejected here.
	// (go-jose's Validate always checks expiry against time.Now() unless
	// told otherwise - there is no zero-value way to ask it to skip that
	// check - so we don't use it for the time dimension at all.)
	if standard.Issuer != "rdpgw" {
		log.Printf("token validation failed: unexpected issuer %q", standard.Issuer)
		return false, errors.New("invalid issuer")
	}
	validAudience := false
	for _, aud := range standard.Audience {
		if aud == paaAudience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		log.Printf("token validation failed: unexpected audience %v", standard.Audience)
		return false, errors.New("invalid audience")
	}

	var hash string
	if ReconnectWindow > 0 {
		hash = hashToken(tokenString)
	}

	now := timeNow()
	if standard.Expiry != nil && now.After(standard.Expiry.Time()) {
		// Token is past its nominal expiry. Only acceptable if reconnects
		// are enabled AND we can find real evidence this token previously
		// authenticated an active tunnel, within the reconnect window of
		// that tunnel's last known activity. This means a stale/unused
		// .rdp file is rejected exactly as before - it can only get here
		// if it was already actively used.
		if ReconnectWindow <= 0 {
			log.Printf("PAA token for %s expired at %s and reconnects are disabled",
				standard.Subject, standard.Expiry.Time())
			return false, errors.New("token expired")
		}

		// Prefer a still-open tunnel's live LastSeen - covers the rare
		// case where a reconnect races an old tunnel that hasn't finished
		// tearing down yet. Otherwise fall back to what was recorded when
		// a matching tunnel last closed.
		lastActivity, found := protocol.TunnelLastSeenByHash(hash)
		if !found {
			if v, ok := closedTunnelActivity.Get(hash); ok {
				lastActivity, found = v.(time.Time), true
			}
		}

		if !found {
			log.Printf("PAA token for %s expired at %s and was never seen used before; rejecting",
				standard.Subject, standard.Expiry.Time())
			return false, errors.New("token expired")
		}
		if now.Sub(lastActivity) > ReconnectWindow {
			log.Printf("PAA token for %s expired at %s; last real activity was %s ago, past the %s reconnect window",
				standard.Subject, standard.Expiry.Time(), now.Sub(lastActivity), ReconnectWindow)
			closedTunnelActivity.Delete(hash)
			return false, errors.New("reconnect window exceeded")
		}
		log.Printf("PAA token for %s expired at %s but last real activity was only %s ago; allowing reconnect",
			standard.Subject, standard.Expiry.Time(), now.Sub(lastActivity))
	}

	tunnel := getTunnel(ctx)
	if tunnel == nil {
		return false, errors.New("no tunnel in context")
	}

	if ReconnectWindow > 0 {
		tunnel.PAATokenHash = hash
	}

	tunnel.TargetServer = custom.RemoteServer
	tunnel.RemoteAddr = custom.ClientIP
	tunnel.User.SetUserName(standard.Subject)

	return true, nil
}

func GeneratePAAToken(ctx context.Context, username string, server string) (string, error) {
	if len(SigningKey) < 32 {
		return "", errors.New("token signing key not long enough or not specified")
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: SigningKey}, nil)
	if err != nil {
		log.Printf("Cannot obtain signer %s", err)
		return "", err
	}

	standard := jwt.Claims{
		Issuer:   "rdpgw",
		Audience: jwt.Audience{paaAudience},
		Expiry:   jwt.NewNumericDate(timeNow().Add(ExpiryTime)),
		Subject:  username,
	}

	id := identity.FromCtx(ctx)
	private := customClaims{
		RemoteServer: server,
		ClientIP:     id.GetAttribute(identity.AttrClientIp).(string),
	}

	if token, err := jwt.Signed(sig).Claims(standard).Claims(private).Serialize(); err != nil {
		log.Printf("Cannot sign PAA token %s", err)
		return "", err
	} else {
		return token, nil
	}
}

func GenerateUserToken(ctx context.Context, userName string) (string, error) {
	if len(UserEncryptionKey) < 32 {
		return "", errors.New("user token encryption key not long enough or not specified")
	}

	claims := jwt.Claims{
		Subject: userName,
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Issuer:  "rdpgw",
	}

	enc, err := jose.NewEncrypter(
		jose.A128CBC_HS256,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       UserEncryptionKey,
		},
		(&jose.EncrypterOptions{Compression: jose.DEFLATE}).WithContentType("JWT"),
	)

	if err != nil {
		log.Printf("Cannot encrypt user token due to %s", err)
		return "", err
	}

	// this makes the token bigger and we deal with a limited space of 511 characters
	if len(UserSigningKey) > 0 {
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: UserSigningKey}, nil)
		token, err := jwt.SignedAndEncrypted(sig, enc).Claims(claims).Serialize()
		if len(token) > 511 {
			log.Printf("WARNING: token too long: len %d > 511", len(token))
		}
		return token, err
	}

	// no signature
	token, err := jwt.Encrypted(enc).Claims(claims).Serialize()
	return token, err
}

func UserInfo(ctx context.Context, token string) (jwt.Claims, error) {
	standard := jwt.Claims{}
	if len(UserEncryptionKey) > 0 && len(UserSigningKey) > 0 {
		enc, err := jwt.ParseSignedAndEncrypted(
			token,
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A128CBC_HS256},
			[]jose.SignatureAlgorithm{jose.HS256},
		)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		token, err := enc.Decrypt(UserEncryptionKey)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
		if err = token.Claims(UserSigningKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return standard, errors.New("cannot verify signature")
		}
	} else if len(UserSigningKey) == 0 {
		token, err := jwt.ParseEncrypted(token, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A128CBC_HS256})
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		err = token.Claims(UserEncryptionKey, &standard)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
	}

	// go-jose doesnt verify the expiry
	err := standard.Validate(jwt.Expected{
		Issuer: "rdpgw",
		Time:   time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return standard, fmt.Errorf("token validation failed due to %s", err)
	}

	return standard, nil
}

func QueryInfo(ctx context.Context, tokenString string, issuer string) (string, error) {
	standard := jwt.Claims{}
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		log.Printf("Cannot get token %s", err)
		return "", errors.New("cannot get token")
	}
	err = token.Claims(QuerySigningKey, &standard)
	if err = token.Claims(QuerySigningKey, &standard); err != nil {
		log.Printf("cannot verify signature %s", err)
		return "", errors.New("cannot verify signature")
	}

	// go-jose doesnt verify the expiry
	err = standard.Validate(jwt.Expected{
		Issuer: issuer,
		Time:   time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return "", fmt.Errorf("token validation failed due to %s", err)
	}

	return standard.Subject, nil
}

// GenerateQueryToken this is a helper function for testing
func GenerateQueryToken(ctx context.Context, query string, issuer string) (string, error) {
	if len(QuerySigningKey) < 32 {
		return "", errors.New("query token encryption key not long enough or not specified")
	}

	claims := jwt.Claims{
		Subject: query,
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Issuer:  issuer,
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: QuerySigningKey},
		(&jose.SignerOptions{}).WithBase64(true))

	if err != nil {
		log.Printf("Cannot encrypt user token due to %s", err)
		return "", err
	}

	token, err := jwt.Signed(sig).Claims(claims).Serialize()
	return token, err
}

func getTunnel(ctx context.Context) *protocol.Tunnel {
	s, ok := ctx.Value(protocol.CtxTunnel).(*protocol.Tunnel)
	if !ok {
		log.Printf("cannot get session info from context")
		return nil
	}
	return s
}
