package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/antonybholmes/go-web"
	"github.com/antonybholmes/go-web/auth/keystore"
	"github.com/gin-gonic/gin"
)

const (
	HeaderUserID    = "X-User-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderSignature = "X-Signature"

	MaxSkewDefault = 5 * time.Minute
)

// VerifyEd25519SignatureMiddleware verifies requests signed with Ed25519 signatures.
// It expects the following headers:
// - X-User-Id: the user ID whose public key will be used to verify the signature
// - X-Timestamp: the timestamp of the request in RFC3339Nano format
// - X-Signature: the base64-encoded Ed25519 signature of the request
//
// The signature is computed over a canonical message consisting of:
// METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + BODY
//
// The middleware checks that the timestamp is within maxSkew of the current time
// to prevent replay attacks. It then retrieves the user's public keys from the keystore
// and verifies the signature against each key. If verification succeeds, the request
// is allowed to proceed; otherwise, a 401 Unauthorized response is returned.
// MaxSkew allows for clock differences between client and server and should be set
// to a reasonable value (e.g., 5 minutes).
func VerifyEd25519SignatureMiddleware(maxSkew time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {

		userID := c.GetHeader(HeaderUserID)
		if userID == "" {
			web.UnauthorizedResp(c, "missing X-User-Id")
			return
		}

		sigB64 := c.GetHeader(HeaderSignature)
		if sigB64 == "" {
			web.UnauthorizedResp(c, "missing X-Signature")
			return
		}

		ts := c.GetHeader(HeaderTimestamp)
		if ts == "" {
			web.UnauthorizedResp(c, "missing X-Timestamp")
			return
		}

		// Parse timestamp with RFC3339Nano format for high precision
		timestamp, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			web.UnauthorizedResp(c, "invalid X-Timestamp")
			return
		}

		err = checkTimestamp(timestamp, maxSkew)

		if err != nil {
			web.UnauthorizedResp(c, err.Error())

			return
		}

		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			web.UnauthorizedResp(c, "invalid signature encoding")
			return
		}

		// Read body safely (re-buffer so next handler can still use it)
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			web.UnauthorizedResp(c, "cannot read body")
			return
		}

		// Re-wrap the bytes so other handlers can read it
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Message to verify:
		msg := buildSignedMessage(c.Request.Method, c.Request.URL.Path, ts, bodyBytes)

		// Get all valid keys for user
		keys, err := keystore.GetUserPublicKeysCached(userID)

		if err != nil {
			web.UnauthorizedResp(c, "user not found")
			return
		}

		verified := false
		for _, k := range keys {
			if ed25519.Verify(k, msg, sig) {
				verified = true
				break
			}
		}

		if !verified {
			web.UnauthorizedResp(c, "invalid signature")
			return
		}

		// Pass to next handler
		c.Next()
	}
}

func checkTimestamp(ts time.Time, maxSkew time.Duration) error {
	now := time.Now().UTC() // Explicitly use UTC for consistent comparison

	// If client timestamp is too far in the future:
	if ts.After(now.Add(maxSkew)) {
		return fmt.Errorf("timestamp too far in the future")
	}

	// If client timestamp is too old, we use Add(-maxSkew) to return a time rather than using Sub
	// which returns a Duration.
	if ts.Before(now.Add(-maxSkew)) {
		return fmt.Errorf("timestamp too far in the past")
	}

	return nil
}

func buildSignedMessage(method, path, timestamp string, body []byte) []byte {
	// Deterministic signing structure
	// You can customize this
	msg := method + "\n" + path + "\n" + timestamp + "\n"
	return append([]byte(msg), body...)
}

// Example of how to sign requests in Python using PyNaCl
// import nacl.signing
// import base64
// import requests
// from datetime import datetime, timezone

// # --------------------------
// # 1. Load or generate your Ed25519 key
// # --------------------------
// # Generate a new key (for testing)
// private_key = nacl.signing.SigningKey.generate()
// public_key = private_key.verify_key
// print("Public key (upload to server):", base64.b64encode(public_key.encode()).decode())

// # Or load an existing private key from base64
// # private_key = nacl.signing.SigningKey(base64.b64decode("<your private key>"))

// # --------------------------
// # 2. Prepare request
// # --------------------------
// url = "http://localhost:8080/api/secure"
// method = "POST"
// body = b'{"data":"hello world"}'  # JSON bytes

// # UTC timestamp in RFC3339Nano format
// timestamp = datetime.now(timezone.utc).isoformat(timespec='nanoseconds')

// # --------------------------
// # 3. Build the canonical message to sign
// # --------------------------
// # This must match buildSignedMessage in Go:
// # msg = method + "\n" + path + "\n" + timestamp + "\n" + body
// from urllib.parse import urlparse

// path = urlparse(url).path
// msg = method + "\n" + path + "\n" + timestamp + "\n"
// msg_bytes = msg.encode() + body

// # --------------------------
// # 4. Sign the message
// # --------------------------
// signature = private_key.sign(msg_bytes).signature
// sig_b64 = base64.b64encode(signature).decode()

// # --------------------------
// # 5. Send the request with headers
// # --------------------------
// headers = {
//     "X-User-Id": "user123",
//     "X-Timestamp": timestamp,
//     "X-Signature": sig_b64,
//     "Content-Type": "application/json",
// }

// response = requests.post(url, data=body, headers=headers)
// print(response.status_code, response.text)
