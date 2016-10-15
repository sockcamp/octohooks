package octohooks

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"github.com/pkg/errors"
)

// SecretResolver defines a simple interface for returning a Secret based
// on a request that has come in from Github
type SecretResolver interface {
	Resolve(req *http.Request) (Secret, error)
}

// StaticResolver implements SecretResolver but only validates all requests
// against a static secret you initialize it with
type StaticResolver struct {
	Secret string
}

// force a compilation error if static resolver doesnt implement the correct
// interface
var _ SecretResolver = &StaticResolver{}

// Resolve returns a Secret from the defined variable
func (sr *StaticResolver) Resolve(req *http.Request) (Secret, error) {
	return Secret(sr.Secret), nil
}

type signatureInvalid string

func (s signatureInvalid) Error() string {
	return string(s)
}

// Secret contains behavior for verifying github webhooks against the secret
type Secret string

// Validate validates a signature and body against the secret
func (s Secret) Validate(sig string, body []byte) error {
	if len(s) == 0 {
		return nil
	}

	if len(sig) == 0 {
		return signatureInvalid("signature not found")
	}

	mac := hmac.New(sha1.New, []byte(s))
	_, err := mac.Write(body)
	if err != nil {
		return errors.Wrap(err, "could not generate hmac signature")
	}

	expectedMAC := mac.Sum(nil)
	expectedSig := []byte("sha1=" + hex.EncodeToString(expectedMAC))
	if subtle.ConstantTimeCompare(expectedSig, []byte(sig)) != 1 {
		return signatureInvalid("signature invalid")
	}

	return nil
}
