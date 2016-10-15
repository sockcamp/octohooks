package octohooks

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretValidation(t *testing.T) {
	secret := Secret("super-secret")

	t.Run("A valid signature returns no error", func(t *testing.T) {
		signature := "sha1=8942fc54602322464f81a966cbd09a17077d4702"
		body := []byte("hello-world")

		err := secret.Validate(signature, body)
		assert.Nil(t, err)
	})

	t.Run("An invalid signature returns an signatureInvalid error", func(t *testing.T) {
		signature := "sha1=bunk"
		body := []byte("hello-world")

		err := secret.Validate(signature, body)

		assert.IsType(t, signatureInvalid(""), err, "type matches signatureInvalid")
	})

	t.Run("An empty signature returns a signatureInvalid error", func(t *testing.T) {
		signature := ""
		body := []byte("hello-world")

		err := secret.Validate(signature, body)

		assert.IsType(t, signatureInvalid(""), err, "type matches signatureInvalid")
		assert.Equal(t, "signature not found", err.Error(), "error is descriptive")
	})

	t.Run("An empty secret returns a no error", func(t *testing.T) {
		secret = Secret("")
		signature := "bunk"
		body := []byte("hello-world")

		err := secret.Validate(signature, body)

		assert.Nil(t, err, "empty error")
	})
}

func TestStaticResolver(t *testing.T) {
	resolver := StaticResolver{Secret: "super-secret"}

	secret, err := resolver.Resolve(&http.Request{})
	assert.Nil(t, err)
	assert.Equal(t, Secret("super-secret"), secret, "secret matches static one provided")
}
