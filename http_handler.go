package octohooks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"net/http"
)

// Handler implements http.Handler for handling incoming github webhooks
type Handler struct {
	Secret string
	Events chan Event
}

var _ http.Handler = &Handler{}

func NewHandler() *Handler {
	return &Handler{
		Events: make(chan Event, 5),
	}
}

// ServeHTTP implements http.Handler
// This is where we handle all incoming github webhooks and check signing
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	err = h.validSignature(body, r)
	if err != nil {
		switch err.(type) {
		case signatureInvalid:
			http.Error(w, err.Error(), http.StatusForbidden)
		default:
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	go func() {
		e := NewEventFromRequestAndBody(r, body)
		h.Events <- e
	}()
}

func (h *Handler) validSignature(body []byte, r *http.Request) error {
	if len(h.Secret) == 0 {
		return nil
	}

	signature := r.Header.Get("X-Hub-Signature")
	if len(signature) == 0 {
		return signatureInvalid("signature not found")
	}

	// This portion has been shamelessly stolen from
	// https://github.com/phayes/hookserve
	mac := hmac.New(sha1.New, []byte(h.Secret))
	_, err := mac.Write(body)
	if err != nil {
		return err
	}

	expectedMAC := mac.Sum(nil)
	expectedSig := "sha1=" + hex.EncodeToString(expectedMAC)
	if expectedSig != signature {
		return signatureInvalid("signature invalid")
	}

	return nil
}
