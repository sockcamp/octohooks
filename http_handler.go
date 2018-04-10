package octohooks

import (
	"io/ioutil"
	"net/http"
)

// Handler implements http.Handler for handling incoming github webhooks
type Handler struct {
	SecretResolver SecretResolver
	Events         chan Event
}

var _ http.Handler = &Handler{}

// NewHandler returns a http.Handler compliant struct that exposes a channel
// of events that you can create your own consumer against.
func NewHandler(resolver SecretResolver) *Handler {
	return &Handler{
		SecretResolver: resolver,
		Events:         make(chan Event),
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

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type not allowed", http.StatusUnsupportedMediaType)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	secret, err := h.SecretResolver.Resolve(r)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	err = secret.Validate(r.Header.Get("X-Hub-Signature"), body)
	if err != nil {
		switch err.(type) {
		case signatureInvalid:
			http.Error(w, err.Error(), http.StatusForbidden)
		default:
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	e := NewEventFromRequestAndBody(r, body)
	h.Events <- e

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("ok"))
}
