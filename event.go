package octohooks

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/google/go-github/github"
)

// Event contains the basic information about an event that happened
type Event struct {
	// Name of the event (issue, pull request, commit, etc...)
	Name           string
	GithubUsername string
	EventDetail    interface{}
	Err            error
}

// NewEventFromRequestAndBody constructs an event from a github webhook request
func NewEventFromRequestAndBody(r *http.Request, body []byte) Event {
	e := Event{}
	e.Name = r.Header.Get("X-Github-Event")

	var eventDetail interface{}
	switch e.Name {
	case "pull_request":
		eventDetail = &github.PullRequestEvent{}
	case "push":
		eventDetail = &github.PushEvent{}
	}

	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(eventDetail); err != nil {
		e.Err = err
		return e
	}

	e.EventDetail = eventDetail

	return e
}
