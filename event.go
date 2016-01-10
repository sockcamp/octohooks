package octohooks

import (
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

// NewEventFromRequest constructs an event from a github webhook request
func NewEventFromRequest(r *http.Request) Event {
	e := Event{}
	e.Name = r.Header.Get("X-Github-Event")

	var eventDetail interface{}
	switch e.Name {
	case "pull_request":
		eventDetail = &github.PullRequestEvent{}
	}

	if err := json.NewDecoder(r.Body).Decode(eventDetail); err != nil {
		e.Err = err
		return e
	}

	return e
}
