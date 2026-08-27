package palisadehttp_test

import (
	"log"
	"net/http"

	"github.com/palisade-bot-defense/palisade/pkg/palisadehttp"
)

func Example() {
	guard, err := palisadehttp.New(palisadehttp.Config{
		BaseURL:      "http://127.0.0.1:8080",
		APIKey:       "load-this-from-secret-management",
		FailureMode:  palisadehttp.FailClosed,
		FallbackPath: "/support/verification",
		Classifier: func(request *http.Request) (palisadehttp.Classification, error) {
			if request.Method == http.MethodGet {
				return palisadehttp.Classification{Action: "read", EndpointClass: "public_content"}, nil
			}
			return palisadehttp.Classification{Action: "other", EndpointClass: "other"}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	application := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	_ = guard.Handler(application)
}
